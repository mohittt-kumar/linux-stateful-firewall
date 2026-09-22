"""
proxy.py - Real-Time Intercepting Web Filter Proxy Engine
=========================================================
Architectural & Security Role:
------------------------------
Real-world enterprise web filters (e.g. Zscaler, BlueCoat, FortiProxy, Squid)
operate at Layer 7 (Application Layer) as forward proxies. This allows them to:
1. Intercept HTTP and HTTPS (CONNECT tunnel) domain requests by hostname.
2. Defeat CDN Anycast IP hopping, IPv6 bypasses, and DNS caching.
3. Render authentic '403 Forbidden - Blocked by Security Policy' pages directly in the user's browser.
4. Integrate with the operating system without requiring kernel-level elevation.

This engine listens on 127.0.0.1:8080 and queries the SQLite database in real-time.
"""

import os
import re
import socket
import select
import threading
import logging
import time
from typing import Tuple, Optional

logger = logging.getLogger("web_proxy")
logging.basicConfig(level=logging.INFO)

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8080
_PROXY_SERVER_THREAD = None
_RUNNING = False


# High-contrast Cybersecurity Block Screen HTML
BLOCK_SCREEN_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden - Net-Firewall</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background-color: #0b0f19;
            color: #f9fafb;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 1.5rem;
        }
        .container {
            background-color: #111827;
            border: 1px solid #ef4444;
            border-radius: 12px;
            box-shadow: 0 10px 25px -5px rgba(239, 68, 68, 0.3);
            max-width: 540px;
            width: 100%;
            padding: 2.5rem 2rem;
            text-align: center;
        }
        .icon {
            font-size: 3.5rem;
            margin-bottom: 1rem;
            line-height: 1;
        }
        h1 {
            color: #ef4444;
            font-size: 1.6rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            letter-spacing: 0.05em;
        }
        p {
            color: #9ca3af;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 1.25rem;
        }
        code {
            font-family: 'JetBrains Mono', Consolas, monospace;
            color: #06b6d4;
            background-color: rgba(6, 182, 212, 0.1);
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 14px;
            font-weight: 600;
        }
        .details-box {
            background-color: rgba(0, 0, 0, 0.3);
            border: 1px solid #374151;
            border-radius: 8px;
            padding: 1rem;
            margin: 1.25rem 0;
            text-align: left;
            font-size: 12px;
            color: #d1d5db;
        }
        .details-box div { margin-bottom: 4px; }
        .details-box strong { color: #f9fafb; }
        .footer {
            font-size: 11px;
            color: #6b7280;
            font-family: Consolas, monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>ACCESS RESTRICTED</h1>
        <p>Access to <code>{domain}</code> has been blocked by your <strong>Linux Stateful Network Firewall Policy</strong>.</p>
        
        <div class="details-box">
            <div><strong>Blocked Domain:</strong> {domain}</div>
            <div><strong>Interception Engine:</strong> Net-Firewall Web Filter (Layer 7 SWG)</div>
            <div><strong>Verdict:</strong> 403 Forbidden (DROP Policy Enforced)</div>
            <div><strong>Timestamp:</strong> {timestamp}</div>
        </div>

        <p class="footer">To permit this connection, open the Firewall Console and disable the rule.</p>
    </div>
</body>
</html>
"""


def render_block_screen(domain: str, port: int = 80) -> bytes:
    """Renders the HTML 403 block screen with string replacement to avoid CSS brace formatting conflicts."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    html = (
        BLOCK_SCREEN_TEMPLATE
        .replace("{domain}", domain)
        .replace("{port}", str(port))
        .replace("{timestamp}", ts)
    )
    return html.encode("utf-8")


def is_domain_blocked(domain: str) -> bool:
    """
    Checks if a domain or its apex/parent domain is marked as blocked in SQLite.
    Example: 'www.instagram.com' matches 'instagram.com' or 'www.instagram.com'.
    """
    from database import get_web_filters
    clean_domain = domain.lower().strip().split(":")[0]

    filters = get_web_filters()
    for f in filters:
        if f.get("enabled") == 1 and f.get("action", "").lower() == "block":
            target = f.get("domain", "").lower().strip()
            # Direct match
            if clean_domain == target:
                return True
            # Subdomain match (e.g. www.instagram.com matching instagram.com)
            if clean_domain.endswith("." + target):
                return True
            # Apex match if target had www.
            if target.startswith("www.") and clean_domain == target[4:]:
                return True

    return False


def log_web_filter_drop(domain: str, port: int, client_ip: str):
    """Records the web filter drop event into the database logs and increments hit counter."""
    from database import add_log_entry, increment_web_filter_hit
    try:
        increment_web_filter_hit(domain)
    except Exception as ex:
        logger.debug(f"Hit count update error: {ex}")

    add_log_entry(
        source_ip=client_ip,
        destination_ip=domain,
        protocol="tcp",
        action="DROP",
        source_port=None,
        destination_port=str(port),
        reason=f"Web Filter: Blocked {domain}"
    )


def handle_client_connection(client_sock: socket.socket, client_addr: Tuple[str, int]):
    """Handles an incoming HTTP or HTTPS (CONNECT) proxy connection."""
    client_ip = client_addr[0]
    try:
        client_sock.settimeout(6.0)
        request_data = client_sock.recv(4096)
        if not request_data:
            client_sock.close()
            return

        header_line = request_data.decode("utf-8", errors="ignore").split("\r\n")[0]
        tokens = header_line.split()
        if len(tokens) < 2:
            client_sock.close()
            return

        method = tokens[0].upper()
        target = tokens[1]

        # Case 1: HTTPS CONNECT Tunnel (e.g., CONNECT instagram.com:443 HTTP/1.1)
        if method == "CONNECT":
            host_port = target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            if is_domain_blocked(host):
                logger.info(f"🚫 [BLOCKED HTTPS]: {host}:{port} for client {client_ip}")
                log_web_filter_drop(host, port, client_ip)

                # Return Cyber 403 Forbidden response with graceful shutdown to prevent direct fallback
                body = render_block_screen(host, port)
                resp = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Server: Net-Firewall-SWG\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Proxy-Connection: close\r\n"
                    b"Connection: close\r\n"
                    b"Alt-Svc: clear\r\n"
                    b"Content-Length: " + str(len(body)).encode("utf-8") + b"\r\n\r\n" + body
                )
                try:
                    client_sock.sendall(resp)
                    client_sock.shutdown(socket.SHUT_WR)
                    client_sock.settimeout(0.5)
                    try:
                        client_sock.recv(1024)
                    except Exception:
                        pass
                except Exception:
                    pass
                client_sock.close()
                return

            # Allowed: Connect to remote host and establish bidirectional tunnel
            try:
                remote_sock = socket.create_connection((host, port), timeout=6.0)
                client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                tunnel_bidirectional(client_sock, remote_sock)
            except Exception as ex:
                logger.debug(f"Tunnel connection failed for {host}:{port} - {ex}")
                try:
                    client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                except Exception:
                    pass
                client_sock.close()

        # Case 2: Standard HTTP Request (e.g., GET http://example.com/ HTTP/1.1)
        else:
            host = ""
            # Extract Host header
            for line in request_data.decode("utf-8", errors="ignore").split("\r\n"):
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            if not host and target.startswith("http://"):
                host = target[7:].split("/")[0]

            port = 80
            if ":" in host:
                parts = host.split(":", 1)
                host_clean = parts[0].strip()
                try:
                    port = int(parts[1].strip())
                except ValueError:
                    port = 80
            else:
                host_clean = host.strip() if host else "unknown"

            # Always allow loopback traffic (Firewall Management Console)
            if host_clean in ("127.0.0.1", "localhost", "0.0.0.0"):
                try:
                    remote_sock = socket.create_connection((host_clean, port), timeout=6.0)
                    remote_sock.sendall(request_data)
                    tunnel_bidirectional(client_sock, remote_sock)
                except Exception:
                    client_sock.close()
                return

            if is_domain_blocked(host_clean):
                logger.info(f"🚫 [BLOCKED HTTP]: {host_clean} for client {client_ip}")
                log_web_filter_drop(host_clean, port, client_ip)

                body = render_block_screen(host_clean, port)
                resp = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Connection: close\r\n"
                    b"Content-Length: " + str(len(body)).encode("utf-8") + b"\r\n\r\n" + body
                )
                try:
                    client_sock.sendall(resp)
                except Exception:
                    pass
                client_sock.close()
                return

            # Allowed: Forward HTTP request
            try:
                remote_sock = socket.create_connection((host_clean, port), timeout=6.0)
                remote_sock.sendall(request_data)
                tunnel_bidirectional(client_sock, remote_sock)
            except Exception as ex:
                client_sock.close()

    except Exception as ex:
        try:
            client_sock.close()
        except Exception:
            pass


def tunnel_bidirectional(sock1: socket.socket, sock2: socket.socket):
    """Streams data bi-directionally between the client socket and remote server socket."""
    sockets = [sock1, sock2]
    try:
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 30.0)
            if xlist or not rlist:
                break
            for s in rlist:
                other = sock2 if s is sock1 else sock1
                data = s.recv(8192)
                if not data:
                    return
                other.sendall(data)
    except Exception:
        pass
    finally:
        try:
            sock1.close()
        except Exception:
            pass
        try:
            sock2.close()
        except Exception:
            pass


def _proxy_server_worker():
    """Proxy server listen loop."""
    global _RUNNING
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server_sock.bind((PROXY_HOST, PROXY_PORT))
        server_sock.listen(100)
        logger.info(f"🛡️ Web Filter Proxy Engine active on {PROXY_HOST}:{PROXY_PORT}")
        _RUNNING = True

        while _RUNNING:
            try:
                server_sock.settimeout(1.0)
                client_sock, client_addr = server_sock.accept()
                t = threading.Thread(target=handle_client_connection, args=(client_sock, client_addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception as ex:
                if _RUNNING:
                    logger.debug(f"Proxy accept exception: {ex}")
    except Exception as ex:
        logger.error(f"Failed to bind proxy on port {PROXY_PORT}: {ex}")
    finally:
        try:
            server_sock.close()
        except Exception:
            pass


def start_proxy_daemon():
    """Starts the Web Filter proxy daemon thread if not already running."""
    global _PROXY_SERVER_THREAD, _RUNNING
    if _PROXY_SERVER_THREAD is None or not _PROXY_SERVER_THREAD.is_alive():
        _RUNNING = True
        _PROXY_SERVER_THREAD = threading.Thread(target=_proxy_server_worker, daemon=True, name="WebFilterProxy")
        _PROXY_SERVER_THREAD.start()


# ---------------------------------------------------------------------------
# Windows System-Wide Browser Proxy Auto-Configuration (Zero Admin Needed)
# ---------------------------------------------------------------------------

def set_windows_browser_proxy(enable: bool = True) -> bool:
    """
    Enables or disables the proxy in Windows user registry (HKCU).
    Requires ZERO administrator privileges and applies instantly to Chrome, Edge, and IE!
    """
    if os.name != "nt":
        return False

    try:
        import winreg
        import ctypes

        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE)

        if enable:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{PROXY_HOST}:{PROXY_PORT}")
            # Bypass local addresses and Flask management console (port 5000)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<-loopback>;<local>;127.0.0.1;127.0.0.1:*;localhost;localhost:*")
            logger.info("Windows Browser Proxy: ENABLED (127.0.0.1:8080)")
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            logger.info("Windows Browser Proxy: DISABLED")

        winreg.CloseKey(key)

        # Toggle QUIC (HTTP/3 UDP) prevention policy in HKCU for Chrome and Edge
        for pol_sub in [r"Software\Policies\Google\Chrome", r"Software\Policies\Microsoft\Edge"]:
            try:
                pol_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, pol_sub)
                if enable:
                    winreg.SetValueEx(pol_key, "QuicAllowed", 0, winreg.REG_DWORD, 0)
                else:
                    winreg.SetValueEx(pol_key, "QuicAllowed", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(pol_key)
            except Exception as pe:
                logger.debug(f"QUIC policy toggle for {pol_sub}: {pe}")

        # Notify Windows Internet subsystem to refresh proxy settings immediately
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # INTERNET_OPTION_REFRESH
        return True

    except Exception as ex:
        logger.error(f"Error updating Windows proxy registry: {ex}")
        return False


def get_windows_browser_proxy_status() -> bool:
    """Checks whether the Windows browser proxy is currently enabled."""
    if os.name != "nt":
        return False
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_READ)
        val, _ = winreg.QueryValueEx(key, "ProxyEnable")
        winreg.CloseKey(key)
        return val == 1
    except Exception:
        return False
