"""
web_filter.py - Real-World Website & Domain Access Control Engine (Web Filter)
==============================================================================
Cybersecurity & Network Engineering Analysis:
---------------------------------------------
Why modern websites (Instagram, YouTube, Google) are difficult to block on Layer 3/4:
1. Massive Anycast CDNs: Instagram does not use a single IP; it uses hundreds of rotating
   IPs and subdomains (e.g., instagram.com, www.instagram.com, static.cdninstagram.com).
2. QUIC / HTTP/3 over UDP: Modern browsers (Chrome, Edge) use UDP port 443 (QUIC) instead
   of standard TCP port 443. A firewall must block BOTH TCP and UDP port 443.
3. Dual-Stack IPv6: If an IPv4 address is blocked, the browser immediately fails over to IPv6.
4. OS Elevation / UAC: On Windows, non-admin processes cannot modify the Windows Firewall.
"""

import os
import re
import socket
import subprocess
import shutil
import logging
from typing import List, Tuple, Dict, Any, Optional

logger = logging.getLogger("web_filter")

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,15}$"
)


def is_admin_elevated() -> bool:
    """Checks whether the current process has administrator or root privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def validate_domain(domain_str: str) -> Tuple[bool, str]:
    """
    Validates a domain name (e.g., 'example.com', 'instagram.com').
    Strips protocol prefixes (http://, https://) and paths automatically.
    """
    if not domain_str or not domain_str.strip():
        return False, "Domain cannot be empty."

    cleaned = domain_str.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/")[0].split(":")[0].strip()

    if not DOMAIN_REGEX.match(cleaned):
        return False, f"Invalid domain format: '{domain_str}'. Example: 'example.com' or 'instagram.com'"

    return True, cleaned


def resolve_domain_ips(domain: str) -> List[str]:
    """
    Queries DNS to resolve all active IPv4 addresses associated with the domain
    AND its www alias (e.g., both instagram.com and www.instagram.com).
    """
    ips = set()
    domains_to_check = [domain]
    if not domain.startswith("www."):
        domains_to_check.append(f"www.{domain}")
    else:
        domains_to_check.append(domain[4:])

    for d in domains_to_check:
        try:
            results = socket.getaddrinfo(d, None, socket.AF_INET)
            for r in results:
                ip = r[4][0]
                if ip and ip != "0.0.0.0":
                    ips.add(ip)
        except Exception as e:
            logger.debug(f"DNS lookup for {d}: {e}")

    return sorted(list(ips))


WINDOWS_HOSTS_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_MARKER = "# NETFW_FILTER"


def update_windows_hosts(domain: str, block: bool = True) -> bool:
    """
    Directly binds or unbinds the domain and its www alias to 127.0.0.1 in the
    Windows hosts file when elevated, ensuring instant browser connection refusal.
    """
    if os.name != "nt" or not is_admin_elevated():
        return False

    try:
        clean = domain.lower().strip()
        apex = clean[4:] if clean.startswith("www.") else clean
        domains = [apex, f"www.{apex}"]

        if not os.path.exists(WINDOWS_HOSTS_PATH):
            return False

        with open(WINDOWS_HOSTS_PATH, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Remove any previous entries for this domain
        filtered_lines = [l for l in lines if not (HOSTS_MARKER in l and apex in l)]

        if block:
            new_entry = f"127.0.0.1 {' '.join(domains)} {HOSTS_MARKER}\n"
            filtered_lines.append(new_entry)

        with open(WINDOWS_HOSTS_PATH, "w", encoding="utf-8") as f:
            f.writelines(filtered_lines)

        # Flush Windows DNS cache immediately
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, timeout=5)
        logger.info(f"Windows Hosts File: {'Blocked' if block else 'Unblocked'} {apex} and www.{apex}")
        return True
    except Exception as ex:
        logger.warning(f"Hosts file update error: {ex}")
        return False


def enforce_host_firewall_rule(domain: str, ip_list: List[str], block: bool = True) -> Tuple[bool, str]:
    """
    Enforces website blocking on the host operating system:
    - Blocks both TCP (HTTP/HTTPS) and UDP (QUIC / HTTP/3).
    - On Windows (Admin): Uses netsh advfirewall + hosts file DNS binding.
    - On Windows (Standard User): Handled via auto-configured Layer 7 Proxy.
    - On Linux: Managed via kernel nftables engine.
    """
    clean_name = re.sub(r"[^a-zA-Z0-9]", "_", domain)[:25]
    rule_tcp = f"NETFW_TCP_{clean_name}"
    rule_udp = f"NETFW_UDP_{clean_name}"

    if os.name == "nt":
        if is_admin_elevated():
            try:
                # 1. Update Windows Firewall rules
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_tcp}"], capture_output=True, text=True)
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_udp}"], capture_output=True, text=True)

                if block and ip_list:
                    remote_ips = ",".join(ip_list)
                    cmd_tcp = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_tcp}", "dir=out", "action=block", "enable=yes",
                        "protocol=TCP", "remoteport=80,443", f"remoteip={remote_ips}"
                    ]
                    cmd_udp = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_udp}", "dir=out", "action=block", "enable=yes",
                        "protocol=UDP", "remoteport=443", f"remoteip={remote_ips}"
                    ]
                    subprocess.run(cmd_tcp, capture_output=True, text=True, timeout=5)
                    subprocess.run(cmd_udp, capture_output=True, text=True, timeout=5)

                # 2. Update Windows hosts file and flush DNS
                update_windows_hosts(domain, block=block)

                action_verb = "Blocked" if block else "Unblocked"
                logger.info(f"Windows Kernel & DNS: {action_verb} {domain}")
                return True, f"Enforced on Windows Firewall (TCP/UDP 80/443) + Hosts DNS ({action_verb} {domain})."

            except Exception as ex:
                logger.warning(f"Windows host firewall enforcement error: {ex}")
                return False, str(ex)
        else:
            # Running as standard user - Layer 7 proxy handles it automatically
            return True, "Enforced via Layer 7 Web Filter Proxy Engine (Zero Admin Required)."

    return True, "Enforced via gateway ruleset."


def sync_all_web_filters():
    """
    Synchronizes all active web filters to the host OS, proxy, and nftables ruleset.
    """
    from database import get_web_filters, get_all_rules
    from firewall import apply_ruleset

    filters = get_web_filters()

    if os.name == "nt" and is_admin_elevated():
        for f in filters:
            domain = f["domain"]
            ips = [ip.strip() for ip in f["resolved_ips"].split(",") if ip.strip()]
            is_blocked = (f["enabled"] == 1 and f["action"] == "block")
            enforce_host_firewall_rule(domain, ips, block=is_blocked)

    # Re-apply nftables ruleset
    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

