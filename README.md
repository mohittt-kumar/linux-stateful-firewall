# Linux-Based Stateful Network Firewall with Web-Based Monitoring and Rule Management

[![Repository](https://img.shields.io/badge/GitHub-Repository-blue?logo=github)](https://github.com/mohittt-kumar/linux-stateful-firewall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-grade, educational Linux network security gateway built with **nftables**, **Python (Flask)**, **SQLite**, **vanilla JavaScript**, and a high-performance **C++ Traffic & Log Analyzer**.

Designed specifically for cybersecurity lab demonstrations, portfolio projects, and technical interview explanations.

---

## 1. System Architecture & Topology

```text
               INTERNET / HOST NETWORK (NAT)
                         |
                         | DHCP (e.g. 192.168.122.x or NAT)
                 +---------------+
                 |  Adapter 1    |
                 | (e.g. ens33)  |
                 +---------------+
                 |  FIREWALL VM  |
                 |  Ubuntu Linux |
                 |  nftables     |
                 |  Flask Web UI |
                 |  SQLite DB    |
                 +---------------+
                 |  Adapter 2    |
                 | (e.g. ens38)  |
                 | 192.168.50.1  |
                 +-------+-------+
                         |
      === ISOLATED VIRTUAL LAN SWITCH (192.168.50.0/24) ===
                         |
             +-----------+-----------+
             |                       |
     +-------+-------+       +-------+-------+
     |   CLIENT VM   |       |   SERVER VM   |
     | 192.168.50.10 |       | 192.168.50.20 |
     | Gateway:      |       | Gateway:      |
     | 192.168.50.1  |       | 192.168.50.1  |
     +---------------+       +---------------+
```

### Addressing Table

| Device | Interface | Subnet / Role | IP Address | Default Gateway |
| :--- | :--- | :--- | :--- | :--- |
| **Firewall VM** | `ens33` (WAN) | External / Internet | DHCP | Assigned by Hypervisor |
| **Firewall VM** | `ens38` (LAN) | Internal Gateway | `192.168.50.1/24` | *None* |
| **Client VM** | `ens33` (LAN) | Test Client Host | `192.168.50.10/24` | `192.168.50.1` |
| **Server VM** | `ens33` (LAN) | Target Services Host | `192.168.50.20/24` | `192.168.50.1` |

---

## 2. Project Directory Structure

```text
network-firewall/
│
├── app.py                  # Flask web application & REST API
├── database.py             # SQLite parameterized persistence layer
├── firewall.py             # nftables compiler, atomic ruleset applicator, and counter parser
├── monitoring.py           # Interface metrics, conntrack table parser, and kernel log telemetry
├── validators.py           # Strict input validation layer (command injection defense)
├── requirements.txt        # Minimal Python dependencies (Flask, Werkzeug)
├── setup_lab.sh            # Automated deployment script for Ubuntu Linux
│
├── database/
│   └── firewall.db         # SQLite database file (created on startup)
│
├── templates/
│   ├── base.html           # Dark cyber theme base template
│   ├── dashboard.html      # Overview telemetry, metric cards, and threat analyzer
│   ├── rules.html          # Rule management table, status toggles, and creation form
│   ├── connections.html    # Conntrack state table inspection
│   └── logs.html           # Firewall security events and drop audit trail
│
├── static/
│   ├── css/
│   │   └── style.css       # Clean responsive dark theme CSS
│   └── js/
│       └── dashboard.js    # Live polling, async rule CRUD, and analyzer integration
│
├── firewall/
│   └── nftables.conf       # Native exportable nftables configuration
│
├── analyzer/
│   ├── analyzer.cpp        # High-performance C++ traffic pattern and threat analyzer
│   └── Makefile            # C++ compiler build script
│
├── tests/
│   └── test_firewall.py    # Automated test suite (validators, DB, nftables generator, Flask)
│
└── README.md
```

---

## 3. Quick Start & Deployment

### Option A: Running on Ubuntu Linux Firewall VM (Recommended)

1. Clone or copy this directory to your Ubuntu Firewall VM:
   ```bash
   cd network-firewall
   ```
2. Run the automated installer:
   ```bash
   sudo bash setup_lab.sh
   ```
3. Open your browser and navigate to:
   ```text
   http://192.168.50.1:5000
   ```
   *(Or access from your host machine via the Firewall's WAN IP)*

### Option B: Running in Emulation / Development Mode (Any OS)

The firewall contains an **automatic simulation fallback engine**. If `nft` is not installed or the app is run without root privileges (such as on Windows or macOS for development):
```bash
python -m pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000` to preview and test the complete web UI, rule creation, database persistence, and analytics.

---

## 4. How the Firewall Works (Under the Hood)

### Communication Flow

```text
User creates rule via Web UI
            ↓
Browser sends JSON / Form Data
            ↓
validators.py (Verifies IP/CIDR, port range, whitelisted protocols, priority)
            ↓
database.py (Saves rule via parameterized SQL: INSERT INTO rules VALUES (?, ?, ...))
            ↓
firewall.py (Compiles ordered database rules into native nftables syntax)
            ↓
Atomic Application (Writes to temp file and runs: subprocess.run(['nft', '-f', temp_path]))
            ↓
Linux Kernel Netfilter filters packets in kernel-space with stateful connection tracking
```

### nftables Stateful Architecture

The firewall generates a baseline `table inet filter` with three primary chains:

1. **`input` chain**: Controls traffic destined for the Firewall VM itself.
   * Accepts loopback (`iif "lo" accept`).
   * Permits SSH (port 22) and Web UI (port 5000) for management.
   * Permits established/related traffic.
2. **`forward` chain**: Controls traffic routed between the WAN and LAN segments.
   * **Default Policy = DROP**: Packets are denied unless explicitly permitted.
   * **State Tracking (`ct state established,related accept`)**: Fast-paths return packets belonging to an active two-way connection.
   * **Invalid Dropping (`ct state invalid drop`)**: Silently discards malformed or out-of-sequence TCP packets.
   * **Dynamic Database Rules**: Inserted in strict priority order.
   * **Default Logging**: Packets hitting default drop are logged with prefix `[NFT_FORWARD_DEFAULT_DROP]`.
3. **`output` chain**: Permits traffic originated by the firewall itself (`policy accept`).

---

## 5. Security Engineering Decisions

| Risk / Threat | Defense Mechanism in This Project |
| :--- | :--- |
| **Command Injection** | Never use `shell=True` or `os.system()`. Subprocess calls use explicit argument lists (e.g. `['nft', '-f', path]`). All fields validated via `validators.py`. |
| **SQL Injection** | All database queries strictly use `?` parameter placeholders. Zero string concatenation in SQL. |
| **Stored Cross-Site Scripting (XSS)** | Flask/Jinja2 template auto-escaping enabled by default. User inputs are safely rendered as text. |
| **Subnet Mask Bypass** | Uses Python's standard `ipaddress.ip_network(strict=False)` to validate IPv4 addresses and CIDR notations. |
| **Unauthorized Remote Management** | Web management port (5000) and SSH (22) are strictly permitted only on the internal management interface in `input` chain. |

---

## 6. Controlled Testing Plan (5 Test Scenarios)

Perform these tests from the **Client VM (`192.168.50.10`)** targeting the **Server VM (`192.168.50.20`)**:

### Test 1: ICMP Ping
* **Action**: Create rule `Block Client Ping`: Source `192.168.50.10`, Destination `192.168.50.20`, Protocol `icmp`, Action `DROP`, Priority `15`.
* **Command on Client**: `ping -c 3 192.168.50.20`
* **Expected Result**: 100% packet loss (timeout).
* **Verify on Firewall**:
  ```bash
  sudo nft list ruleset | grep "Block Client Ping"
  sudo journalctl -k -e | grep "NFT_DROP"
  ```

### Test 2: HTTP Web Traffic (Port 80)
* **Setup**: Start a test web server on Server VM:
  ```bash
  python3 -m http.server 80
  ```
* **Command on Client**: `curl -I http://192.168.50.20`
* **Expected Result**: HTTP 200 OK (permitted by default baseline rule).
* **Block Test**: In Web UI, add rule `Block HTTP`: Protocol `tcp`, Dest Port `80`, Action `DROP`, Priority `10`.
* **Command on Client**: `curl --connect-timeout 3 http://192.168.50.20`
* **Expected Result**: Connection timed out.

### Test 3: HTTPS Traffic (Port 443)
* **Test**: Outbound HTTPS requests from Client to WAN/Internet.
* **Command on Client**: `curl -I https://www.google.com`
* **Expected Result**: Permitted via port 443 rule + NAT. Stateful rule accepts returning TLS handshake packets.

### Test 4: DNS Resolution (UDP Port 53)
* **Command on Client**: `dig @8.8.8.8 google.com +short`
* **Expected Result**: Returns IP address. In conntrack table (`/connections`), see UDP state transition `[UNREPLIED]` &rarr; `[ASSURED]`.

### Test 5: SSH Traffic (Port 22)
* **Action**: In Web UI, add rule `Block SSH`: Protocol `tcp`, Dest Port `22`, Action `DROP`, Priority `10`.
* **Command on Client**: `ssh -o ConnectTimeout=3 192.168.50.20`
* **Expected Result**: Connection timed out. Dropped packet counter increments in dashboard.

---

## 7. Troubleshooting Runbook

| Symptom | Diagnostic Command | Resolution |
| :--- | :--- | :--- |
| **Client cannot reach any IP** | `ip route show` on Client | Ensure default gateway is `192.168.50.1`. |
| **Firewall is not forwarding** | `cat /proc/sys/net/ipv4/ip_forward` | If `0`, run `sudo sysctl -w net.ipv4.ip_forward=1`. |
| **Rules not taking effect** | `sudo nft list ruleset` | Verify rule order. Remember: lower priority number executes first. |
| **Active connections not displaying** | `lsmod \| grep nf_conntrack` | Run `sudo modprobe nf_conntrack` to load the kernel module. |
| **Port 5000 already in use** | `sudo ss -tulpn \| grep :5000` | Terminate old Flask process: `sudo kill -9 <PID>`. |

---

## 8. 18 Cybersecurity Interview Questions & Direct Answers

#### 1. What is a firewall?
> A firewall is a network security device or software that inspects incoming and outgoing network traffic against a defined set of security rules to determine whether traffic should be allowed or blocked.

#### 2. What is a stateful firewall?
> A stateful firewall tracks the state of active network connections (such as the TCP three-way handshake or DNS request/response pairs). Instead of evaluating every packet in isolation, it remembers the conversation and automatically permits valid return traffic.

#### 3. What is nftables?
> `nftables` is the modern Linux kernel packet classification framework that replaced `iptables`, `ip6tables`, `arptables`, and `ebtables`. It provides higher packet throughput, a cleaner unified syntax, and native support for sets and dictionaries.

#### 4. Why did you use nftables instead of iptables?
> `nftables` is the current standard in Linux. It compiles rules into a compact virtual machine bytecode executed inside the kernel, avoiding the code duplication and atomic reload bottlenecks of `iptables`.

#### 5. Why did you use Python for the backend?
> Python provides clean standard libraries for networking, IP address parsing (`ipaddress`), regular expressions, and secure process management without unnecessary boilerplate.

#### 6. Why Flask?
> Flask is a lightweight microframework that introduces minimal overhead. It avoids complex microservice or ORM bloat, making the firewall logic easy to audit, secure, and explain.

#### 7. Why SQLite?
> SQLite is serverless, zero-configuration, and stores the database in a single local file. Because firewall rules and recent audit logs are managed locally on the gateway machine, an external database server like PostgreSQL or MySQL is unnecessary.

#### 8. What is conntrack?
> `conntrack` (connection tracking) is the Linux netfilter subsystem that monitors and stores the 5-tuple state of active Layer 4 sessions (`/proc/net/nf_conntrack`). It enables stateful decisions like `ct state established,related`.

#### 9. What happens when a packet enters the firewall?
> The packet hits the network interface, passes to the Linux networking stack, and enters the netfilter hooks. If the packet is destined for another host, it enters the `forward` chain. The kernel checks the conntrack table; if it is established/related return traffic, it is accepted immediately. If new, it is evaluated sequentially against forward rules by priority. If no rule matches, the default policy (DROP) is enforced.

#### 10. What happens when a packet matches a DROP rule?
> The kernel silently discards the packet. No ICMP unreachable notification is sent back to the sender, which prevents port scanners from quickly mapping active IP addresses.

#### 11. What is default deny?
> Default deny (zero-trust perimeter) is the security principle where all traffic is blocked by default unless explicitly permitted by an authorized rule.

#### 12. Why is rule order important?
> Firewall rules follow the first-match principle. If a broad "Allow Any" rule sits with higher priority above a specific "Block IP" rule, the allow rule will trigger first and the block rule will never be reached.

#### 13. How did you test the firewall?
> I used an isolated 3-VM architecture (Firewall, Client, Server). I generated real traffic (ICMP ping, HTTP, HTTPS, DNS, SSH) from the Client VM, applied filtering rules via the Web UI, and verified packet drops and state transitions using `tcpdump`, `nft list ruleset`, and journalctl.

#### 14. How did you prevent command injection?
> I avoided `shell=True` and `os.system()`. All external system calls pass explicit argument vectors to `subprocess.run()`. Every user input is strictly validated against IPv4/CIDR parsers, regexes, and whitelisted protocols before rule generation.

#### 15. How did you monitor traffic?
> Through three sources: parsing `/proc/net/dev` for interface packet counts, reading `/proc/net/nf_conntrack` for active sessions, and querying `nftables` packet counters.

#### 16. How did you troubleshoot blocked traffic?
> I ran `sudo tcpdump -i ens38 -nn` to verify packet arrival at the interface, inspected `sudo nft list ruleset` to check rule ordering and packet counters, and checked `journalctl -k` for `[NFT_DROP]` log messages.

#### 17. What limitations does your firewall have?
> It operates at Layers 3 and 4 (IP addresses, ports, protocols, and connection state). It does not perform Layer 7 Deep Packet Inspection (DPI), TLS decryption, or web application firewall (WAF) payload inspection.

#### 18. How would you improve it for production?
> In production, I would add:
> 1. Role-based authentication (RBAC) with MFA for the web console.
> 2. Suricata / Zeek integration for Intrusion Detection/Prevention (IDS/IPS).
> 3. High Availability (HA) clustering using VRRP / `keepalived` with `conntrackd` state synchronization.
> 4. Structured JSON log streaming to an enterprise SIEM (e.g. Wazuh or Splunk).

---

## 9. 60-Second Interview Elevator Pitch

> *"I designed and built a Linux-based stateful network firewall running in an isolated 3-VM routed gateway topology. I used nftables in the Linux kernel as the core filtering engine and engineered a lightweight Python Flask management layer with an SQLite database.*
>
> *The firewall enforces a strict default-deny policy, stateful connection tracking with conntrack, and granular Layer 3 and 4 rule priorities. To guarantee system security, I built a strict validation layer that prevents command injection by avoiding shell execution and sanitizing all IP/CIDR inputs.*
>
> *For telemetry, the system monitors interface throughput and live connection states, complemented by an optimized C++ module to analyze traffic patterns and detect port-scanning attempts. I thoroughly validated rule enforcement and state transitions across the lab using tcpdump and nftables packet counters."*
