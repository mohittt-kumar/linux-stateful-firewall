#!/usr/bin/env bash
# ==============================================================================
# setup_lab.sh - Automated Deployment Script for Firewall VM (Ubuntu Linux)
# ==============================================================================

set -e

echo "============================================================"
echo " Setting up Linux-Based Stateful Network Firewall Lab"
echo "============================================================"

# 1. Ensure Running as Root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run this script with sudo: sudo bash setup_lab.sh"
    exit 1
fi

# 2. Install Required System Packages
echo "[*] Installing required networking and development packages..."
apt-get update -y
apt-get install -y \
    nftables \
    conntrack \
    tcpdump \
    iproute2 \
    procps \
    g++ \
    make \
    python3 \
    python3-pip \
    python3-venv \
    curl

# 3. Enable Linux IPv4 Forwarding
echo "[*] Enabling IPv4 packet forwarding in the Linux kernel..."
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -p

# 4. Enable and Start nftables system service
echo "[*] Enabling nftables service..."
systemctl enable nftables
systemctl start nftables

# 5. Set up Python Virtual Environment & Install Dependencies
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "[*] Configuring Python virtual environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

# 6. Compile C++ Traffic Analyzer
echo "[*] Compiling C++ Traffic Analyzer..."
if [ -d "analyzer" ]; then
    cd analyzer
    make clean || true
    make
    cd ..
    echo "[+] C++ Analyzer binary compiled successfully."
fi

# 7. Apply Initial Baseline nftables Configuration
echo "[*] Applying baseline nftables ruleset..."
nft -f firewall/nftables.conf
echo "[+] Baseline nftables rules loaded into kernel."

# 8. Create systemd service for the Firewall Web Management App
echo "[*] Creating systemd service (net-firewall.service)..."
cat <<EOF > /etc/systemd/system/net-firewall.service
[Unit]
Description=Linux Stateful Network Firewall Web Console
After=network.target nftables.service

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/venv/bin/python3 $SCRIPT_DIR/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable net-firewall.service
systemctl restart net-firewall.service

echo "============================================================"
echo " Setup Completed Successfully!"
echo " Web Dashboard: http://192.168.50.1:5000 (or http://<firewall-ip>:5000)"
echo " Service Status: sudo systemctl status net-firewall"
echo " Live Logs:      sudo journalctl -u net-firewall -f"
echo "============================================================"
