"""
validators.py - Strict Input Validation Layer for Firewall Management
======================================================================
Security Rationale:
-------------------
Firewall rules are compiled directly into kernel packet-filtering instructions (nftables).
Treating user input as untrusted and strictly validating every field prevents:
1. Command injection (shell metacharacters: ;, |, &, `, $, etc.)
2. Buffer overflows or syntax errors in nftables syntax
3. Invalid CIDR / subnet masks leading to unintended security bypasses
4. Denial-of-Service via invalid rule definitions
"""

import ipaddress
import re
from typing import Tuple, Dict, Any, Optional

ALLOWED_PROTOCOLS = {"tcp", "udp", "icmp", "all"}
ALLOWED_ACTIONS = {"accept", "drop", "reject"}
MIN_PORT = 1
MAX_PORT = 65535
MIN_PRIORITY = 1
MAX_PRIORITY = 9999


def validate_ip_or_cidr(value: Optional[str]) -> Tuple[bool, str]:
    """
    Validates whether a string is a valid IPv4 address, CIDR block, or 'any'.
    
    Examples of valid input:
      - 'any'
      - '192.168.50.10'
      - '192.168.50.0/24'
      
    Returns:
      (True, normalized_value) or (False, error_message)
    """
    if not value or value.strip().lower() in ("any", "*", "0.0.0.0/0", ""):
        return True, "any"

    cleaned = value.strip()

    # Reject dangerous shell or separator characters explicitly
    if any(ch in cleaned for ch in [";", "&", "|", "`", "$", "\n", "\r", " "]):
        return False, "IP/CIDR contains invalid characters or shell metacharacters."

    try:
        # strict=False allows host bits to be set in network definitions (e.g. 192.168.1.10/24)
        net = ipaddress.ip_network(cleaned, strict=False)
        if net.version != 4:
            return False, "Only IPv4 addresses are currently supported."
        return True, str(net)
    except ValueError:
        return False, f"Invalid IPv4 address or CIDR notation: '{cleaned}'"


def validate_port(value: Optional[str]) -> Tuple[bool, str]:
    """
    Validates port numbers: can be 'any', a single integer (1-65535),
    or a port range like '8000-8080'.
    
    Returns:
      (True, normalized_value) or (False, error_message)
    """
    if not value or str(value).strip().lower() in ("any", "*", "", "all", "0"):
        return True, "any"

    cleaned = str(value).strip()

    # Reject dangerous characters
    if not re.match(r"^[0-9\-]+$", cleaned):
        return False, "Port must contain only digits and optional hyphen for ranges (e.g., 80 or 8000-8080)."

    # Port Range check: e.g. 8000-8080
    if "-" in cleaned:
        parts = cleaned.split("-")
        if len(parts) != 2:
            return False, "Invalid port range format. Expected format: 'start-end' (e.g. 8000-8080)."
        try:
            start_p, end_p = int(parts[0]), int(parts[1])
            if not (MIN_PORT <= start_p <= MAX_PORT and MIN_PORT <= end_p <= MAX_PORT):
                return False, f"Port numbers in range must be between {MIN_PORT} and {MAX_PORT}."
            if start_p >= end_p:
                return False, f"Start port ({start_p}) must be strictly less than end port ({end_p})."
            return True, f"{start_p}-{end_p}"
        except ValueError:
            return False, "Invalid port integers in range."

    # Single Port check
    try:
        p = int(cleaned)
        if not (MIN_PORT <= p <= MAX_PORT):
            return False, f"Port must be between {MIN_PORT} and {MAX_PORT}."
        return True, str(p)
    except ValueError:
        return False, f"Invalid port number: '{cleaned}'"


def validate_protocol(value: Optional[str]) -> Tuple[bool, str]:
    """
    Validates packet protocol: strictly limited to tcp, udp, icmp, or all.
    """
    if not value or str(value).strip().lower() in ("all", "any", "*", ""):
        return True, "all"

    cleaned = str(value).strip().lower()
    if cleaned not in ALLOWED_PROTOCOLS:
        return False, f"Unsupported protocol '{cleaned}'. Allowed: {', '.join(sorted(ALLOWED_PROTOCOLS))}"
    return True, cleaned


def validate_action(value: Optional[str]) -> Tuple[bool, str]:
    """
    Validates firewall verdict action: accept, drop, or reject.
    """
    if not value:
        return False, "Action is required."

    cleaned = str(value).strip().lower()
    if cleaned not in ALLOWED_ACTIONS:
        return False, f"Invalid action '{cleaned}'. Allowed: {', '.join(sorted(ALLOWED_ACTIONS))}"
    return True, cleaned


def validate_priority(value: Any) -> Tuple[bool, int]:
    """
    Validates rule evaluation priority (1 to 9999).
    Lower numbers indicate higher evaluation precedence.
    """
    try:
        p = int(value)
        if not (MIN_PRIORITY <= p <= MAX_PRIORITY):
            return False, f"Priority must be an integer between {MIN_PRIORITY} and {MAX_PRIORITY}."
        return True, p
    except (ValueError, TypeError):
        return False, "Priority must be a valid integer."


def validate_rule_name(value: Optional[str]) -> Tuple[bool, str]:
    """
    Validates human-readable rule label. Must be alphanumeric with spaces, dashes, or underscores.
    Length between 1 and 64 characters.
    """
    if not value or not str(value).strip():
        return False, "Rule name cannot be empty."

    cleaned = str(value).strip()
    if len(cleaned) > 64:
        return False, "Rule name cannot exceed 64 characters."

    if not re.match(r"^[A-Za-z0-9_\-\. ]+$", cleaned):
        return False, "Rule name can only contain letters, numbers, spaces, underscores, dots, and hyphens."

    return True, cleaned


def validate_firewall_rule_payload(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """
    Validates a complete rule creation or update dictionary.
    
    Returns:
      (True, sanitized_dict) if valid.
      (False, {"error": "detailed message"}) if invalid.
    """
    # 1. Name
    ok, name_val = validate_rule_name(payload.get("name"))
    if not ok:
        return False, {"error": name_val}

    # 2. Source IP/CIDR
    ok, src_val = validate_ip_or_cidr(payload.get("source"))
    if not ok:
        return False, {"error": f"Source IP error: {src_val}"}

    # 3. Destination IP/CIDR
    ok, dst_val = validate_ip_or_cidr(payload.get("destination"))
    if not ok:
        return False, {"error": f"Destination IP error: {dst_val}"}

    # 4. Protocol
    ok, proto_val = validate_protocol(payload.get("protocol"))
    if not ok:
        return False, {"error": f"Protocol error: {proto_val}"}

    # 5. Source Port
    ok, sport_val = validate_port(payload.get("source_port"))
    if not ok:
        return False, {"error": f"Source Port error: {sport_val}"}

    # 6. Destination Port
    ok, dport_val = validate_port(payload.get("destination_port"))
    if not ok:
        return False, {"error": f"Destination Port error: {dport_val}"}

    # Port protocol compatibility check: ICMP does not have Layer 4 TCP/UDP ports
    if proto_val == "icmp" and (sport_val != "any" or dport_val != "any"):
        return False, {"error": "ICMP protocol cannot be paired with TCP/UDP port restrictions."}

    # 7. Action
    ok, action_val = validate_action(payload.get("action"))
    if not ok:
        return False, {"error": f"Action error: {action_val}"}

    # 8. Priority
    ok, prio_val = validate_priority(payload.get("priority", 100))
    if not ok:
        return False, {"error": f"Priority error: {prio_val}"}

    # 9. Enabled flag
    enabled_raw = payload.get("enabled", 1)
    if isinstance(enabled_raw, str):
        enabled_val = 1 if enabled_raw.lower() in ("1", "true", "yes", "on") else 0
    else:
        enabled_val = 1 if bool(enabled_raw) else 0

    sanitized = {
        "name": name_val,
        "source": src_val,
        "destination": dst_val,
        "protocol": proto_val,
        "source_port": sport_val,
        "destination_port": dport_val,
        "action": action_val,
        "priority": prio_val,
        "enabled": enabled_val,
    }

    return True, sanitized
