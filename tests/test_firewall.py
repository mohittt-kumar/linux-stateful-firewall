"""
tests/test_firewall.py - Automated Security, Validation, and Unit Test Suite
============================================================================
Tests:
1. Input validation & Command Injection defense
2. SQLite Database CRUD operations & parameterized safety
3. nftables syntax generation (default drop, stateful inspection)
4. Flask REST API endpoints and error handling
"""

import os
import sys
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from validators import (
    validate_ip_or_cidr, validate_port, validate_protocol,
    validate_action, validate_priority, validate_firewall_rule_payload
)
from database import (
    init_db, get_all_rules, add_rule, update_rule,
    toggle_rule, delete_rule, add_log_entry, get_logs
)
from firewall import generate_nftables_ruleset, build_nft_rule_statement
from app import app


class TestInputValidation(unittest.TestCase):
    """Verifies that malicious or malformed inputs are strictly rejected."""

    def test_valid_ips_and_cidrs(self):
        valid_inputs = ["any", "192.168.50.10", "10.0.0.0/8", "172.16.1.0/24", "0.0.0.0/0"]
        for val in valid_inputs:
            ok, res = validate_ip_or_cidr(val)
            self.assertTrue(ok, f"Expected '{val}' to be valid.")

    def test_command_injection_in_ip(self):
        malicious = [
            "192.168.1.1; rm -rf /",
            "10.0.0.1 && touch /tmp/hacked",
            "`whoami`",
            "192.168.1.1 | nc 10.0.0.1 4444",
            "$(cat /etc/passwd)",
            "192.168.1.1\nreboot"
        ]
        for val in malicious:
            ok, res = validate_ip_or_cidr(val)
            self.assertFalse(ok, f"Malicious input '{val}' must be rejected!")

    def test_port_validation(self):
        # Valid
        self.assertTrue(validate_port("any")[0])
        self.assertTrue(validate_port("80")[0])
        self.assertTrue(validate_port("443")[0])
        self.assertTrue(validate_port("8000-8080")[0])

        # Invalid
        self.assertFalse(validate_port("70000")[0])  # Out of range (>65535)
        self.assertFalse(validate_port("-5")[0])
        self.assertFalse(validate_port("80; reboot")[0])  # Shell injection attempt
        self.assertFalse(validate_port("8080-8000")[0])  # Start >= End

    def test_protocol_validation(self):
        self.assertTrue(validate_protocol("tcp")[0])
        self.assertTrue(validate_protocol("udp")[0])
        self.assertTrue(validate_protocol("icmp")[0])
        self.assertTrue(validate_protocol("all")[0])
        self.assertFalse(validate_protocol("bogus_protocol")[0])

    def test_payload_validation(self):
        valid_payload = {
            "name": "Block Malicious Host",
            "source": "192.168.50.99",
            "destination": "any",
            "protocol": "tcp",
            "source_port": "any",
            "destination_port": "22",
            "action": "drop",
            "priority": 50,
            "enabled": 1
        }
        ok, res = validate_firewall_rule_payload(valid_payload)
        self.assertTrue(ok)
        self.assertEqual(res["name"], "Block Malicious Host")


class TestDatabaseCRUD(unittest.TestCase):
    """Tests SQLite persistence layer."""

    def setUp(self):
        init_db()

    def test_rule_lifecycle(self):
        # 1. Add
        rule_data = {
            "name": "Test Web Drop",
            "source": "192.168.50.15",
            "destination": "192.168.50.20",
            "protocol": "tcp",
            "source_port": "any",
            "destination_port": "8080",
            "action": "drop",
            "priority": 90,
            "enabled": 1
        }
        rule_id = add_rule(rule_data)
        self.assertIsInstance(rule_id, int)

        # 2. Query
        rules = get_all_rules()
        found = any(r["id"] == rule_id for r in rules)
        self.assertTrue(found)

        # 3. Toggle
        new_status = toggle_rule(rule_id)
        self.assertEqual(new_status, 0)
        new_status = toggle_rule(rule_id)
        self.assertEqual(new_status, 1)

        # 4. Delete
        deleted = delete_rule(rule_id)
        self.assertTrue(deleted)


class TestNftablesGenerator(unittest.TestCase):
    """Verifies that generated nftables rules match stateful firewall syntax."""

    def test_nftables_syntax(self):
        rules = [
            {
                "id": 1,
                "name": "Block SSH",
                "source": "192.168.50.10",
                "destination": "192.168.50.20",
                "protocol": "tcp",
                "source_port": "any",
                "destination_port": "22",
                "action": "drop",
                "priority": 10,
                "enabled": 1
            }
        ]
        conf = generate_nftables_ruleset(rules, wan_iface="ens33")
        self.assertIn("flush ruleset", conf)
        self.assertIn("type filter hook forward priority 0; policy drop;", conf)
        self.assertIn("ct state established,related", conf)
        self.assertIn("ip saddr 192.168.50.10", conf)
        self.assertIn("tcp dport 22", conf)
        self.assertIn("drop", conf)
        # Real-World NAT Masquerade test
        self.assertIn("table ip nat", conf)
        self.assertIn('oifname "ens33" masquerade', conf)

    def test_clear_logs_stays_empty(self):
        """Verifies that clearing logs keeps the table empty and never resurrects sample logs."""
        from database import clear_logs, get_logs
        from monitoring import poll_kernel_firewall_logs

        clear_logs()
        poll_kernel_firewall_logs()
        logs = get_logs()
        self.assertEqual(len(logs), 0, "Logs must remain 0 after clear_logs!")


class TestWebFilter(unittest.TestCase):
    """Tests Website & Domain Filtering features."""

    def test_domain_validation(self):
        from web_filter import validate_domain
        ok, d = validate_domain("example.com")
        self.assertTrue(ok)
        self.assertEqual(d, "example.com")

        ok, d = validate_domain("https://sub.domain.org/path?q=1")
        self.assertTrue(ok)
        self.assertEqual(d, "sub.domain.org")

        ok, d = validate_domain("not_a_domain")
        self.assertFalse(ok)

    def test_web_filter_db_crud(self):
        from database import add_web_filter, get_web_filters, toggle_web_filter, delete_web_filter

        fid = add_web_filter("test-blocked-site.com", "93.184.216.34", action="block")
        self.assertIsInstance(fid, int)

        filters = get_web_filters()
        self.assertTrue(any(f["domain"] == "test-blocked-site.com" for f in filters))

        status = toggle_web_filter(fid)
        self.assertEqual(status, 0)

        deleted = delete_web_filter(fid)
        self.assertIsNotNone(deleted)


class TestFlaskEndpoints(unittest.TestCase):
    """Tests web UI and REST API routes."""

    def setUp(self):
        self.client = app.test_client()

    def test_pages_render(self):
        for route in ["/dashboard", "/rules", "/webfilter", "/connections", "/logs"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed to render.")

    def test_api_stats(self):
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("allowed_packets", data)
        self.assertIn("blocked_packets", data)
        self.assertIn("interfaces", data)

    def test_api_export_nftables(self):
        res = self.client.get("/api/firewall/export")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"table inet filter", res.data)


if __name__ == "__main__":
    unittest.main()
