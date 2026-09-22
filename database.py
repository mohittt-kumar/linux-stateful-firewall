"""
database.py - SQLite Database Management Layer for Network Firewall
===================================================================
Security & Architectural Principles:
------------------------------------
1. Parameterized Queries: Every query utilizes '?' placeholders to eliminate SQL Injection.
2. ACID Compliance: State transitions and rule modifications are committed atomically.
3. Separation of Concerns: Handles pure persistence; packet filter syntax is decoupled.
4. Auto-Seeding: Seeds safe baseline gateway rules upon initial initialization.
"""

import os
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database")
DB_PATH = os.path.join(DB_DIR, "firewall.db")


def get_db_connection() -> sqlite3.Connection:
    """Returns an SQLite connection with dictionary row access enabled."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes tables and seeds default baseline rules if database is empty."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Table 1: Firewall Rules
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        destination TEXT NOT NULL,
        protocol TEXT NOT NULL,
        source_port TEXT NOT NULL DEFAULT 'any',
        destination_port TEXT NOT NULL DEFAULT 'any',
        action TEXT NOT NULL,
        priority INTEGER NOT NULL DEFAULT 100,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table 2: Firewall Security Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        source_port TEXT,
        destination_port TEXT,
        protocol TEXT NOT NULL,
        action TEXT NOT NULL,
        reason TEXT,
        rule_id INTEGER,
        FOREIGN KEY (rule_id) REFERENCES rules(id) ON DELETE SET NULL
    );
    """)

    # Table 3: Stateful Connection Tracking Cache
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT NOT NULL,
        destination_ip TEXT NOT NULL,
        source_port TEXT,
        destination_port TEXT,
        protocol TEXT NOT NULL,
        state TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Table 4: System Settings & Metadata
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)

    # Table 5: Website & Domain Filters (Web Access Control)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS web_filters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT NOT NULL UNIQUE,
        resolved_ips TEXT NOT NULL,
        action TEXT NOT NULL DEFAULT 'block',
        enabled INTEGER NOT NULL DEFAULT 1,
        hit_count INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    conn.commit()

    # Check if baseline rules should be seeded
    cursor.execute("SELECT COUNT(*) AS cnt FROM rules;")
    count = cursor.fetchone()["cnt"]
    if count == 0:
        seed_baseline_rules(cursor)
        conn.commit()

    # Check if sample demonstration logs should be seeded (only once ever)
    cursor.execute("SELECT value FROM system_settings WHERE key = 'initial_logs_seeded';")
    logs_seeded = cursor.fetchone()
    if not logs_seeded:
        seed_initial_demo_logs(cursor)
        cursor.execute("INSERT INTO system_settings (key, value) VALUES ('initial_logs_seeded', '1');")
        conn.commit()

    conn.close()


def seed_initial_demo_logs(cursor: sqlite3.Cursor):
    """Inserts initial demonstration security events only on first database creation."""
    events = [
        ("192.168.1.105", "93.184.216.34", "tcp", "DROP", "51291", "443", "Blocked by Web Filter: example.com"),
        ("192.168.1.105", "8.8.8.8", "udp", "ACCEPT", "53102", "53", "Allowed DNS lookup"),
        ("192.168.1.105", "142.250.190.46", "tcp", "ACCEPT", "50192", "443", "Allowed HTTPS web traffic"),
        ("10.0.0.99", "192.168.1.1", "tcp", "DROP", "39012", "23", "Blocked Telnet (insecure protocol)"),
    ]
    for src, dst, proto, action, sport, dport, reason in events:
        cursor.execute("""
            INSERT INTO logs (source_ip, destination_ip, protocol, action, source_port, destination_port, reason)
            VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (src, dst, proto, action, sport, dport, reason))


def seed_baseline_rules(cursor: sqlite3.Cursor):
    """
    Seeds universal gateway rules (matching any source IP to any destination IP):
    - Allow DNS (port 53)
    - Allow Web browsing (HTTP/HTTPS)
    - Allow Ping (ICMP)
    - Allow Management SSH (port 22)
    """
    baseline = [
        ("Allow Management SSH", "any", "any", "tcp", "any", "22", "accept", 10, 1),
        ("Allow Management Web UI", "any", "any", "tcp", "any", "5000", "accept", 20, 1),
        ("Allow Universal DNS", "any", "any", "udp", "any", "53", "accept", 30, 1),
        ("Allow Universal HTTP Web", "any", "any", "tcp", "any", "80", "accept", 40, 1),
        ("Allow Universal HTTPS Web", "any", "any", "tcp", "any", "443", "accept", 50, 1),
        ("Allow Universal ICMP Ping", "any", "any", "icmp", "any", "any", "accept", 60, 1),
    ]

    for name, src, dst, proto, sport, dport, action, prio, enabled in baseline:
        cursor.execute("""
            INSERT INTO rules (name, source, destination, protocol, source_port, destination_port, action, priority, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (name, src, dst, proto, sport, dport, action, prio, enabled))


# ---------------------------------------------------------------------------
# Rule CRUD Operations
# ---------------------------------------------------------------------------

def get_all_rules(order_by_priority: bool = True) -> List[Dict[str, Any]]:
    """Fetches all rules, sorted by priority (lowest integer = highest priority)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    order = "ORDER BY priority ASC, id ASC" if order_by_priority else "ORDER BY id ASC"
    cursor.execute(f"SELECT * FROM rules {order};")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_rule_by_id(rule_id: int) -> Optional[Dict[str, Any]]:
    """Fetches a single rule by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM rules WHERE id = ?;", (rule_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def add_rule(data: Dict[str, Any]) -> int:
    """Inserts a new validated rule."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO rules (name, source, destination, protocol, source_port, destination_port, action, priority, enabled)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        data["name"],
        data["source"],
        data["destination"],
        data["protocol"],
        data.get("source_port", "any"),
        data.get("destination_port", "any"),
        data["action"],
        data.get("priority", 100),
        data.get("enabled", 1)
    ))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def update_rule(rule_id: int, data: Dict[str, Any]) -> bool:
    """Updates an existing rule."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE rules
        SET name = ?, source = ?, destination = ?, protocol = ?,
            source_port = ?, destination_port = ?, action = ?,
            priority = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?;
    """, (
        data["name"],
        data["source"],
        data["destination"],
        data["protocol"],
        data.get("source_port", "any"),
        data.get("destination_port", "any"),
        data["action"],
        data.get("priority", 100),
        data.get("enabled", 1),
        rule_id
    ))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def toggle_rule(rule_id: int) -> Optional[int]:
    """Toggles the enabled status (1 -> 0 or 0 -> 1). Returns new status or None."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM rules WHERE id = ?;", (rule_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    new_status = 0 if row["enabled"] == 1 else 1
    cursor.execute("""
        UPDATE rules
        SET enabled = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?;
    """, (new_status, rule_id))
    conn.commit()
    conn.close()
    return new_status


def delete_rule(rule_id: int) -> bool:
    """Deletes a rule by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM rules WHERE id = ?;", (rule_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


# ---------------------------------------------------------------------------
# Logging Operations
# ---------------------------------------------------------------------------

def add_log_entry(source_ip: str, destination_ip: str, protocol: str,
                  action: str, source_port: Optional[str] = None,
                  destination_port: Optional[str] = None,
                  reason: Optional[str] = None, rule_id: Optional[int] = None):
    """Inserts a security event into the audit log."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (source_ip, destination_ip, source_port, destination_port, protocol, action, reason, rule_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    """, (source_ip, destination_ip, source_port, destination_port, protocol, action, reason, rule_id))
    conn.commit()
    conn.close()


def get_logs(limit: int = 100, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves recent logs with optional verdict filtering."""
    conn = get_db_connection()
    cursor = conn.cursor()
    if action_filter:
        cursor.execute("""
            SELECT l.*, r.name AS rule_name
            FROM logs l
            LEFT JOIN rules r ON l.rule_id = r.id
            WHERE LOWER(l.action) = LOWER(?)
            ORDER BY l.id DESC
            LIMIT ?;
        """, (action_filter, limit))
    else:
        cursor.execute("""
            SELECT l.*, r.name AS rule_name
            FROM logs l
            LEFT JOIN rules r ON l.rule_id = r.id
            ORDER BY l.id DESC
            LIMIT ?;
        """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def clear_logs():
    """Purges all log entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs;")
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Connection Tracking Cache Operations
# ---------------------------------------------------------------------------

def update_connections_cache(conns: List[Dict[str, Any]]):
    """Refreshes the active connections table from live conntrack observations."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM connections;")
    for c in conns:
        cursor.execute("""
            INSERT INTO connections (source_ip, destination_ip, source_port, destination_port, protocol, state)
            VALUES (?, ?, ?, ?, ?, ?);
        """, (
            c.get("source_ip", "0.0.0.0"),
            c.get("destination_ip", "0.0.0.0"),
            str(c.get("source_port", "")),
            str(c.get("destination_port", "")),
            c.get("protocol", "unknown"),
            c.get("state", "UNKNOWN")
        ))
    conn.commit()
    conn.close()


def get_cached_connections() -> List[Dict[str, Any]]:
    """Returns the most recent active connections."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM connections ORDER BY id DESC LIMIT 200;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Web & Domain Filtering Operations (Web Access Control)
# ---------------------------------------------------------------------------

def get_web_filters() -> List[Dict[str, Any]]:
    """Fetches all website domain filtering policies."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM web_filters ORDER BY id DESC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_web_filter_by_id(filter_id: int) -> Optional[Dict[str, Any]]:
    """Fetches a single web filter by ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM web_filters WHERE id = ?;", (filter_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def add_web_filter(domain: str, resolved_ips: str, action: str = "block", enabled: int = 1) -> int:
    """Inserts or updates a domain filter."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO web_filters (domain, resolved_ips, action, enabled)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            resolved_ips = excluded.resolved_ips,
            action = excluded.action,
            enabled = excluded.enabled;
    """, (domain.lower().strip(), resolved_ips, action.lower(), enabled))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id


def toggle_web_filter(filter_id: int) -> Optional[int]:
    """Toggles enabled status for a web filter."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT enabled FROM web_filters WHERE id = ?;", (filter_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    new_status = 0 if row["enabled"] == 1 else 1
    cursor.execute("UPDATE web_filters SET enabled = ? WHERE id = ?;", (new_status, filter_id))
    conn.commit()
    conn.close()
    return new_status


def update_web_filter_ips(filter_id: int, resolved_ips: str) -> bool:
    """Updates the resolved IP list for an existing domain filter."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE web_filters SET resolved_ips = ? WHERE id = ?;", (resolved_ips, filter_id))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0


def delete_web_filter(filter_id: int) -> Optional[Dict[str, Any]]:
    """Deletes a web filter and returns the deleted record so rules can be uninstalled."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM web_filters WHERE id = ?;", (filter_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    deleted_filter = dict(row)
    cursor.execute("DELETE FROM web_filters WHERE id = ?;", (filter_id,))
    conn.commit()
    conn.close()
    return deleted_filter


def get_active_blocked_ips() -> List[str]:
    """Returns a flat list of all active blocked IPv4 addresses from enabled web filters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT resolved_ips FROM web_filters WHERE enabled = 1 AND action = 'block';")
    rows = cursor.fetchall()
    conn.close()
    ips = []
    for r in rows:
        for ip in r["resolved_ips"].split(","):
            cleaned = ip.strip()
            if cleaned and cleaned not in ips:
                ips.append(cleaned)
    return ips


def increment_web_filter_hit(domain: str):
    """Increments the hit counter when a domain is intercepted and blocked."""
    conn = get_db_connection()
    cursor = conn.cursor()
    clean = domain.lower().strip()
    apex = clean[4:] if clean.startswith("www.") else clean
    cursor.execute("""
        UPDATE web_filters
        SET hit_count = hit_count + 1
        WHERE domain = ? OR domain = ? OR domain = ?;
    """, (clean, apex, f"www.{apex}"))
    conn.commit()
    conn.close()

