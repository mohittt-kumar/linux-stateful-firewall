"""
app.py - Web-Based Management Layer for Linux Stateful Network Firewall
========================================================================
Security & Engineering Highlights:
----------------------------------
1. Restrictive Management Binding: Defaults to binding on 0.0.0.0:5000 (accessible on LAN).
2. Input Validation: Strictly routes every state-changing request through validators.py.
3. Safe Output Rendering: Relies on Jinja2 auto-escaping to mitigate Stored Cross-Site Scripting.
4. Synchronous Kernel State Sync: Rule creation/deletion triggers atomic nftables sync.
"""

import os
import subprocess
import shutil
from flask import Flask, render_template, request, jsonify, redirect, url_for, Response

from database import (
    init_db, get_all_rules, get_rule_by_id, add_rule,
    update_rule, toggle_rule, delete_rule,
    get_logs, clear_logs, get_cached_connections,
    get_web_filters, get_web_filter_by_id, add_web_filter,
    toggle_web_filter, delete_web_filter, update_web_filter_ips
)
from validators import validate_firewall_rule_payload
from firewall import (
    apply_ruleset, get_firewall_status, generate_nftables_ruleset
)
from monitoring import (
    get_interface_statistics, get_active_connections, poll_kernel_firewall_logs,
    get_network_topology_summary
)
from web_filter import (
    validate_domain, resolve_domain_ips,
    enforce_host_firewall_rule, sync_all_web_filters,
    is_admin_elevated
)
from proxy import (
    start_proxy_daemon, set_windows_browser_proxy, get_windows_browser_proxy_status
)

import atexit
import signal
import sys

app = Flask(__name__)
app.config["SECRET_KEY"] = "firewall-lab-secret-key-change-in-production"

# Initialize SQLite database on app startup
init_db()

# Start background Web Filter proxy engine on 127.0.0.1:8080
start_proxy_daemon()

# Safety Guarantee: Reset any orphaned proxy settings left over from previous unexpected shutdowns
if os.name == "nt":
    set_windows_browser_proxy(False)

def cleanup_system_on_exit():
    """Ensures Windows proxy is disabled when the application exits or is terminated."""
    if os.name == "nt":
        try:
            set_windows_browser_proxy(False)
        except Exception:
            pass

atexit.register(cleanup_system_on_exit)

def _sig_handler(signum, frame):
    cleanup_system_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, _sig_handler)
signal.signal(signal.SIGTERM, _sig_handler)
if hasattr(signal, "SIGBREAK"):
    signal.signal(signal.SIGBREAK, _sig_handler)


# ---------------------------------------------------------------------------
# HTML View Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("dashboard_view"))


@app.route("/dashboard")
def dashboard_view():
    poll_kernel_firewall_logs()
    status = get_firewall_status()
    interfaces = get_interface_statistics()
    network_info = get_network_topology_summary()
    recent_logs = get_logs(limit=8)
    active_conns = get_active_connections()

    return render_template(
        "dashboard.html",
        status=status,
        interfaces=interfaces,
        network_info=network_info,
        recent_logs=recent_logs,
        active_conns_count=len(active_conns),
        active_page="dashboard"
    )


@app.route("/rules")
def rules_view():
    rules = get_all_rules(order_by_priority=True)
    status = get_firewall_status()
    return render_template("rules.html", rules=rules, status=status, active_page="rules")


@app.route("/webfilter")
def webfilter_view():
    filters = get_web_filters()
    is_admin = is_admin_elevated()
    proxy_active = get_windows_browser_proxy_status() if os.name == "nt" else False
    return render_template(
        "webfilter.html",
        filters=filters,
        is_admin=is_admin,
        proxy_active=proxy_active,
        is_windows=(os.name == "nt"),
        active_page="webfilter"
    )


@app.route("/api/proxy/status", methods=["GET"])
def api_proxy_status():
    active = get_windows_browser_proxy_status() if os.name == "nt" else False
    return jsonify({"active": active, "is_windows": os.name == "nt"})


@app.route("/api/proxy/toggle", methods=["POST"])
def api_proxy_toggle():
    if os.name != "nt":
        return jsonify({"success": False, "error": "System proxy auto-configuration is designed for Windows desktop testing."}), 400
    current = get_windows_browser_proxy_status()
    new_state = not current
    ok = set_windows_browser_proxy(new_state)
    return jsonify({
        "success": ok,
        "active": new_state,
        "message": "Live Browser Protection ENABLED (All websites filtered via 127.0.0.1:8080)." if new_state else "Live Browser Protection DISABLED (Normal direct browsing)."
    })


@app.route("/connections")
def connections_view():
    conns = get_active_connections()
    return render_template("connections.html", connections=conns, active_page="connections")


@app.route("/logs")
def logs_view():
    poll_kernel_firewall_logs()
    action_filter = request.args.get("action")
    logs = get_logs(limit=100, action_filter=action_filter)
    return render_template(
        "logs.html",
        logs=logs,
        current_filter=action_filter or "all",
        active_page="logs"
    )


# ---------------------------------------------------------------------------
# Web Filter REST Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/webfilter", methods=["GET"])
def api_get_webfilters():
    return jsonify(get_web_filters())


@app.route("/api/webfilter", methods=["POST"])
def api_add_webfilter():
    payload = request.get_json(silent=True) or request.form.to_dict()
    domain_raw = payload.get("domain", "")
    action = payload.get("action", "block")

    valid, domain = validate_domain(domain_raw)
    if not valid:
        return jsonify({"success": False, "error": domain}), 400

    # Resolve IPs
    ips = resolve_domain_ips(domain)
    if not ips:
        return jsonify({
            "success": False,
            "error": f"Could not resolve domain '{domain}'. Please verify the domain name."
        }), 400

    ips_str = ", ".join(ips)
    filter_id = add_web_filter(domain, ips_str, action=action, enabled=1)

    # Enforce on Host OS (Windows netsh / Linux)
    enforced, msg = enforce_host_firewall_rule(domain, ips, block=(action == "block"))

    # Enforce on nftables ruleset
    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    return jsonify({
        "success": True,
        "filter_id": filter_id,
        "domain": domain,
        "resolved_ips": ips,
        "message": f"Successfully blocked {domain} on Ports 80/443 (IPs: {ips_str}). {msg}"
    })


@app.route("/api/webfilter/<int:filter_id>/toggle", methods=["POST"])
def api_toggle_webfilter(filter_id: int):
    f = get_web_filter_by_id(filter_id)
    if not f:
        return jsonify({"success": False, "error": "Filter not found"}), 404

    new_status = toggle_web_filter(filter_id)
    domain = f["domain"]
    ips = [ip.strip() for ip in f["resolved_ips"].split(",") if ip.strip()]
    should_block = (new_status == 1 and f["action"] == "block")

    enforce_host_firewall_rule(domain, ips, block=should_block)
    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    return jsonify({
        "success": True,
        "enabled": new_status,
        "domain": domain,
        "message": f"Filter for '{domain}' is now {'Active (Blocked)' if new_status == 1 else 'Disabled (Allowed)'}."
    })


@app.route("/api/webfilter/<int:filter_id>/delete", methods=["POST", "DELETE"])
def api_delete_webfilter(filter_id: int):
    deleted = delete_web_filter(filter_id)
    if not deleted:
        return jsonify({"success": False, "error": "Filter not found"}), 404

    domain = deleted["domain"]
    ips = [ip.strip() for ip in deleted["resolved_ips"].split(",") if ip.strip()]
    enforce_host_firewall_rule(domain, ips, block=False)

    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    return jsonify({
        "success": True,
        "message": f"Filter for '{domain}' deleted and unblocked."
    })


@app.route("/api/webfilter/<int:filter_id>/refresh", methods=["POST"])
def api_refresh_webfilter(filter_id: int):
    """Re-resolves DNS for a previously added domain filter."""
    f = get_web_filter_by_id(filter_id)
    if not f:
        return jsonify({"success": False, "error": "Filter not found"}), 404

    domain = f["domain"]
    ips = resolve_domain_ips(domain)
    if not ips:
        return jsonify({"success": False, "error": f"Could not resolve DNS for '{domain}'"}), 400

    ips_str = ", ".join(ips)
    update_web_filter_ips(filter_id, ips_str)

    if f["enabled"] == 1 and f["action"] == "block":
        enforce_host_firewall_rule(domain, ips, block=True)

    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    return jsonify({
        "success": True,
        "domain": domain,
        "resolved_ips": ips,
        "message": f"Re-resolved DNS for {domain}: {ips_str}"
    })


@app.route("/api/webfilter/refresh-all", methods=["POST"])
def api_refresh_all_webfilters():
    """Re-resolves DNS for all saved domain filters."""
    filters = get_web_filters()
    updated = []
    for f in filters:
        domain = f["domain"]
        ips = resolve_domain_ips(domain)
        if ips:
            ips_str = ", ".join(ips)
            update_web_filter_ips(f["id"], ips_str)
            updated.append(f"{domain} ({ips_str})")
            if f["enabled"] == 1 and f["action"] == "block":
                enforce_host_firewall_rule(domain, ips, block=True)

    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    return jsonify({
        "success": True,
        "updated_count": len(updated),
        "message": f"Successfully updated {len(updated)} domain(s)."
    })


# ---------------------------------------------------------------------------
# REST API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/stats", methods=["GET"])
def api_stats():
    """Returns telemetry metrics for live dashboard polling."""
    poll_kernel_firewall_logs()
    status = get_firewall_status()
    interfaces = get_interface_statistics()
    active_conns = get_active_connections()
    rules = get_all_rules()

    return jsonify({
        "status": status.get("status", "ONLINE"),
        "allowed_packets": status.get("allowed_packets", 0),
        "blocked_packets": status.get("blocked_packets", 0),
        "active_connections_count": len(active_conns),
        "rules_count": len(rules),
        "interfaces": interfaces,
    })


@app.route("/api/rules", methods=["GET"])
def api_get_rules():
    rules = get_all_rules(order_by_priority=True)
    return jsonify(rules)


@app.route("/api/rules", methods=["POST"])
def api_add_rule():
    """
    Creates a new firewall rule:
    1. Validates input fields strictly.
    2. Inserts into SQLite.
    3. Re-applies the ruleset to nftables atomically.
    """
    payload = request.get_json(silent=True) or request.form.to_dict()
    valid, result = validate_firewall_rule_payload(payload)

    if not valid:
        return jsonify({"success": False, "error": result.get("error", "Validation failed")}), 400

    new_id = add_rule(result)
    all_rules = get_all_rules(order_by_priority=True)

    # Sync with kernel nftables
    applied, msg = apply_ruleset(all_rules)

    return jsonify({
        "success": True,
        "rule_id": new_id,
        "message": f"Rule '{result['name']}' added successfully. {msg}"
    })


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
def api_toggle_rule(rule_id: int):
    """Toggles rule state (enabled/disabled) and re-syncs firewall."""
    new_status = toggle_rule(rule_id)
    if new_status is None:
        return jsonify({"success": False, "error": "Rule not found"}), 404

    all_rules = get_all_rules(order_by_priority=True)
    applied, msg = apply_ruleset(all_rules)

    return jsonify({
        "success": True,
        "enabled": new_status,
        "message": f"Rule ID {rule_id} status updated to {'Enabled' if new_status == 1 else 'Disabled'}."
    })


@app.route("/api/rules/<int:rule_id>/delete", methods=["POST", "DELETE"])
def api_delete_rule(rule_id: int):
    """Deletes a rule and immediately synchronizes nftables."""
    deleted = delete_rule(rule_id)
    if not deleted:
        return jsonify({"success": False, "error": "Rule not found"}), 404

    all_rules = get_all_rules(order_by_priority=True)
    applied, msg = apply_ruleset(all_rules)

    return jsonify({
        "success": True,
        "message": f"Rule {rule_id} removed and firewall re-synchronized."
    })


@app.route("/api/firewall/apply", methods=["POST"])
def api_apply_firewall():
    """Manually forces re-application of the database ruleset to nftables."""
    all_rules = get_all_rules(order_by_priority=True)
    success, msg = apply_ruleset(all_rules)
    return jsonify({"success": success, "message": msg})


@app.route("/api/firewall/export", methods=["GET"])
def api_export_nftables():
    """Exports generated native nftables configuration as plain text."""
    all_rules = get_all_rules(order_by_priority=True)
    ruleset = generate_nftables_ruleset(all_rules)
    return Response(ruleset, mimetype="text/plain")


@app.route("/api/connections", methods=["GET"])
def api_connections():
    conns = get_active_connections()
    return jsonify(conns)


@app.route("/api/logs", methods=["GET"])
def api_logs():
    poll_kernel_firewall_logs()
    action = request.args.get("action")
    limit = int(request.args.get("limit", 100))
    logs = get_logs(limit=limit, action_filter=action)
    return jsonify(logs)


@app.route("/api/logs/clear", methods=["POST"])
def api_clear_logs():
    clear_logs()
    return jsonify({"success": True, "message": "Log audit trail purged."})


@app.route("/api/analyzer/run", methods=["POST"])
def api_run_analyzer():
    """
    Executes the C++ log analyzer module if compiled,
    or falls back to built-in telemetry analysis.
    """
    poll_kernel_firewall_logs()
    logs = get_logs(limit=200)

    analyzer_bin = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analyzer", "analyzer")
    if os.name == "nt":
        analyzer_bin += ".exe"

    if os.path.exists(analyzer_bin):
        try:
            # Export logs to temporary json and run binary
            import json
            import tempfile
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as tf:
                json.dump(logs, tf)
                temp_log_path = tf.name

            proc = subprocess.run(
                [analyzer_bin, temp_log_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            os.remove(temp_log_path)

            if proc.returncode == 0:
                analysis = json.loads(proc.stdout)
                return jsonify({"success": True, "analysis": analysis, "engine": "C++ Native Analyzer"})
        except Exception as e:
            pass

    # Built-in analysis fallback
    proto_counts = {}
    blocked_ips = {}
    targeted_ports = {}

    for entry in logs:
        p = entry.get("protocol", "unknown")
        proto_counts[p] = proto_counts.get(p, 0) + 1

        if entry.get("action", "").upper() == "DROP":
            src = entry.get("source_ip", "unknown")
            blocked_ips[src] = blocked_ips.get(src, 0) + 1

        dport = entry.get("destination_port")
        if dport:
            targeted_ports[dport] = targeted_ports.get(dport, 0) + 1

    analysis = {
        "total_analyzed_events": len(logs),
        "protocol_distribution": proto_counts,
        "top_blocked_sources": sorted(blocked_ips.items(), key=lambda x: x[1], reverse=True)[:5],
        "targeted_destination_ports": sorted(targeted_ports.items(), key=lambda x: x[1], reverse=True)[:5],
        "engine": "Python Fallback Analyzer"
    }

    return jsonify({"success": True, "analysis": analysis, "engine": "Python Internal Analyzer"})


# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Ensure baseline rules are synced to nftables at startup
    rules = get_all_rules(order_by_priority=True)
    apply_ruleset(rules)

    print("=" * 65)
    print(" Linux-Based Stateful Network Firewall Web Management Console")
    print(" Default Deny Forward Policy Enabled | Stateful Inspection Active")
    print(" Web Interface accessible on http://0.0.0.0:5000")
    print("=" * 65)

    app.run(host="0.0.0.0", port=5000, debug=True)
