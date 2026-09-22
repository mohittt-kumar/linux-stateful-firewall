/**
 * dashboard.js - Asynchronous UI Telemetry & Firewall Operations
 */

// Show alert toasts
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.5s';
        setTimeout(() => toast.remove(), 500);
    }, 4000);
}

// Disable port input for ICMP protocol
function handleProtocolChange() {
    const protoSelect = document.getElementById('rule-protocol');
    const dportInput = document.getElementById('rule-dport');
    if (!protoSelect || !dportInput) return;

    if (protoSelect.value.toLowerCase() === 'icmp') {
        dportInput.value = 'any';
        dportInput.disabled = true;
    } else {
        dportInput.disabled = false;
    }
}

// Synchronize Database Rules to Linux Kernel (nftables)
async function syncFirewallRules() {
    try {
        const res = await fetch('/api/firewall/apply', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('✅ ' + data.message, 'success');
        } else {
            showToast('❌ Failed: ' + data.message, 'error');
        }
    } catch (err) {
        showToast('❌ Network error syncing firewall.', 'error');
    }
}

// Add New Firewall Rule via Form
async function handleAddRule(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    try {
        const res = await fetch('/api/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (data.success) {
            showToast('🛡️ ' + data.message, 'success');
            form.reset();
            setTimeout(() => location.reload(), 800);
        } else {
            showToast('❌ Validation Error: ' + (data.error || 'Failed'), 'error');
        }
    } catch (err) {
        showToast('❌ Network error saving rule.', 'error');
    }
}

// Toggle Rule Enabled/Disabled
async function toggleRule(ruleId) {
    try {
        const res = await fetch(`/api/rules/${ruleId}/toggle`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            const btn = document.getElementById(`btn-toggle-${ruleId}`);
            const row = document.getElementById(`rule-row-${ruleId}`);
            if (data.enabled === 1) {
                btn.className = 'btn-toggle toggle-on';
                btn.textContent = 'ENABLED';
                if (row) row.classList.remove('rule-disabled');
                showToast(`Rule #${ruleId} enabled and applied.`, 'success');
            } else {
                btn.className = 'btn-toggle toggle-off';
                btn.textContent = 'DISABLED';
                if (row) row.classList.add('rule-disabled');
                showToast(`Rule #${ruleId} disabled.`, 'success');
            }
        } else {
            showToast('❌ ' + data.error, 'error');
        }
    } catch (err) {
        showToast('❌ Error toggling rule.', 'error');
    }
}

// Delete Firewall Rule
async function deleteRule(ruleId, ruleName) {
    if (!confirm(`Are you sure you want to delete rule "${ruleName}" (ID: ${ruleId})?`)) {
        return;
    }

    try {
        const res = await fetch(`/api/rules/${ruleId}/delete`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('🗑️ ' + data.message, 'success');
            const row = document.getElementById(`rule-row-${ruleId}`);
            if (row) row.remove();
        } else {
            showToast('❌ ' + data.error, 'error');
        }
    } catch (err) {
        showToast('❌ Error deleting rule.', 'error');
    }
}

// Clear Audit Logs
async function clearAuditLogs() {
    if (!confirm('Are you sure you want to clear all firewall logs?')) return;
    try {
        const res = await fetch('/api/logs/clear', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast('Log records purged.', 'success');
            setTimeout(() => location.reload(), 500);
        }
    } catch (err) {
        showToast('Error clearing logs.', 'error');
    }
}

// Execute C++ Log Analyzer & Display Analytics
async function runTrafficAnalyzer() {
    const resultsCard = document.getElementById('analyzer-results');
    const summaryBox = document.getElementById('analytics-summary');
    const engineTag = document.getElementById('analyzer-engine-tag');

    if (!resultsCard || !summaryBox) return;

    summaryBox.innerHTML = '<p class="text-muted">Analyzing log telemetry and connection attempts...</p>';
    resultsCard.style.display = 'block';

    try {
        const res = await fetch('/api/analyzer/run', { method: 'POST' });
        const data = await res.json();

        if (data.success && data.analysis) {
            const a = data.analysis;
            engineTag.textContent = data.engine || 'C++ Analyzer';

            let topBlockedHtml = '<li>None</li>';
            if (a.top_blocked_sources && a.top_blocked_sources.length > 0) {
                topBlockedHtml = a.top_blocked_sources
                    .map(([ip, cnt]) => `<li><code>${ip}</code> &mdash; <strong>${cnt}</strong> drops</li>`)
                    .join('');
            }

            let topPortsHtml = '<li>None</li>';
            if (a.targeted_destination_ports && a.targeted_destination_ports.length > 0) {
                topPortsHtml = a.targeted_destination_ports
                    .map(([port, cnt]) => `<li>Port <code>${port}</code> &mdash; <strong>${cnt}</strong> hits</li>`)
                    .join('');
            }

            summaryBox.innerHTML = `
                <div class="grid-2-col" style="margin-top: 0.75rem;">
                    <div>
                        <h4 style="font-size: 12px; text-transform: uppercase; color: var(--accent-rose); margin-bottom: 0.5rem;">
                            🚨 Top Blocked Source IPs
                        </h4>
                        <ul style="padding-left: 1.25rem; font-size: 13px;">${topBlockedHtml}</ul>
                    </div>
                    <div>
                        <h4 style="font-size: 12px; text-transform: uppercase; color: var(--accent-cyan); margin-bottom: 0.5rem;">
                            🎯 Targeted Destination Ports
                        </h4>
                        <ul style="padding-left: 1.25rem; font-size: 13px;">${topPortsHtml}</ul>
                    </div>
                </div>
            `;
            showToast('Analysis completed successfully.', 'success');
        } else {
            summaryBox.innerHTML = '<p class="text-danger">Failed to generate analytics.</p>';
        }
    } catch (err) {
        summaryBox.innerHTML = '<p class="text-danger">Failed to execute traffic analyzer.</p>';
    }
}

// Background Polling for Live Telemetry (Runs on Dashboard)
function startLivePolling() {
    const cardStatus = document.getElementById('card-status');
    const cardAllowed = document.getElementById('card-allowed');
    const cardBlocked = document.getElementById('card-blocked');
    const cardConns = document.getElementById('card-conns');

    if (!cardStatus) return; // Not on dashboard page

    setInterval(async () => {
        try {
            const res = await fetch('/api/stats');
            if (res.ok) {
                const data = await res.json();
                if (cardStatus) cardStatus.textContent = data.status;
                if (cardAllowed) cardAllowed.textContent = data.allowed_packets;
                if (cardBlocked) cardBlocked.textContent = data.blocked_packets;
                if (cardConns) cardConns.textContent = data.active_connections_count;
            }
        } catch (e) {
            // Silently ignore transient network glitches during polling
        }
    }, 3500);
}

document.addEventListener('DOMContentLoaded', () => {
    startLivePolling();
});
