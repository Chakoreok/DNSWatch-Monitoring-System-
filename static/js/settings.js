// ==========================================================================
// DNSWatch Settings Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  loadNetworkInterfaces();
  loadUsers();

  // If user is Admin (admin sections present on page), initialize blocking & sinkhole
  if (document.getElementById('table-block-rules')) {
    loadSinkholeStatus();
    loadBlockRules();
    loadBlockRequests();
    // Poll sinkhole and pending requests every 5 seconds
    setInterval(() => {
      loadSinkholeStatus();
      loadBlockSummary();
    }, 5000);
  }

  // Portal sessions table (Admin/Analyst)
  if (document.getElementById('settings-viewers-tbody')) {
    loadSettingsViewers();
    setInterval(loadSettingsViewers, 20000); // Auto-refresh every 20s
  }
});

// --------------------------------------------------------------------------
// Network Capture & System
// --------------------------------------------------------------------------

async function loadNetworkInterfaces() {
  try {
    const res = await fetch('/api/monitoring/interfaces');
    const data = await res.json();
    const select = document.getElementById('settings-iface-select');
    if (select && data.success && data.interfaces && data.interfaces.length > 0) {
      select.innerHTML = '<option value="">Auto-Detect / All Interfaces</option>' +
        data.interfaces.map(iface => {
          const ipStr = iface.ip ? ` (${iface.ip})` : '';
          return `<option value="${iface.name}">${iface.description || iface.name}${ipStr}</option>`;
        }).join('');
    }
  } catch (err) {
    console.error('Error loading interfaces:', err);
  }
}

function saveCaptureSettings() {
  const selectedIface = document.getElementById('settings-iface-select').value;
  if (typeof showToast === 'function') {
    showToast(`Interface selection saved: ${selectedIface || 'Auto-Detect / All Interfaces'}`, 'success');
  } else {
    alert(`Interface selection saved: ${selectedIface || 'Auto-Detect'}. Active when monitoring starts.`);
  }
}

async function clearAllData() {
  if (!confirm("Are you sure you want to completely clear all recorded DNS logs, security alerts, devices, and website activity?")) return;
  try {
    const res = await fetch('/api/monitoring/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') {
        showToast("All sample activity data has been successfully cleared!", 'success');
      }
      setTimeout(() => {
        window.location.href = '/dashboard';
      }, 500);
    } else {
      if (typeof showToast === 'function') {
        showToast("Error: " + data.message, 'danger');
      } else {
        alert("Error: " + data.message);
      }
    }
  } catch (err) {
    console.error("Error clearing data:", err);
    if (typeof showToast === 'function') {
      showToast("Failed to clear data: " + err.message, 'danger');
    } else {
      alert("Failed to clear data: " + err.message);
    }
  }
}

// --------------------------------------------------------------------------
// User Management
// --------------------------------------------------------------------------

async function loadUsers() {
  try {
    const res = await fetch('/api/users');
    const data = await res.json();
    const tbody = document.getElementById('users-tbody');
    if (!tbody) return;

    if (data.success && data.users && data.users.length > 0) {
      tbody.innerHTML = data.users.map(u => {
        const roleBadge = (u.role || '').toLowerCase() === 'administrator'
          ? '<span class="badge" style="background:#fee2e2; color:#991b1b; font-weight:700;">Administrator</span>'
          : ((u.role || '').toLowerCase() === 'security analyst' 
             ? '<span class="badge" style="background:#fef3c7; color:#92400e; font-weight:600;">Security Analyst</span>'
             : '<span class="badge" style="background:#f1f5f9; color:#64748b;">Viewer</span>');

        return `
          <tr>
            <td style="font-weight: 600;">${escapeHtml(u.username)}</td>
            <td>${escapeHtml(u.full_name || '-')}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${escapeHtml(u.email)}</td>
            <td>${roleBadge}</td>
            <td><span class="badge badge-safe">${escapeHtml(u.status || 'ACTIVE')}</span></td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${escapeHtml(u.created_at || '-')}</td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">No users found.</td></tr>';
    }
  } catch (err) {
    console.error('Error loading users:', err);
  }
}

function openCreateUserModal() {
  const form = document.getElementById('form-create-user');
  if (form) form.reset();
  openModal('modal-create-user');
}

async function submitCreateUser(e) {
  e.preventDefault();
  const payload = {
    username: document.getElementById('input-new-username').value.trim(),
    full_name: document.getElementById('input-new-fullname').value.trim(),
    email: document.getElementById('input-new-email').value.trim(),
    password: document.getElementById('input-new-password').value.trim(),
    role_id: parseInt(document.getElementById('input-new-role').value)
  };

  try {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-create-user');
      loadUsers();
      if (typeof showToast === 'function') {
        showToast(`User account '${payload.username}' created successfully!`, 'success');
      }
    } else {
      if (typeof showToast === 'function') {
        showToast('Error creating user: ' + data.message, 'danger');
      } else {
        alert('Error creating user: ' + data.message);
      }
    }
  } catch (err) {
    console.error('Error submitting user creation:', err);
    if (typeof showToast === 'function') {
      showToast('Error submitting user creation', 'danger');
    }
  }
}

// --------------------------------------------------------------------------
// DNS Sinkhole Control (Admin)
// --------------------------------------------------------------------------

let sinkholeActive = false;

async function loadSinkholeStatus() {
  try {
    const res = await fetch('/api/monitoring/sinkhole/status');
    const data = await res.json();
    if (data.success && data.sinkhole) {
      const sh = data.sinkhole;
      sinkholeActive = sh.is_running;

      const badge = document.getElementById('sinkhole-status-badge');
      const text = document.getElementById('sinkhole-status-text');
      const btn = document.getElementById('btn-sinkhole-toggle');
      const count = document.getElementById('sinkhole-blocked-count');
      const errBox = document.getElementById('sinkhole-error-msg');

      if (badge) {
        badge.className = sh.is_running ? 'badge badge-safe' : 'badge badge-blocked';
        badge.textContent = sh.is_running ? 'Active (Listening)' : 'Inactive';
      }
      if (text) {
        text.innerHTML = sh.is_running 
          ? `<span style="color:var(--brand-success);font-weight:600;"><i class="fa-solid fa-circle-check"></i> Running on port ${sh.port}</span>`
          : '<span style="color:var(--text-muted);"><i class="fa-solid fa-circle-xmark"></i> Stopped</span>';
      }
      if (btn) {
        btn.className = sh.is_running ? 'btn btn-danger' : 'btn btn-primary';
        btn.innerHTML = sh.is_running 
          ? '<i class="fa-solid fa-stop"></i> Stop Sinkhole' 
          : '<i class="fa-solid fa-play"></i> Start Sinkhole';
      }
      if (count) {
        count.textContent = sh.blocked_domains_count || 0;
      }
      if (errBox) {
        if (sh.error_message) {
          errBox.style.display = 'block';
          errBox.textContent = 'Error: ' + sh.error_message;
        } else {
          errBox.style.display = 'none';
        }
      }
    }
  } catch (err) {
    console.error('Error loading sinkhole status:', err);
  }
}

async function toggleSinkhole() {
  const btn = document.getElementById('btn-sinkhole-toggle');
  if (btn) btn.disabled = true;

  const port = parseInt(document.getElementById('sinkhole-port-input')?.value || 53);
  const upstream = (document.getElementById('sinkhole-upstream-input')?.value || '8.8.8.8').trim();

  try {
    const endpoint = sinkholeActive ? '/api/monitoring/sinkhole/stop' : '/api/monitoring/sinkhole/start';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ port, upstream_dns: upstream })
    });
    const data = await res.json();
    if (data.message) {
      if (typeof showToast === 'function') {
        showToast(data.message, data.success ? 'success' : 'info');
      } else {
        alert(data.message);
      }
    }
    loadSinkholeStatus();
  } catch (err) {
    console.error('Error toggling sinkhole:', err);
    if (typeof showToast === 'function') {
      showToast('Failed to toggle DNS Sinkhole: ' + err.message, 'danger');
    } else {
      alert('Failed to toggle DNS Sinkhole: ' + err.message);
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

// --------------------------------------------------------------------------
// Manual Block Rules (Admin)
// --------------------------------------------------------------------------

async function loadBlockRules() {
  try {
    const res = await fetch('/api/blocking/rules');
    const data = await res.json();
    const tbody = document.getElementById('block-rules-tbody');
    if (!tbody) return;

    if (data.success && data.rules && data.rules.length > 0) {
      tbody.innerHTML = data.rules.map(r => {
        const statusBadge = r.is_active
          ? '<span class="badge badge-blocked">Active</span>'
          : '<span class="badge" style="background:#f1f5f9;color:#64748b;">Inactive</span>';

        const toggleBtn = r.is_active
          ? `<button class="btn btn-outline" style="padding:2px 8px;font-size:11px;color:#d97706;border-color:#fcd34d;" title="Deactivate rule" onclick="toggleBlockRule(${r.id}, false)">
              <i class="fa-solid fa-pause"></i> Disable
             </button>`
          : `<button class="btn btn-outline" style="padding:2px 8px;font-size:11px;color:var(--success);border-color:#86efac;" title="Activate rule" onclick="toggleBlockRule(${r.id}, true)">
              <i class="fa-solid fa-play"></i> Enable
             </button>`;

        return `
          <tr>
            <td>
              <div class="domain-cell">
                <span class="domain-icon"><i class="fa-solid fa-ban" style="color:var(--danger)"></i></span>
                <span style="font-weight:600;font-family:monospace;">${escapeHtml(r.domain)}</span>
              </div>
            </td>
            <td style="color:var(--text-muted);font-size:12px;">${escapeHtml(r.reason || '-')}</td>
            <td style="font-size:12px;">${escapeHtml(r.created_by)}</td>
            <td style="font-size:12px;">${escapeHtml(r.approved_by || '-')}</td>
            <td>${statusBadge}</td>
            <td style="color:var(--text-muted);font-size:11.5px;">${escapeHtml(r.created_at_display || r.created_at || '-')}</td>
            <td>
              <div style="display:flex;gap:6px;align-items:center;">
                ${toggleBtn}
                <button class="btn btn-outline" style="padding:2px 8px;font-size:11px;color:var(--danger);border-color:#fca5a5;" title="Delete rule" onclick="deleteBlockRule(${r.id}, '${escapeHtml(r.domain)}')">
                  <i class="fa-solid fa-trash-can"></i>
                </button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:30px;">No manual block rules created yet. Click <strong>Add Block Rule</strong> to block a domain.</td></tr>';
    }
  } catch (err) {
    console.error('Error loading block rules:', err);
  }
}

function openAddBlockRuleModal() {
  const form = document.getElementById('form-add-block-rule');
  if (form) form.reset();
  const fb = document.getElementById('add-block-rule-feedback');
  if (fb) { fb.innerHTML = ''; fb.style.display = 'none'; }
  openModal('modal-add-block-rule');
}

async function submitAddBlockRule(e) {
  e.preventDefault();
  const domain = document.getElementById('input-block-domain').value.trim();
  const reason = document.getElementById('input-block-reason').value.trim();
  const fb = document.getElementById('add-block-rule-feedback');

  try {
    const res = await fetch('/api/blocking/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, reason })
    });
    const data = await res.json();
    if (data.success) {
      if (fb) {
        fb.style.display = 'block';
        fb.style.color = 'var(--success)';
        fb.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${escapeHtml(data.message)}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message, 'success');
      }
      setTimeout(() => {
        closeModal('modal-add-block-rule');
        loadBlockRules();
        loadSinkholeStatus();
      }, 700);
    } else {
      if (fb) {
        fb.style.display = 'block';
        fb.style.color = 'var(--danger)';
        fb.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(data.message)}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message, 'danger');
      }
    }
  } catch (err) {
    if (fb) {
      fb.style.display = 'block';
      fb.style.color = 'var(--danger)';
      fb.innerHTML = `Error: ${escapeHtml(err.message)}`;
    }
  }
}

async function toggleBlockRule(ruleId, newActive) {
  try {
    const res = await fetch(`/api/blocking/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: newActive })
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') {
        showToast(data.message, 'success');
      }
      loadBlockRules();
      loadSinkholeStatus();
    } else {
      alert('Error updating rule: ' + data.message);
    }
  } catch (err) {
    console.error('Error toggling block rule:', err);
  }
}

async function deleteBlockRule(ruleId, domain) {
  if (!confirm(`Are you sure you want to delete the block rule for '${domain}'? This will unblock the domain.`)) return;
  try {
    const res = await fetch(`/api/blocking/rules/${ruleId}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') {
        showToast(data.message, 'info');
      }
      loadBlockRules();
      loadSinkholeStatus();
    } else {
      alert('Error deleting rule: ' + data.message);
    }
  } catch (err) {
    console.error('Error deleting block rule:', err);
  }
}

// --------------------------------------------------------------------------
// Block Requests Review (Admin)
// --------------------------------------------------------------------------

async function loadBlockRequests() {
  const filter = document.getElementById('req-status-filter')?.value || 'PENDING';
  try {
    const res = await fetch(`/api/blocking/requests?status=${encodeURIComponent(filter)}`);
    const data = await res.json();
    const tbody = document.getElementById('block-requests-tbody');
    if (!tbody) return;

    if (data.success && data.requests && data.requests.length > 0) {
      tbody.innerHTML = data.requests.map(req => {
        let statusBadge = '<span class="badge" style="background:#fef3c7;color:#92400e;font-weight:600;">Pending</span>';
        if (req.status === 'APPROVED') {
          statusBadge = '<span class="badge badge-safe">Approved</span>';
        } else if (req.status === 'REJECTED') {
          statusBadge = '<span class="badge" style="background:#fee2e2;color:#991b1b;">Rejected</span>';
        }

        let actionHtml = '';
        if (req.status === 'PENDING') {
          actionHtml = `
            <div style="display:flex;gap:6px;align-items:center;">
              <button class="btn btn-primary" style="padding:2px 8px;font-size:11px;background:var(--danger);border-color:var(--danger);" onclick="approveBlockRequest(${req.id}, '${escapeHtml(req.domain)}')">
                <i class="fa-solid fa-check"></i> Approve
              </button>
              <button class="btn btn-outline" style="padding:2px 8px;font-size:11px;color:#64748b;" onclick="openRejectModal(${req.id}, '${escapeHtml(req.domain)}')">
                <i class="fa-solid fa-xmark"></i> Reject
              </button>
            </div>
          `;
        } else {
          const detail = req.status === 'APPROVED' 
            ? `Approved by ${escapeHtml(req.reviewed_by || 'Admin')}`
            : `Rejected: ${escapeHtml(req.rejection_reason || '-')}`;
          actionHtml = `<span style="font-size:11px;color:var(--text-muted);">${detail}</span>`;
        }

        return `
          <tr>
            <td style="color:var(--text-muted);font-size:11px;">#${req.id}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon"><i class="fa-solid fa-globe"></i></span>
                <span style="font-weight:600;font-family:monospace;">${escapeHtml(req.domain)}</span>
              </div>
            </td>
            <td style="font-family:monospace;font-size:12px;">${escapeHtml(req.client_ip || '-')}</td>
            <td style="font-size:12px;">
              <div>${escapeHtml(req.reason)}</div>
              ${req.detection_info ? `<div style="font-size:10.5px;color:var(--text-muted);margin-top:2px;">${escapeHtml(req.detection_info)}</div>` : ''}
            </td>
            <td style="font-size:12px;">${escapeHtml(req.requested_by)}</td>
            <td style="color:var(--text-muted);font-size:11.5px;">${escapeHtml(req.requested_at_display || req.requested_at || '-')}</td>
            <td>${statusBadge}</td>
            <td>${actionHtml}</td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;color:var(--text-muted);padding:30px;">No block requests found matching '${filter}'.</td></tr>`;
    }
  } catch (err) {
    console.error('Error loading block requests:', err);
  }
}

async function loadBlockSummary() {
  try {
    const res = await fetch('/api/blocking/summary');
    const data = await res.json();
    if (data.success) {
      const badge = document.getElementById('pending-requests-badge');
      if (badge) {
        badge.textContent = data.pending_requests;
        badge.style.display = data.pending_requests > 0 ? 'inline-flex' : 'none';
      }
    }
  } catch (err) {
    // Ignore transient poll error
  }
}

async function approveBlockRequest(reqId, domain) {
  if (!confirm(`Approve block request for '${domain}'? This will immediately add a block rule and enforce it.`)) return;
  try {
    const res = await fetch(`/api/blocking/requests/${reqId}/approve`, {
      method: 'PUT'
    });
    const data = await res.json();
    if (data.success) {
      alert(data.message || `Domain '${domain}' is now blocked.`);
      loadBlockRequests();
      loadBlockRules();
      loadSinkholeStatus();
    } else {
      alert('Failed to approve request: ' + data.message);
    }
  } catch (err) {
    console.error('Error approving request:', err);
    alert('Error: ' + err.message);
  }
}

function openRejectModal(reqId, domain) {
  document.getElementById('reject-modal-req-id').value = reqId;
  document.getElementById('reject-modal-domain').textContent = domain;
  document.getElementById('input-reject-reason').value = '';
  const fb = document.getElementById('reject-modal-feedback');
  if (fb) { fb.innerHTML = ''; fb.style.display = 'none'; }
  openModal('modal-reject-request');
}

async function submitRejectRequest() {
  const reqId = document.getElementById('reject-modal-req-id').value;
  const reason = document.getElementById('input-reject-reason').value.trim();
  const fb = document.getElementById('reject-modal-feedback');

  if (!reason) {
    if (fb) {
      fb.style.display = 'block';
      fb.style.color = 'var(--danger)';
      fb.innerHTML = 'Please enter a rejection reason.';
    }
    return;
  }

  try {
    const res = await fetch(`/api/blocking/requests/${reqId}/reject`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rejection_reason: reason })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-reject-request');
      loadBlockRequests();
    } else {
      if (fb) {
        fb.style.display = 'block';
        fb.style.color = 'var(--danger)';
        fb.innerHTML = escapeHtml(data.message);
      }
    }
  } catch (err) {
    if (fb) {
      fb.style.display = 'block';
      fb.style.color = 'var(--danger)';
      fb.innerHTML = `Error: ${escapeHtml(err.message)}`;
    }
  }
}

// ==========================================================================
// Web Portal Session Monitoring (Admin / Analyst)
// ==========================================================================
async function loadSettingsViewers() {
  const tbody = document.getElementById('settings-viewers-tbody');
  if (!tbody) return;

  const roleFilter = (document.getElementById('settings-viewer-role-filter') || {}).value || '';
  let url = '/api/portal-sessions';
  if (roleFilter) url += `?role=${encodeURIComponent(roleFilter)}`;

  const isAdmin = !!document.querySelector('[data-user-role="Administrator"]') ||
                  !!document.body.getAttribute('data-user-role')?.toLowerCase().includes('admin');

  try {
    const res = await fetch(url);
    const data = await res.json();
    if (!data.success) return;

    const sessions = data.sessions || [];
    const onlineCount = data.online_count || 0;

    const badge = document.getElementById('settings-online-badge');
    if (badge) badge.textContent = onlineCount;

    if (sessions.length === 0) {
      const cols = isAdmin ? 9 : 8;
      tbody.innerHTML = `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-muted);padding:35px;">
        <i class="fa-solid fa-users-slash" style="font-size:24px;margin-bottom:8px;color:var(--text-light);"></i>
        <div>No portal sessions found.</div>
      </td></tr>`;
      return;
    }

    const browserIcons = { Chrome: 'fa-brands fa-chrome', Firefox: 'fa-brands fa-firefox-browser', Safari: 'fa-brands fa-safari', Edge: 'fa-brands fa-edge', Opera: 'fa-brands fa-opera' };

    tbody.innerHTML = sessions.map(s => {
      const isOnline = s.is_online;
      const statusDot = isOnline
        ? `<span style="display:inline-flex;align-items:center;gap:6px;"><span class="status-dot active" style="width:8px;height:8px;"></span><span style="color:var(--brand-success);font-size:12px;font-weight:600;">Online</span></span>`
        : `<span style="display:inline-flex;align-items:center;gap:6px;"><span class="status-dot" style="width:8px;height:8px;background:var(--text-light);"></span><span style="color:var(--text-muted);font-size:12px;">Offline</span></span>`;

      const role = s.role_name || 'Viewer';
      let roleBadgeClass = 'badge';
      if (role.toLowerCase().includes('admin')) roleBadgeClass += ' badge-blocked';
      else if (role.toLowerCase().includes('analyst')) roleBadgeClass += ' badge-suspicious';
      else roleBadgeClass += ' badge-safe';

      const browserIcon = browserIcons[s.browser] || 'fa-solid fa-globe';

      const adminAction = isAdmin ? `<td><button class="btn btn-outline btn-sm" onclick="endSettingsSession(${s.id}, '${s.username}')" style="color:var(--brand-danger);border-color:rgba(239,68,68,0.3);font-size:11px;"><i class="fa-solid fa-plug-circle-xmark"></i> End</button></td>` : '';

      return `<tr>
        <td>${statusDot}</td>
        <td><div style="font-weight:600;color:var(--text-main);">${s.username}</div><div style="font-size:11px;color:var(--text-muted);">ID: ${s.user_id}</div></td>
        <td><span class="${roleBadgeClass}" style="font-size:11px;">${role}</span></td>
        <td><span class="ip-chip" onclick="copyToClipboard && copyToClipboard('${s.ip_address}', 'IP')" title="Click to copy">${s.ip_address} <i class="fa-regular fa-copy"></i></span></td>
        <td><div style="font-size:12px;"><i class="${browserIcon}" style="margin-right:4px;color:var(--brand-info);"></i>${s.browser}</div><div style="font-size:11px;color:var(--text-muted);">${s.os}</div></td>
        <td style="font-size:12px;font-family:var(--font-mono);">${s.current_page || '/'}</td>
        <td style="font-size:12px;color:var(--text-muted);">${s.started_at_display}</td>
        <td style="font-size:12px;color:var(--text-muted);">${s.last_seen_ago}</td>
        ${adminAction}
      </tr>`;
    }).join('');

  } catch (err) {
    console.error('Error loading settings viewers:', err);
  }
}

async function endSettingsSession(sessionId, username) {
  if (!confirm(`Force end portal session for "${username}"?`)) return;
  try {
    const res = await fetch(`/api/portal-sessions/${sessionId}/end`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin'
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') showToast(data.message, 'success');
      loadSettingsViewers();
    } else {
      if (typeof showToast === 'function') showToast(data.message || 'Failed.', 'error');
    }
  } catch (err) { console.error(err); }
}

async function cleanupPortalSessions() {
  try {
    const res = await fetch('/api/portal-sessions/cleanup', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'same-origin'
    });
    const data = await res.json();
    if (typeof showToast === 'function') showToast(data.message, data.success ? 'success' : 'error');
    if (data.success) loadSettingsViewers();
  } catch (err) { console.error(err); }
}
