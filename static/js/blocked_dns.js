// ==========================================================================
// DNSWatch Blocked DNS Controller (/blocked-dns)
// ==========================================================================

let cachedBlockedRules = [];
let blockedSearchTimeout = null;

document.addEventListener('DOMContentLoaded', () => {
  loadBlockRules();
});

function debounceBlockedSearch() {
  clearTimeout(blockedSearchTimeout);
  blockedSearchTimeout = setTimeout(() => {
    filterBlockedDnsTable();
  }, 250);
}

function filterBlockedDnsTable() {
  const query = (document.getElementById('blocked-dns-search')?.value || '').trim().toLowerCase();
  const tbody = document.getElementById('block-rules-tbody');
  if (!tbody) return;

  const filtered = cachedBlockedRules.filter(r => {
    if (!query) return true;
    return (r.domain && r.domain.toLowerCase().includes(query)) ||
           (r.reason && r.reason.toLowerCase().includes(query)) ||
           (r.created_by && r.created_by.toLowerCase().includes(query));
  });

  renderBlockedRulesRows(filtered, tbody);
}

async function loadBlockRules() {
  const tbody = document.getElementById('block-rules-tbody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/blocking/rules');
    const data = await res.json();

    if (data.success && Array.isArray(data.rules)) {
      cachedBlockedRules = data.rules;
      filterBlockedDnsTable();
    } else {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--text-muted);padding:35px;">Failed to load blocked domains.</td></tr>`;
    }
  } catch (err) {
    console.error('Error loading blocked rules:', err);
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;color:var(--brand-danger);padding:35px;">Error loading blocked domains.</td></tr>`;
  }
}

function renderBlockedRulesRows(rules, tbody) {
  if (!rules || rules.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center;color:var(--text-muted);padding:40px;">
          <i class="fa-solid fa-shield-halved" style="font-size:28px;color:var(--brand-success);margin-bottom:10px;display:block;"></i>
          No blocked domains found. Domains blocked across the system will appear here.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rules.map(r => {
    const statusBadge = r.is_active
      ? '<span class="badge badge-blocked"><i class="fa-solid fa-ban"></i> Active</span>'
      : '<span class="badge" style="background:var(--bg-surface-elevated);color:var(--text-muted);">Disabled</span>';

    const toggleBtn = r.is_active
      ? `<button class="btn btn-outline btn-sm" style="font-size:11px;padding:3px 8px;" onclick="toggleBlockRuleActive(${r.id}, false)" title="Disable block rule"><i class="fa-solid fa-pause"></i> Disable</button>`
      : `<button class="btn btn-outline btn-sm" style="font-size:11px;padding:3px 8px;color:var(--brand-success);" onclick="toggleBlockRuleActive(${r.id}, true)" title="Enable block rule"><i class="fa-solid fa-play"></i> Enable</button>`;

    return `
      <tr id="rule-row-${r.id}">
        <td style="font-family:var(--font-mono);font-weight:600;color:#f87171;">
          <span style="cursor:pointer;" onclick="if(typeof copyToClipboard==='function') copyToClipboard('${escapeHtml(r.domain)}', 'Domain')">
            <i class="fa-solid fa-ban" style="margin-right:6px;font-size:11px;"></i>${escapeHtml(r.domain)}
          </span>
        </td>
        <td style="font-size:12px;color:var(--text-muted);max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(r.reason || '-')}">
          ${escapeHtml(r.reason || '-')}
        </td>
        <td style="font-size:12px;">${escapeHtml(r.created_by || 'admin')}</td>
        <td style="font-size:12px;">${escapeHtml(r.approved_by || 'admin')}</td>
        <td>${statusBadge}</td>
        <td style="font-size:11.5px;color:var(--text-muted);font-family:var(--font-mono);">${escapeHtml(r.created_at || '-')}</td>
        <td>
          <div style="display:flex;gap:6px;align-items:center;">
            ${toggleBtn}
            <button class="btn-icon" onclick="deleteBlockRule(${r.id}, '${escapeHtml(r.domain)}')" title="Delete block rule">
              <i class="fa-regular fa-trash-can"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
}

async function toggleBlockRuleActive(ruleId, newActive) {
  try {
    const res = await fetch(`/api/blocking/rules/${ruleId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: newActive })
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') {
        showToast(data.message || 'Block rule status updated', 'info');
      }
      loadBlockRules();
    } else {
      if (typeof showToast === 'function') {
        showToast(data.message || 'Failed to update rule', 'danger');
      }
    }
  } catch (err) {
    console.error('Error toggling block rule:', err);
  }
}

async function deleteBlockRule(ruleId, domain) {
  if (!confirm(`Remove '${domain}' from Blocked DNS? Traffic to this domain will no longer be sinkholed.`)) return;

  try {
    const res = await fetch(`/api/blocking/rules/${ruleId}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') {
        showToast(data.message || `Removed '${domain}' from Blocked DNS`, 'warning');
      }
      loadBlockRules();
    } else {
      if (typeof showToast === 'function') {
        showToast(data.message || 'Failed to remove block rule', 'danger');
      }
    }
  } catch (err) {
    console.error('Error deleting block rule:', err);
  }
}

function escapeHtml(str) {
  if (!str && str !== 0) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
