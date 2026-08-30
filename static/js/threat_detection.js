// ==========================================================================
// DNSWatch Threat Detection Controller
// ==========================================================================

let maliciousSearchTimeout = null;
let rulesSearchTimeout = null;
let cachedRules = [];

document.addEventListener('DOMContentLoaded', () => {
  loadThreatSummary();
  loadMaliciousDomains();
  loadDomainRules();
  loadFrequencyRule();
});

// 1. Summary Counts
async function loadThreatSummary() {
  try {
    const res = await fetch('/api/threats/summary');
    const data = await res.json();
    if (data.success) {
      document.getElementById('threat-cnt-malicious').textContent = data.malicious_domains_count;
      document.getElementById('threat-cnt-rules').textContent = data.domain_rules_count;
      document.getElementById('threat-cnt-freq').textContent = data.frequency_rules_count;
      document.getElementById('threat-cnt-today').textContent = data.threats_detected_today;
    }
  } catch (err) {
    console.error('Error loading threat summary:', err);
  }
}

// --------------------------------------------------------------------------
// Section 1: Malicious Domains
// --------------------------------------------------------------------------
function debounceMaliciousSearch() {
  clearTimeout(maliciousSearchTimeout);
  maliciousSearchTimeout = setTimeout(loadMaliciousDomains, 300);
}

async function loadMaliciousDomains() {
  const search = document.getElementById('malicious-search-input').value.trim();
  const url = new URL('/api/threats/domains', window.location.origin);
  if (search) url.searchParams.set('search', search);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('malicious-domains-tbody');

    if (data.success && data.domains && data.domains.length > 0) {
      tbody.innerHTML = data.domains.map(d => {
        const statusBadge = d.status.toLowerCase() === 'active' 
          ? `<span class="badge badge-safe" style="cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Inactive')">Active</span>`
          : `<span class="badge" style="background:#f1f5f9; color:#64748b; cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Active')">Inactive</span>`;

        return `
          <tr>
            <td style="font-weight: 600; font-family: monospace; color: #ef4444;">${d.domain}</td>
            <td><span style="background: #f1f5f9; padding: 2px 8px; border-radius: 4px; font-size: 11px;">${d.category}</span></td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${d.added_at || d.created_at}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${d.added_by || 'admin'}</td>
            <td>${statusBadge}</td>
            <td>
              <button class="btn-icon" onclick="deleteMaliciousDomain(${d.id}, '${d.domain}')" title="Delete Domain">
                <i class="fa-regular fa-trash-can"></i>
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
            No malicious domains registered. Click <strong>+ Add Domain</strong> to register a threat.
          </td>
        </tr>
      `;
    }
  } catch (err) {
    console.error('Error loading malicious domains:', err);
  }
}

function openAddDomainModal() {
  document.getElementById('form-add-domain').reset();
  document.getElementById('modal-add-domain').classList.add('show');
}

async function submitAddDomain(e) {
  e.preventDefault();
  const domain = document.getElementById('input-domain-name').value.trim();
  const category = document.getElementById('input-domain-cat').value;
  const severity = document.getElementById('input-domain-sev').value;
  const description = document.getElementById('input-domain-desc').value.trim();

  try {
    const res = await fetch('/api/threats/domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, category, severity, description, status: 'Active' })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-add-domain');
      loadMaliciousDomains();
      loadThreatSummary();
    } else {
      alert('Error: ' + data.message);
    }
  } catch (err) {
    console.error('Error adding domain:', err);
  }
}

async function toggleDomainStatus(id, newStatus) {
  try {
    const res = await fetch(`/api/threats/domains/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    const data = await res.json();
    if (data.success) {
      loadMaliciousDomains();
    }
  } catch (err) {
    console.error('Error toggling domain status:', err);
  }
}

async function deleteMaliciousDomain(id, domain) {
  if (!confirm(`Are you sure you want to remove '${domain}' from the malicious domain list?`)) return;
  try {
    const res = await fetch(`/api/threats/domains/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      loadMaliciousDomains();
      loadThreatSummary();
    }
  } catch (err) {
    console.error('Error deleting domain:', err);
  }
}

// --------------------------------------------------------------------------
// Section 2: Domain Rules (Basic Domain Rule Checking)
// --------------------------------------------------------------------------
function debounceRulesSearch() {
  clearTimeout(rulesSearchTimeout);
  rulesSearchTimeout = setTimeout(loadDomainRules, 300);
}

async function loadDomainRules() {
  const search = document.getElementById('rules-search-input').value.trim();
  const url = new URL('/api/threats/rules', window.location.origin);
  if (search) url.searchParams.set('search', search);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('domain-rules-tbody');

    if (data.success && data.rules && data.rules.length > 0) {
      cachedRules = data.rules;
      tbody.innerHTML = data.rules.map(r => {
        const actionBadge = (r.action || 'Alert').toLowerCase() === 'block'
          ? '<span class="badge badge-blocked">Block</span>'
          : '<span class="badge badge-suspicious">Alert</span>';

        const statusBadge = r.is_active
          ? `<span class="badge badge-safe" style="cursor: pointer;" onclick="toggleRuleActive(${r.id}, false)">Active</span>`
          : `<span class="badge" style="background:#f1f5f9; color:#64748b; cursor: pointer;" onclick="toggleRuleActive(${r.id}, true)">Inactive</span>`;

        return `
          <tr>
            <td style="font-weight: 600;">${r.rule_name}</td>
            <td><span style="background: #e0f2fe; color: #0369a1; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;">${r.type}</span></td>
            <td style="font-family: monospace; font-size: 12px; color: var(--text-main); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.pattern}">${r.pattern}</td>
            <td>${actionBadge}</td>
            <td>${statusBadge}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${r.last_modified}</td>
            <td>
              <div style="display: flex; gap: 4px;">
                <button class="btn-icon" onclick="openEditRuleModal(${r.id})" title="Edit Rule"><i class="fa-regular fa-pen-to-square"></i></button>
                <button class="btn-icon" onclick="deleteRule(${r.id}, '${r.rule_name}')" title="Delete Rule"><i class="fa-regular fa-trash-can"></i></button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">
            No domain detection rules configured. Click <strong>+ Add Rule</strong> to create one.
          </td>
        </tr>
      `;
    }
  } catch (err) {
    console.error('Error loading domain rules:', err);
  }
}

function openAddRuleModal() {
  document.getElementById('form-add-rule').reset();
  document.getElementById('input-rule-id').value = '';
  document.getElementById('modal-rule-title').textContent = 'Add Domain Rule';
  document.getElementById('modal-add-rule').classList.add('show');
}

function openEditRuleModal(ruleId) {
  const r = cachedRules.find(item => item.id === ruleId);
  if (!r) return;

  document.getElementById('input-rule-id').value = r.id;
  document.getElementById('input-rule-name').value = r.rule_name;
  document.getElementById('input-rule-type').value = r.rule_type;
  document.getElementById('input-rule-pattern').value = r.pattern;
  document.getElementById('input-rule-action').value = r.action || 'Alert';
  document.getElementById('input-rule-sev').value = r.severity || 'MEDIUM';

  document.getElementById('modal-rule-title').textContent = 'Edit Domain Rule';
  document.getElementById('modal-add-rule').classList.add('show');
}

async function submitRule(e) {
  e.preventDefault();
  const ruleId = document.getElementById('input-rule-id').value;
  const payload = {
    rule_name: document.getElementById('input-rule-name').value.trim(),
    rule_type: document.getElementById('input-rule-type').value,
    pattern: document.getElementById('input-rule-pattern').value.trim(),
    action: document.getElementById('input-rule-action').value,
    severity: document.getElementById('input-rule-sev').value
  };

  try {
    const endpoint = ruleId ? `/api/threats/rules/${ruleId}` : '/api/threats/rules';
    const method = ruleId ? 'PUT' : 'POST';

    const res = await fetch(endpoint, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-add-rule');
      loadDomainRules();
      loadThreatSummary();
    } else {
      alert('Error: ' + data.message);
    }
  } catch (err) {
    console.error('Error saving rule:', err);
  }
}

async function toggleRuleActive(id, isActive) {
  try {
    const res = await fetch(`/api/threats/rules/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ is_active: isActive })
    });
    const data = await res.json();
    if (data.success) {
      loadDomainRules();
    }
  } catch (err) {
    console.error('Error toggling rule active state:', err);
  }
}

async function deleteRule(id, ruleName) {
  if (!confirm(`Are you sure you want to delete rule '${ruleName}'?`)) return;
  try {
    const res = await fetch(`/api/threats/rules/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      loadDomainRules();
      loadThreatSummary();
    }
  } catch (err) {
    console.error('Error deleting rule:', err);
  }
}

// --------------------------------------------------------------------------
// Section 3: DNS Query Frequency Rule
// --------------------------------------------------------------------------
async function loadFrequencyRule() {
  try {
    const res = await fetch('/api/threats/frequency-rule');
    const data = await res.json();
    if (data.success && data.frequency_rule) {
      const f = data.frequency_rule;
      document.getElementById('freq-val-threshold').textContent = `${f.threshold} queries`;
      document.getElementById('freq-val-window').textContent = `${f.time_window} seconds`;
      
      const actBadge = f.action.toLowerCase() === 'block' ? '<span class="badge badge-blocked">Block</span>' : '<span class="badge badge-suspicious">Alert</span>';
      document.getElementById('freq-val-action').innerHTML = actBadge;

      const statBadge = f.status.toLowerCase() === 'active' ? '<span class="badge badge-safe">Active</span>' : '<span class="badge" style="background:#f1f5f9; color:#64748b;">Inactive</span>';
      document.getElementById('freq-val-status').innerHTML = statBadge;

      // Populate edit modal fields
      document.getElementById('input-freq-threshold').value = f.threshold;
      document.getElementById('input-freq-window').value = f.time_window;
      document.getElementById('input-freq-action').value = f.action;
      document.getElementById('input-freq-status').value = f.status;
    }
  } catch (err) {
    console.error('Error loading frequency rule:', err);
  }
}

function openEditFreqModal() {
  document.getElementById('modal-edit-freq').classList.add('show');
}

async function submitFrequencyRule(e) {
  e.preventDefault();
  const payload = {
    threshold: document.getElementById('input-freq-threshold').value,
    time_window: document.getElementById('input-freq-window').value,
    action: document.getElementById('input-freq-action').value,
    status: document.getElementById('input-freq-status').value
  };

  try {
    const res = await fetch('/api/threats/frequency-rule', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-edit-freq');
      loadFrequencyRule();
    } else {
      alert('Error updating frequency rule: ' + data.message);
    }
  } catch (err) {
    console.error('Error submitting frequency rule:', err);
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.classList.remove('show');
}
