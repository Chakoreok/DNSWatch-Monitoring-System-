// ==========================================================================
// DNSWatch Threat Detection Controller & Heuristic Sandbox
// ==========================================================================

let maliciousSearchTimeout = null;
let rulesSearchTimeout = null;
let cachedRules = [];
let cachedDomains = [];

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
// Interactive Domain Testing Sandbox
// --------------------------------------------------------------------------
async function testDomainAgainstRules() {
  const input = document.getElementById('sandbox-domain-input');
  const resultBox = document.getElementById('sandbox-result-box');
  if (!input || !resultBox) return;

  const rawDomain = input.value.trim().toLowerCase();
  if (!rawDomain) {
    showToast('Please enter a domain to test in sandbox', 'warning');
    return;
  }

  resultBox.style.display = 'block';
  resultBox.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Evaluating heuristic rules and threat feeds...';
  resultBox.style.background = 'var(--bg-surface-elevated)';
  resultBox.style.border = '1px solid var(--border-color)';
  resultBox.style.color = 'var(--text-main)';

  // 1. Check if domain matches any active malicious domain
  const matchedDomain = cachedDomains.find(d => {
    if ((d.status || '').toLowerCase() !== 'active') return false;
    const target = (d.domain || '').toLowerCase();
    return rawDomain === target || rawDomain.endsWith('.' + target);
  });

  if (matchedDomain) {
    resultBox.style.background = 'rgba(239, 68, 68, 0.12)';
    resultBox.style.border = '1px solid rgba(239, 68, 68, 0.35)';
    resultBox.style.color = '#f87171';
    resultBox.innerHTML = `
      <div style="font-weight: 700; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
        <i class="fa-solid fa-ban"></i> MATCH FOUND: Malicious Domain Feed
      </div>
      <div>Domain <code>${rawDomain}</code> is listed in category <strong>${matchedDomain.category}</strong> (Severity: ${matchedDomain.severity || 'HIGH'}). Action: <strong>BLOCKED / SUSPICIOUS</strong>.</div>
    `;
    return;
  }

  // 2. Check against custom heuristic rules
  for (const rule of cachedRules) {
    if (!rule.is_active) continue;
    const rtype = (rule.rule_type || rule.type || '').toUpperCase();
    const pattern = (rule.pattern || '').toLowerCase();
    let isMatch = false;
    let reason = '';

    if (rtype === 'KEYWORD') {
      const keywords = pattern.split(',').map(k => k.trim()).filter(Boolean);
      for (const kw of keywords) {
        if (rawDomain.includes(kw)) {
          isMatch = true;
          reason = `Keyword '${kw}' found in domain`;
          break;
        }
      }
    } else if (rtype === 'TLD_BLACKLIST') {
      const tlds = pattern.split(',').map(t => t.trim()).filter(Boolean);
      for (const tld of tlds) {
        const cleanTld = tld.startsWith('.') ? tld : '.' + tld;
        if (rawDomain.endsWith(cleanTld)) {
          isMatch = true;
          reason = `Blacklisted TLD extension '${cleanTld}' detected`;
          break;
        }
      }
    } else if (rtype === 'REGEX') {
      try {
        const regex = new RegExp(rule.pattern, 'i');
        if (regex.test(rawDomain)) {
          isMatch = true;
          reason = `Regular expression /${rule.pattern}/ matched`;
        }
      } catch (e) {
        // Invalid regex ignore
      }
    } else if (rtype === 'PATTERN') {
      const wildcard = pattern.replace(/\*/g, '.*');
      try {
        const regex = new RegExp(`^${wildcard}$`, 'i');
        if (regex.test(rawDomain) || rawDomain.includes(pattern.replace(/\*/g, ''))) {
          isMatch = true;
          reason = `Pattern '${pattern}' matched`;
        }
      } catch (e) {}
    }

    if (isMatch) {
      resultBox.style.background = 'rgba(245, 158, 11, 0.12)';
      resultBox.style.border = '1px solid rgba(245, 158, 11, 0.35)';
      resultBox.style.color = '#fbbf24';
      resultBox.innerHTML = `
        <div style="font-weight: 700; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
          <i class="fa-solid fa-triangle-exclamation"></i> MATCH FOUND: Rule "${rule.rule_name}"
        </div>
        <div>Condition: ${reason}. Action: <strong>${rule.action || 'Alert'}</strong> (Severity: ${rule.severity || 'MEDIUM'}).</div>
      `;
      return;
    }
  }

  // Safe result
  resultBox.style.background = 'rgba(16, 185, 129, 0.12)';
  resultBox.style.border = '1px solid rgba(16, 185, 129, 0.35)';
  resultBox.style.color = '#34d399';
  resultBox.innerHTML = `
    <div style="font-weight: 700; margin-bottom: 4px; display: flex; align-items: center; gap: 8px;">
      <i class="fa-solid fa-circle-check"></i> CLEAN DOMAIN (NO MATCHES)
    </div>
    <div>Domain <code>${rawDomain}</code> passed all heuristic keyword, TLD, and blacklist checks without triggering rules.</div>
  `;
}

// --------------------------------------------------------------------------
// Section 1: Malicious Domains Feed
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
      cachedDomains = data.domains;
      tbody.innerHTML = data.domains.map(d => {
        const statusBadge = (d.status || '').toLowerCase() === 'active' 
          ? `<span class="badge badge-safe" style="cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Inactive')"><i class="fa-solid fa-check"></i> Active</span>`
          : `<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-light); cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Active')">Inactive</span>`;

        return `
          <tr>
            <td style="font-weight: 600; font-family: var(--font-mono); color: #f87171;">
              <span style="cursor: pointer;" onclick="copyToClipboard('${d.domain}', 'Domain')">${d.domain}</span>
            </td>
            <td><span style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); padding: 2px 8px; border-radius: var(--radius-xs); font-size: 11px;">${d.category}</span></td>
            <td style="color: var(--text-muted); font-size: 11.5px; font-family: var(--font-mono);">${d.added_at || d.created_at}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${d.added_by || 'admin'}</td>
            <td>${statusBadge}</td>
            <td>
              <button class="btn-icon" onclick="deleteMaliciousDomain(${d.id}, '${d.domain}')" title="Delete Threat Domain">
                <i class="fa-regular fa-trash-can"></i>
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 35px;">
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
  openModal('modal-add-domain');
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
      showToast(`Domain '${domain}' registered in threat blacklist`, 'success');
    } else {
      showToast('Error: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error adding domain:', err);
    showToast('Failed to add threat domain', 'danger');
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
      showToast(`Domain status updated to ${newStatus}`, 'info', 1600);
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
      showToast(`Removed '${domain}' from blacklist`, 'warning');
    }
  } catch (err) {
    console.error('Error deleting domain:', err);
  }
}

// --------------------------------------------------------------------------
// Section 2: Domain Rules (Heuristic Rule Checking)
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
          ? `<span class="badge badge-safe" style="cursor: pointer;" onclick="toggleRuleActive(${r.id}, false)"><i class="fa-solid fa-check"></i> Active</span>`
          : `<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-light); cursor: pointer;" onclick="toggleRuleActive(${r.id}, true)">Inactive</span>`;

        return `
          <tr>
            <td style="font-weight: 600;">${r.rule_name}</td>
            <td><span style="background: rgba(59, 130, 246, 0.12); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.25); padding: 2px 8px; border-radius: var(--radius-xs); font-size: 11px; font-weight: 600; font-family: var(--font-mono);">${r.type}</span></td>
            <td style="font-family: var(--font-mono); font-size: 12px; color: var(--text-main); max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.pattern}">${r.pattern}</td>
            <td>${actionBadge}</td>
            <td>${statusBadge}</td>
            <td style="color: var(--text-muted); font-size: 11.5px; font-family: var(--font-mono);">${r.last_modified}</td>
            <td>
              <div style="display: flex; gap: 4px;">
                <button class="btn-icon btn-icon-primary" onclick="openEditRuleModal(${r.id})" title="Edit Rule"><i class="fa-regular fa-pen-to-square"></i></button>
                <button class="btn-icon" onclick="deleteRule(${r.id}, '${r.rule_name}')" title="Delete Rule"><i class="fa-regular fa-trash-can"></i></button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 35px;">
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
  document.getElementById('modal-rule-title').innerHTML = '<i class="fa-solid fa-filter" style="color: var(--brand-warning);"></i> Add Domain Heuristic Rule';
  openModal('modal-add-rule');
}

function openEditRuleModal(ruleId) {
  const r = cachedRules.find(item => item.id === ruleId);
  if (!r) return;

  document.getElementById('input-rule-id').value = r.id;
  document.getElementById('input-rule-name').value = r.rule_name;
  document.getElementById('input-rule-type').value = r.rule_type || r.type;
  document.getElementById('input-rule-pattern').value = r.pattern;
  document.getElementById('input-rule-action').value = r.action || 'Alert';
  document.getElementById('input-rule-sev').value = r.severity || 'MEDIUM';

  document.getElementById('modal-rule-title').innerHTML = '<i class="fa-solid fa-pen-to-square" style="color: var(--brand-primary);"></i> Edit Domain Heuristic Rule';
  openModal('modal-add-rule');
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
      showToast(ruleId ? 'Rule updated successfully' : 'New detection rule created', 'success');
    } else {
      showToast('Error: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error saving rule:', err);
    showToast('Failed to save rule', 'danger');
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
      showToast(`Rule state updated`, 'info', 1600);
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
      showToast(`Rule '${ruleName}' deleted`, 'warning');
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

      const statBadge = f.status.toLowerCase() === 'active' ? '<span class="badge badge-safe">Active</span>' : '<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-light);">Inactive</span>';
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
  openModal('modal-edit-freq');
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
      showToast('Frequency burst rule configuration updated', 'success');
    } else {
      showToast('Error updating frequency rule: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error submitting frequency rule:', err);
    showToast('Failed to update frequency rule', 'danger');
  }
}
