// ==========================================================================
// DNSWatch Threat Detection Controller, OSINT Feeds & Testing Sandbox
// ==========================================================================
/* global openModal, closeModal, showToast, copyToClipboard, triggerDomainBlockAnimation */

let maliciousSearchTimeout = null;
let rulesSearchTimeout = null;
let cachedRules = [];
let cachedDomains = [];
let cachedFeeds = [];

document.addEventListener('DOMContentLoaded', () => {
  loadThreatSummary();
  loadThreatFeeds();
  loadMaliciousDomains();
  loadDomainRules();
  loadFrequencyRule();
  
  // Restore user's hide/show preference for the malicious feed table
  const savedCollapse = localStorage.getItem('dnswatch_malicious_feed_collapsed');
  if (savedCollapse === 'true') {
    toggleMaliciousFeedCollapse(false);
  }
});

// --------------------------------------------------------------------------
// 1. Summary Counts & Telemetry
// --------------------------------------------------------------------------
async function loadThreatSummary() {
  try {
    const res = await fetch('/api/threats/summary');
    const data = await res.json();
    if (data.success) {
      document.getElementById('threat-cnt-malicious').textContent = (data.malicious_domains_count || 0).toLocaleString();
      document.getElementById('threat-cnt-rules').textContent = data.domain_rules_count || 0;
      if (document.getElementById('threat-cnt-feeds')) {
        document.getElementById('threat-cnt-feeds').textContent = data.threat_feeds_count || 4;
      }
      document.getElementById('threat-cnt-today').textContent = data.threats_detected_today || 0;
    }
  } catch (err) {
    console.error('Error loading threat summary:', err);
  }
}

// --------------------------------------------------------------------------
// 2. Threat Intelligence Feeds Management & Live Sync
// --------------------------------------------------------------------------
async function loadThreatFeeds() {
  const grid = document.getElementById('threat-feeds-grid');
  if (!grid) return;

  try {
    const res = await fetch('/api/threats/feeds');
    const data = await res.json();
    if (data.success && data.feeds) {
      cachedFeeds = data.feeds;
      grid.innerHTML = data.feeds.map(f => {
        const isSuccess = f.sync_status === 'SUCCESS';
        const isSyncing = f.sync_status === 'SYNCING';
        
        let statusBadge = `<span class="badge badge-safe"><i class="fa-solid fa-check"></i> Active</span>`;
        if (isSyncing) {
          statusBadge = `<span class="badge badge-suspicious"><i class="fa-solid fa-spinner fa-spin"></i> Syncing</span>`;
        } else if (f.sync_status === 'ERROR') {
          statusBadge = `<span class="badge badge-blocked"><i class="fa-solid fa-circle-exclamation"></i> Error</span>`;
        } else if (!f.is_active) {
          statusBadge = `<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-muted);">Disabled</span>`;
        }

        const iconMap = {
          'URLHAUS': 'fa-solid fa-skull-crossbones',
          'OPENPHISH': 'fa-solid fa-fish-fins',
          'THREATFOX': 'fa-solid fa-shield-virus',
          'OSINT_SEED': 'fa-solid fa-database',
          'CUSTOM': 'fa-solid fa-network-wired'
        };
        const icon = iconMap[f.feed_type] || 'fa-solid fa-satellite-dish';

        return `
          <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 18px; display: flex; flex-direction: column; justify-content: space-between; position: relative;">
            <div>
              <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <div style="width: 32px; height: 32px; border-radius: var(--radius-sm); background: rgba(59, 130, 246, 0.12); color: var(--brand-primary); display: flex; align-items: center; justify-content: center; font-size: 14px;">
                    <i class="${icon}"></i>
                  </div>
                  <div>
                    <h4 style="font-size: 13.5px; font-weight: 700; color: var(--text-main); margin: 0;">${f.name}</h4>
                    <span style="font-size: 11px; color: var(--text-muted);">${f.category}</span>
                  </div>
                </div>
                ${statusBadge}
              </div>
              <p style="font-size: 12px; color: var(--text-muted); line-height: 1.4; margin: 8px 0 12px; min-height: 34px;">
                ${f.description || f.source_url}
              </p>
            </div>
            <div>
              <div style="display: flex; justify-content: space-between; align-items: center; font-size: 11.5px; padding-top: 10px; border-top: 1px solid var(--border-color); color: var(--text-muted);">
                <span><i class="fa-solid fa-database"></i> <strong>${(f.domain_count || 0).toLocaleString()}</strong> domains</span>
                <span><i class="fa-regular fa-clock"></i> ${f.last_synced}</span>
              </div>
              <div style="margin-top: 10px; display: flex; gap: 6px;">
                <button class="btn btn-sm btn-outline" style="flex: 1; padding: 4px 8px; font-size: 11px;" onclick="syncSingleFeed(${f.id})" title="Sync Feed Now">
                  <i class="fa-solid fa-rotate"></i> Sync
                </button>
                <button class="btn btn-sm btn-outline" style="padding: 4px 8px; font-size: 11px;" onclick="toggleFeedState(${f.id})" title="Toggle Active">
                  <i class="fa-solid fa-power-off"></i>
                </button>
              </div>
            </div>
          </div>
        `;
      }).join('');
    }
  } catch (err) {
    console.error('Error loading threat feeds:', err);
  }
}

async function syncAllThreatFeeds() {
  const btn = document.getElementById('btn-sync-feeds');
  const originalHtml = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Syncing Live Threat Feeds...`;

  try {
    const res = await fetch('/api/threats/feeds/sync', { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(`Threat feeds synchronized: ${data.new_domains_added} new threats ingested!`, 'success', 3500);
      loadThreatSummary();
      loadThreatFeeds();
      loadMaliciousDomains();
    } else {
      showToast('Threat feed sync error: ' + (data.message || 'Failed'), 'danger');
    }
  } catch (err) {
    console.error('Error syncing feeds:', err);
    showToast('Failed to connect to feed synchronization service', 'danger');
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalHtml;
  }
}

async function syncSingleFeed(feedId) {
  try {
    showToast('Syncing feed...', 'info', 1500);
    const res = await fetch(`/api/threats/feeds/${feedId}/sync`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'success');
      loadThreatFeeds();
      loadThreatSummary();
      loadMaliciousDomains();
    } else {
      showToast('Sync failed: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error syncing single feed:', err);
  }
}

async function toggleFeedState(feedId) {
  try {
    const res = await fetch(`/api/threats/feeds/${feedId}/toggle`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      showToast(data.message, 'info');
      loadThreatFeeds();
    }
  } catch (err) {
    console.error('Error toggling feed state:', err);
  }
}

// --------------------------------------------------------------------------
// 3. Domain Rule Testing Sandbox & Deep Threat Analyzer
// --------------------------------------------------------------------------
function switchSandboxTab(tab) {
  const singleTab = document.getElementById('sandbox-single-tab');
  const batchTab = document.getElementById('sandbox-batch-tab');
  const btnSingle = document.getElementById('btn-tab-single');
  const btnBatch = document.getElementById('btn-tab-batch');

  if (tab === 'single') {
    singleTab.style.display = 'block';
    batchTab.style.display = 'none';
    btnSingle.className = 'btn btn-sm btn-primary';
    btnBatch.className = 'btn btn-sm btn-outline';
  } else {
    singleTab.style.display = 'none';
    batchTab.style.display = 'block';
    btnSingle.className = 'btn btn-sm btn-outline';
    btnBatch.className = 'btn btn-sm btn-primary';
  }
}

function loadPreset(domain) {
  document.getElementById('sandbox-domain-input').value = domain;
  runSandboxEvaluation();
}

async function runSandboxEvaluation() {
  const input = document.getElementById('sandbox-domain-input');
  const resultBox = document.getElementById('sandbox-result-box');
  const btn = document.getElementById('btn-run-sandbox');
  if (!input || !resultBox) return;

  const rawDomain = input.value.trim().toLowerCase();
  if (!rawDomain) {
    showToast('Please enter a target domain to test in sandbox', 'warning');
    return;
  }

  resultBox.style.display = 'block';
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Evaluating...`;

  resultBox.innerHTML = `
    <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 24px; text-align: center; color: var(--text-muted);">
      <i class="fa-solid fa-circle-notch fa-spin" style="font-size: 24px; color: var(--brand-primary); margin-bottom: 12px;"></i>
      <div style="font-size: 14px; font-weight: 600; color: var(--text-main);">Running Deep Multi-Tier Threat Engine Inspection...</div>
      <div style="font-size: 12px; margin-top: 4px;">Evaluating Shannon entropy, brand impersonation, feed blacklists, and socket DNS resolution for <code>${rawDomain}</code></div>
    </div>
  `;

  try {
    const res = await fetch('/api/threats/sandbox/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: rawDomain })
    });
    const data = await res.json();
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-play"></i> Run Sandbox Test`;

    if (!data.success) {
      resultBox.innerHTML = `<div class="alert alert-danger">${data.message || 'Evaluation error'}</div>`;
      return;
    }

    renderSandboxResult(data);
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-play"></i> Run Sandbox Test`;
    console.error('Sandbox evaluation error:', err);
    resultBox.innerHTML = `<div class="alert alert-danger">Failed to evaluate domain. Network error.</div>`;
  }
}

function renderSandboxResult(report) {
  const resultBox = document.getElementById('sandbox-result-box');
  const d = report.diagnostics;
  const score = report.threat_score;
  const verdict = report.verdict;

  let themeColor = '#10b981'; // Green (Safe)
  let verdictBadge = `<span class="badge badge-safe" style="font-size: 13px; padding: 6px 14px;"><i class="fa-solid fa-circle-check"></i> CLEAN / SAFE DOMAIN</span>`;
  let bannerBg = 'rgba(16, 185, 129, 0.08)';
  let bannerBorder = 'rgba(16, 185, 129, 0.3)';

  if (verdict === 'BLOCKED') {
    themeColor = '#ef4444'; // Red
    verdictBadge = `<span class="badge badge-blocked" style="font-size: 13px; padding: 6px 14px;"><i class="fa-solid fa-ban"></i> MALICIOUS / BLOCKED</span>`;
    bannerBg = 'rgba(239, 68, 68, 0.1)';
    bannerBorder = 'rgba(239, 68, 68, 0.35)';
  } else if (verdict === 'SUSPICIOUS') {
    themeColor = '#f59e0b'; // Amber
    verdictBadge = `<span class="badge badge-suspicious" style="font-size: 13px; padding: 6px 14px;"><i class="fa-solid fa-triangle-exclamation"></i> SUSPICIOUS THREAT</span>`;
    bannerBg = 'rgba(245, 158, 11, 0.1)';
    bannerBorder = 'rgba(245, 158, 11, 0.35)';
  }

  // Diagnostic items
  const dnsRes = d.dns_resolution || {};
  const dnsText = dnsRes.resolved 
    ? `<span style="color:#34d399;"><i class="fa-solid fa-circle-check"></i> Live IP: <code>${dnsRes.ips.join(', ')}</code></span>` 
    : `<span style="color:#f87171;"><i class="fa-solid fa-circle-xmark"></i> ${dnsRes.status || 'NXDOMAIN (Unresolved)'}</span>`;

  const feedMatch = d.threat_feed.matched 
    ? `<span style="color:#f87171; font-weight:600;"><i class="fa-solid fa-skull"></i> Matched ${d.threat_feed.entry.feed_source || 'Feed'} (${d.threat_feed.entry.category})</span>` 
    : `<span style="color:var(--text-muted);"><i class="fa-solid fa-check"></i> No known feed records</span>`;

  const brandInfo = d.brand_impersonation || {};
  const brandText = brandInfo.detected 
    ? `<span style="color:#fbbf24; font-weight:600;"><i class="fa-solid fa-masks-theater"></i> Impersonating <strong>${brandInfo.targeted_brand}</strong> (Lures: ${brandInfo.lures ? brandInfo.lures.join(', ') : 'None'})</span>` 
    : `<span style="color:var(--text-muted);"><i class="fa-solid fa-check"></i> No deceptive brand lures</span>`;

  const lexical = d.lexical || {};
  const entropyBadge = lexical.entropy >= 3.8 
    ? `<span class="badge badge-blocked">${lexical.entropy} (High DGA Risk)</span>` 
    : `<span class="badge badge-safe">${lexical.entropy} (Normal)</span>`;

  const tunneling = d.tunneling || {};
  const tunnelingText = tunneling.is_tunnel_candidate 
    ? `<span style="color:#f87171; font-weight:600;"><i class="fa-solid fa-network-wired"></i> Exfiltration Pattern Detected (Depth: ${tunneling.subdomain_depth})</span>` 
    : `<span style="color:var(--text-muted);"><i class="fa-solid fa-check"></i> Standard query structure</span>`;

  const rulesHit = d.rules_hit || [];
  const rulesListHtml = rulesHit.length > 0 
    ? rulesHit.map(r => `<div style="font-size:11.5px; margin-top:2px;">• <strong style="color:#fbbf24;">${r.name}</strong> (${r.type}): <code>${r.matched_condition}</code> [Action: ${r.action}]</div>`).join('') 
    : `<div style="color:var(--text-muted); font-size:12px;">No custom heuristic rules triggered</div>`;

  const reasonsList = (report.score_breakdown || []).map(r => `<span class="badge" style="background:var(--bg-surface); border:1px solid var(--border-color); font-size:11px;">${r}</span>`).join(' ');

  resultBox.innerHTML = `
    <div style="background: ${bannerBg}; border: 1px solid ${bannerBorder}; border-radius: var(--radius-md); padding: 20px;">
      <!-- Verdict Top Bar -->
      <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
        <div style="display: flex; align-items: center; gap: 12px;">
          ${verdictBadge}
          <span style="font-family: var(--font-mono); font-size: 16px; font-weight: 700; color: var(--text-main);">${report.domain}</span>
          ${d.is_whitelisted ? '<span class="badge badge-safe"><i class="fa-solid fa-shield"></i> Whitelist Immune</span>' : ''}
        </div>
        <div style="display: flex; align-items: center; gap: 12px;">
          <div style="text-align: right;">
            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Composite Threat Score</div>
            <div style="font-size: 18px; font-weight: 800; font-family: var(--font-mono); color: ${themeColor};">${score} / 100</div>
          </div>
          <div style="width: 120px; height: 8px; background: rgba(255,255,255,0.1); border-radius: var(--radius-pill); overflow: hidden;">
            <div style="width: ${score}%; height: 100%; background: ${themeColor}; transition: width 0.4s ease;"></div>
          </div>
        </div>
      </div>

      <div style="font-size: 13px; color: var(--text-main); margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
        <i class="fa-solid fa-circle-info" style="color: ${themeColor};"></i>
        <strong>Action Recommendation:</strong> <span>${report.recommendation}</span>
      </div>

      <div style="display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 18px;">
        ${reasonsList}
      </div>

      <!-- 6-Layer Diagnostic Matrix -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-bottom: 18px;">
        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-skull-crossbones" style="color: var(--brand-danger);"></i> Threat Feed &amp; Blacklist
          </div>
          <div style="font-size: 12.5px;">${feedMatch}</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-chart-simple" style="color: var(--brand-info);"></i> Shannon Entropy &amp; DGA Model
          </div>
          <div style="font-size: 12.5px; display: flex; align-items: center; justify-content: space-between;">
            <span>SLD Entropy: ${entropyBadge}</span>
            <span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">Consonants: ${lexical.max_consonant_cluster || 0}</span>
          </div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-user-secret" style="color: var(--brand-warning);"></i> Brand Typosquatting / Impersonation
          </div>
          <div style="font-size: 12.5px;">${brandText}</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-network-wired" style="color: var(--brand-primary);"></i> DNS Tunneling &amp; Exfiltration
          </div>
          <div style="font-size: 12.5px;">${tunnelingText}</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-tower-broadcast" style="color: #a855f7;"></i> Public Live DNS Resolution
          </div>
          <div style="font-size: 12.5px;">${dnsText}</div>
        </div>

        <div style="background: var(--bg-surface); border: 1px solid var(--border-color); border-radius: var(--radius-sm); padding: 12px;">
          <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-bottom: 4px;">
            <i class="fa-solid fa-filter" style="color: var(--brand-warning);"></i> Configured Rules Triggered (${rulesHit.length})
          </div>
          ${rulesListHtml}
        </div>
      </div>

      <!-- Quick Action Toolbar -->
      <div style="display: flex; gap: 8px; flex-wrap: wrap; justify-content: flex-end; padding-top: 12px; border-top: 1px solid ${bannerBorder};">
        <button class="btn btn-sm btn-danger" onclick="sandboxActionBlock('${report.domain}', this)">
          <i class="fa-solid fa-ban"></i> Enforce Manual Block
        </button>
        <button class="btn btn-sm btn-outline" onclick="sandboxActionAddThreat('${report.domain}', '${report.severity || 'HIGH'}')">
          <i class="fa-solid fa-plus"></i> Add to Blacklist
        </button>
        <button class="btn btn-sm btn-outline" onclick="sandboxActionAddWhitelist('${report.domain}')">
          <i class="fa-solid fa-shield"></i> Add to Whitelist
        </button>
      </div>
    </div>
  `;
}

async function sandboxActionBlock(domain, btn) {
  const targetBtn = btn || (window.event && window.event.currentTarget) || document.querySelector('button[onclick*="sandboxActionBlock"]');
  if (typeof executeDomainBlock === 'function') {
    await executeDomainBlock(targetBtn, domain, {
      reason: 'Manually blocked from Sandbox Analyzer',
      onSuccess: () => {
        setTimeout(runSandboxEvaluation, 600);
      }
    });
  } else {
    try {
      const res = await fetch('/api/blocking/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, reason: 'Manually blocked from Sandbox Analyzer' })
      });
      const data = await res.json();
      if (data.success) {
        showToast(`Domain '${domain}' is now blocked in Tier-0 Sinkhole!`, 'success');
        runSandboxEvaluation();
      } else {
        showToast('Error: ' + data.message, 'danger');
      }
    } catch (err) {
      console.error('Error enforcing block:', err);
    }
  }
}

function sandboxActionAddThreat(domain, sev) {
  openAddDomainModal();
  document.getElementById('input-domain-name').value = domain;
  document.getElementById('input-domain-sev').value = sev || 'HIGH';
}

async function sandboxActionAddWhitelist(domain) {
  try {
    const res = await fetch('/api/threats/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: domain, reason: 'Approved in Sandbox Testing' })
    });
    const data = await res.json();
    if (data.success) {
      showToast(`Domain '${domain}' added to whitelist with immunity!`, 'success');
      runSandboxEvaluation();
    } else {
      showToast('Whitelist error: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error adding to whitelist:', err);
  }
}

// --------------------------------------------------------------------------
// 4. Batch Sandbox Stress Testing
// --------------------------------------------------------------------------
function clearBatchInput() {
  document.getElementById('sandbox-batch-input').value = '';
  document.getElementById('sandbox-batch-result-box').style.display = 'none';
}

async function runBatchSandboxEvaluation() {
  const input = document.getElementById('sandbox-batch-input').value.trim();
  const box = document.getElementById('sandbox-batch-result-box');
  const btn = document.getElementById('btn-run-batch');
  if (!input) {
    showToast('Please enter domains for batch analysis', 'warning');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Processing Batch...`;
  box.style.display = 'block';
  box.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-muted);"><i class="fa-solid fa-circle-notch fa-spin"></i> Running batch heuristics and live DNS resolution...</div>`;

  try {
    const res = await fetch('/api/threats/sandbox/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domains: input })
    });
    const data = await res.json();
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-play"></i> Evaluate Batch List`;

    if (!data.success) {
      box.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
      return;
    }

    box.innerHTML = `
      <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: 16px;">
        <div style="display: flex; gap: 16px; margin-bottom: 14px; flex-wrap: wrap;">
          <div style="font-size: 13px;"><strong>Total:</strong> ${data.total} domains</div>
          <div style="font-size: 13px; color: #34d399;"><i class="fa-solid fa-check"></i> <strong>Clean:</strong> ${data.clean_count}</div>
          <div style="font-size: 13px; color: #fbbf24;"><i class="fa-solid fa-triangle-exclamation"></i> <strong>Suspicious:</strong> ${data.suspicious_count}</div>
          <div style="font-size: 13px; color: #f87171;"><i class="fa-solid fa-ban"></i> <strong>Blocked:</strong> ${data.blocked_count}</div>
        </div>

        <div class="table-responsive">
          <table class="custom-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Primary Indicator</th>
                <th>Live DNS</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              ${data.results.map(r => {
                const badge = r.verdict === 'BLOCKED' 
                  ? `<span class="badge badge-blocked">BLOCKED</span>` 
                  : (r.verdict === 'SUSPICIOUS' ? `<span class="badge badge-suspicious">SUSPICIOUS</span>` : `<span class="badge badge-safe">SAFE</span>`);
                
                const dns = r.dns_resolved ? `<span style="color:#34d399;">Resolved</span>` : `<span style="color:#f87171;">NXDOMAIN</span>`;

                return `
                  <tr>
                    <td style="font-family: var(--font-mono); font-weight:600;">${r.domain}</td>
                    <td>${badge}</td>
                    <td style="font-family: var(--font-mono); font-weight:700;">${r.threat_score}</td>
                    <td style="font-size: 12px; color: var(--text-muted);">${r.primary_reason}</td>
                    <td style="font-size: 12px;">${dns}</td>
                    <td>
                      <div style="display: flex; gap: 4px; align-items: center;">
                        <button class="btn btn-sm btn-outline" style="padding: 2px 8px; font-size: 11px;" onclick="loadPreset('${r.domain}'); switchSandboxTab('single');">
                          Inspect
                        </button>
                        ${r.verdict !== 'BLOCKED' ? `
                        <button class="btn btn-sm btn-danger" style="padding: 2px 8px; font-size: 11px;" onclick="executeDomainBlock(this, '${r.domain}', { reason: 'Batch Sandbox Detection (${r.verdict})' })">
                          <i class="fa-solid fa-ban"></i> Block
                        </button>` : ''}
                      </div>
                    </td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-play"></i> Evaluate Batch List`;
    console.error('Batch evaluation error:', err);
    box.innerHTML = `<div class="alert alert-danger">Batch evaluation failed.</div>`;
  }
}

// --------------------------------------------------------------------------
// 5. Section 1: Malicious Domain Feed (Table & Collapse Toggle)
// --------------------------------------------------------------------------
function toggleMaliciousFeedCollapse(forceShow = null) {
  const container = document.getElementById('malicious-feed-table-container');
  const collapsedBar = document.getElementById('malicious-feed-collapsed-bar');
  const btn = document.getElementById('btn-toggle-malicious-feed');
  const icon = document.getElementById('icon-toggle-malicious-feed');
  const text = document.getElementById('text-toggle-malicious-feed');
  if (!container) return;

  const isCurrentlyHidden = container.style.display === 'none';
  const shouldShow = (forceShow !== null) ? forceShow : isCurrentlyHidden;

  if (shouldShow) {
    // Show table
    container.style.display = 'block';
    if (collapsedBar) collapsedBar.style.display = 'none';
    if (icon) icon.className = 'fa-solid fa-eye-slash';
    if (text) text.textContent = 'Hide List';
    if (btn) btn.className = 'btn btn-sm btn-outline';
    localStorage.setItem('dnswatch_malicious_feed_collapsed', 'false');
  } else {
    // Hide table
    container.style.display = 'none';
    if (collapsedBar) collapsedBar.style.display = 'flex';
    if (icon) icon.className = 'fa-solid fa-eye';
    if (text) text.textContent = 'Show List';
    if (btn) btn.className = 'btn btn-sm btn-primary';
    localStorage.setItem('dnswatch_malicious_feed_collapsed', 'true');
  }
}

function debounceMaliciousSearch() {
  clearTimeout(maliciousSearchTimeout);
  maliciousSearchTimeout = setTimeout(() => {
    // Automatically reveal table if user searches
    const searchVal = document.getElementById('malicious-search-input').value.trim();
    if (searchVal) {
      toggleMaliciousFeedCollapse(true);
    }
    loadMaliciousDomains();
  }, 300);
}

async function loadMaliciousDomains() {
  const search = document.getElementById('malicious-search-input').value.trim();
  const source = document.getElementById('malicious-source-filter').value;
  const url = new URL('/api/threats/domains', window.location.origin);
  if (search) url.searchParams.set('search', search);
  if (source && source !== 'ALL') url.searchParams.set('source', source);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('malicious-domains-tbody');

    if (data.success && data.domains) {
      const totalCount = data.total_count || data.domains.length;
      const countBadge = document.getElementById('malicious-domains-count-badge');
      if (countBadge) countBadge.textContent = `${totalCount.toLocaleString()} Domains`;
      const counterBar = document.getElementById('collapsed-domains-counter');
      if (counterBar) counterBar.textContent = `${totalCount.toLocaleString()} domains`;

      if (data.domains.length > 0) {
        cachedDomains = data.domains;
        tbody.innerHTML = data.domains.map(d => {
          const statusBadge = (d.status || '').toLowerCase() === 'active' 
            ? `<span class="badge badge-safe" style="cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Inactive')"><i class="fa-solid fa-check"></i> Active</span>`
            : `<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-light); cursor: pointer;" onclick="toggleDomainStatus(${d.id}, 'Active')">Inactive</span>`;

        return `
          <tr data-domain="${d.domain}">
            <td style="font-weight: 600; font-family: var(--font-mono); color: #f87171;">
              <span style="cursor: pointer;" onclick="copyToClipboard('${d.domain}', 'Domain')">${d.domain}</span>
            </td>
            <td><span style="background: var(--bg-surface-elevated); border: 1px solid var(--border-color); padding: 2px 8px; border-radius: var(--radius-xs); font-size: 11px;">${d.category}</span></td>
            <td><span style="background: rgba(139, 92, 246, 0.1); color: #a78bfa; border: 1px solid rgba(139, 92, 246, 0.2); padding: 2px 8px; border-radius: var(--radius-xs); font-size: 11px;">${d.feed_source || 'Manual'}</span></td>
            <td style="color: var(--text-muted); font-size: 11.5px; font-family: var(--font-mono);">${d.added_at || d.created_at}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${d.added_by || 'admin'}</td>
            <td>${statusBadge}</td>
            <td>
              <div style="display: flex; gap: 4px; align-items: center;">
                <button class="btn-icon" onclick="loadPreset('${d.domain}')" title="Test in Sandbox"><i class="fa-solid fa-flask"></i></button>
                <button class="btn-icon" onclick="deleteMaliciousDomain(${d.id}, '${d.domain}')" title="Delete Threat Domain"><i class="fa-regular fa-trash-can"></i></button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 35px;">
            No malicious domains found. Click <strong>Sync Live Feeds Now</strong> or <strong>+ Add Threat Domain</strong> to populate.
          </td>
        </tr>
      `;
      }
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
  const feed_source = document.getElementById('input-domain-feed-source').value.trim() || 'Manual';
  const description = document.getElementById('input-domain-desc').value.trim();

  try {
    const res = await fetch('/api/threats/domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, category, severity, feed_source, description, status: 'Active' })
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-add-domain');
      loadMaliciousDomains();
      loadThreatSummary();
      showToast(`Domain '${domain}' added to threat feed`, 'success');
    } else {
      showToast('Error: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error adding domain:', err);
    showToast('Failed to add threat domain', 'danger');
  }
}

function openBulkImportModal() {
  document.getElementById('form-bulk-import').reset();
  openModal('modal-bulk-import');
}

async function submitBulkImport(e) {
  e.preventDefault();
  const btn = document.getElementById('btn-submit-bulk');
  const text_data = document.getElementById('input-bulk-domains').value;
  const category = document.getElementById('input-bulk-cat').value;
  const severity = document.getElementById('input-bulk-sev').value;

  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Ingesting...`;

  try {
    const res = await fetch('/api/threats/domains/bulk-import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text_data, category, severity, feed_source: 'Bulk Import' })
    });
    const data = await res.json();
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-upload"></i> Ingest Domains`;

    if (data.success) {
      closeModal('modal-bulk-import');
      loadMaliciousDomains();
      loadThreatSummary();
      showToast(data.message, 'success');
    } else {
      showToast('Import error: ' + data.message, 'danger');
    }
  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-upload"></i> Ingest Domains`;
    console.error('Bulk import error:', err);
    showToast('Bulk import failed', 'danger');
  }
}

function exportThreatFeedCSV() {
  window.location.href = '/api/threats/domains/export';
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
  if (!confirm(`Are you sure you want to remove '${domain}' from the threat feed?`)) return;
  try {
    const res = await fetch(`/api/threats/domains/${id}`, { method: 'DELETE' });
    const data = await res.json();
    if (data.success) {
      loadMaliciousDomains();
      loadThreatSummary();
      showToast(`Removed '${domain}' from threat blacklist`, 'warning');
    }
  } catch (err) {
    console.error('Error deleting domain:', err);
  }
}

// --------------------------------------------------------------------------
// 6. Section 2: Domain Heuristic Rules
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
            No domain detection rules configured. Click <strong>+ Add Heuristic Rule</strong> to create one.
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
// 7. Section 3: DNS Query Burst Rate Limiter
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
