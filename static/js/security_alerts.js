// ==========================================================================
// DNSWatch Security Alerts JavaScript Controller
// ==========================================================================

let currentAlertPage = 1;
const alertsPerPage = 10;
let alertsSearchTimeout = null;
let currentSelectedAlert = null;
let cachedAlerts = [];

document.addEventListener('DOMContentLoaded', () => {
  fetchAlertCounts();
  fetchAlerts(1);
  
  // Auto refresh periodically when monitoring is active
  setInterval(() => {
    const search = document.getElementById('alerts-search-input').value.trim();
    if (currentAlertPage === 1 && !search && typeof globalMonitoringActive !== 'undefined' && globalMonitoringActive) {
      fetchAlertCounts();
      fetchAlerts(1, true);
    }
  }, 3000);

  document.addEventListener('monitoringStateChanged', () => {
    fetchAlertCounts();
    fetchAlerts(currentAlertPage, true);
  });
});

function debounceAlertsSearch() {
  clearTimeout(alertsSearchTimeout);
  alertsSearchTimeout = setTimeout(() => {
    fetchAlerts(1);
  }, 350);
}

async function fetchAlertCounts() {
  try {
    const res = await fetch('/api/alerts/counts');
    const data = await res.json();
    if (data.success) {
      document.getElementById('alert-cnt-high').textContent = data.high;
      document.getElementById('alert-cnt-med').textContent = data.medium;
      document.getElementById('alert-cnt-low').textContent = data.low;
      document.getElementById('alert-cnt-total').textContent = data.total;
    }
  } catch (err) {
    console.error('Error fetching alert counts:', err);
  }
}

async function fetchAlerts(page = 1, isBackground = false) {
  currentAlertPage = page;
  const search = document.getElementById('alerts-search-input').value.trim();
  const severity = document.getElementById('alerts-severity-filter').value;
  const status = document.getElementById('alerts-status-filter').value;
  const dateVal = document.getElementById('alerts-date-filter').value;

  const url = new URL('/api/alerts', window.location.origin);
  url.searchParams.set('page', page);
  url.searchParams.set('per_page', alertsPerPage);
  if (search) url.searchParams.set('search', search);
  if (severity && severity !== 'ALL') url.searchParams.set('severity', severity);
  if (status && status !== 'ALL') url.searchParams.set('status', status);
  if (dateVal) url.searchParams.set('date', dateVal);

  const refreshIcon = document.querySelector('.toolbar-right button i.fa-rotate-right');
  if (refreshIcon && !isBackground) refreshIcon.classList.add('fa-spin');

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('alerts-tbody');

    if (data.success && data.alerts && data.alerts.length > 0) {
      cachedAlerts = data.alerts;
      tbody.innerHTML = data.alerts.map(alt => {
        const timeStr = alt.time_only || (alt.timestamp ? alt.timestamp.split(' ')[1] : '-');
        const sev = (alt.severity || 'HIGH').toUpperCase();
        let sevBadge = '<span class="badge-high"><i class="fa-solid fa-triangle-exclamation"></i> HIGH</span>';
        if (sev === 'MEDIUM') {
          sevBadge = '<span class="badge-medium"><i class="fa-solid fa-triangle-exclamation"></i> MEDIUM</span>';
        } else if (sev === 'LOW') {
          sevBadge = '<span class="badge-low"><i class="fa-solid fa-circle-info"></i> LOW</span>';
        }
        
        let statusBadge = '<span class="badge-status-new"><i class="fa-solid fa-circle-exclamation"></i> New</span>';
        if ((alt.status || '').toLowerCase() === 'acknowledged') {
          statusBadge = '<span class="badge-status-ack"><i class="fa-solid fa-clock"></i> Acknowledged</span>';
        } else if ((alt.status || '').toLowerCase() === 'resolved') {
          statusBadge = '<span class="badge-status-resolved"><i class="fa-solid fa-check"></i> Resolved</span>';
        }

        const domainText = alt.domain || alt.client_ip;
        const clientIp = alt.client_ip || 'Unknown';

        return `
          <tr data-domain="${escapeHtml(domainText)}">
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap; font-family: var(--font-mono);">${timeStr}</td>
            <td style="font-weight: 600; color: var(--text-main);">${alt.alert_type}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${getDomainIcon(alt.domain)}</span>
                <span style="font-weight: 600; cursor: pointer;" onclick="copyToClipboard('${domainText}', 'Domain')" title="Click to copy">${domainText}</span>
              </div>
            </td>
            <td>
              <span class="ip-chip" onclick="copyToClipboard('${clientIp}', 'Client IP')" title="Click to copy IP">
                ${clientIp} <i class="fa-regular fa-copy"></i>
              </span>
            </td>
            <td>${sevBadge}</td>
            <td>${statusBadge}</td>
            <td>
              <div style="display: flex; gap: 4px; align-items: center;">
                <button class="btn btn-outline btn-sm" onclick="openAlertModal('${alt.id || alt.alert_id}')" title="Incident Triage Details">
                  <i class="fa-solid fa-magnifying-glass"></i> Triage
                </button>
                ${(typeof isAdmin === 'function' && isAdmin() && alt.domain) ? `
                <button type="button" class="btn btn-outline btn-sm" style="color: var(--brand-danger); border-color: rgba(239,68,68,0.3); font-size: 11px; padding: 3px 8px;" title="Block domain" onclick="executeDomainBlock(this, '${escapeHtml(alt.domain)}', { reason: 'Blocked from Alert: ${escapeHtml(alt.alert_type || 'Suspicious Activity')}' })">
                  <i class="fa-solid fa-ban"></i> Block
                </button>` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');

      renderAlertsPagination(data.pagination);
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">
            <i class="fa-solid fa-shield-check" style="font-size: 24px; color: var(--brand-success); margin-bottom: 8px;"></i>
            <div>No security alerts match your criteria.</div>
          </td>
        </tr>
      `;
      document.getElementById('alerts-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('alerts-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    if (!isBackground) console.error('Error fetching alerts:', err);
  } finally {
    if (refreshIcon) refreshIcon.classList.remove('fa-spin');
  }
}

function renderAlertsPagination(p) {
  const start = (p.page - 1) * p.per_page + 1;
  const end = Math.min(p.page * p.per_page, p.total);
  document.getElementById('alerts-pagination-info').textContent = `Showing ${start} to ${end} of ${p.total.toLocaleString()} entries`;

  const container = document.getElementById('alerts-pagination-controls');
  let html = '';

  html += `<button class="page-btn" ${p.page <= 1 ? 'disabled' : ''} onclick="fetchAlerts(${p.page - 1})"><i class="fa-solid fa-chevron-left"></i></button>`;

  const totalPages = p.pages || 1;
  let startPage = Math.max(1, p.page - 2);
  let endPage = Math.min(totalPages, startPage + 4);
  if (endPage - startPage < 4) {
    startPage = Math.max(1, endPage - 4);
  }

  for (let i = startPage; i <= endPage; i++) {
    html += `<button class="page-btn ${i === p.page ? 'active' : ''}" onclick="fetchAlerts(${i})">${i}</button>`;
  }

  html += `<button class="page-btn" ${p.page >= totalPages ? 'disabled' : ''} onclick="fetchAlerts(${p.page + 1})"><i class="fa-solid fa-chevron-right"></i></button>`;

  container.innerHTML = html;
}

function openAlertModal(alertId) {
  const alt = cachedAlerts.find(a => String(a.id) === String(alertId) || a.alert_id === alertId);
  if (!alt) return;
  currentSelectedAlert = alt;

  document.getElementById('modal-alert-title').innerHTML = `
    <i class="fa-solid fa-triangle-exclamation" style="color: var(--brand-danger);"></i>
    <span>${alt.alert_type} (${alt.alert_id || 'Incident'})</span>
  `;

  document.getElementById('modal-alert-body').innerHTML = `
    <div class="system-status-list">
      <div class="status-row">
        <span class="status-row-label"><i class="fa-regular fa-clock"></i> Timestamp</span>
        <span class="status-row-value">${alt.timestamp}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label"><i class="fa-solid fa-globe"></i> Target Domain</span>
        <span class="status-row-value" style="font-family: var(--font-mono); color: #f87171;">${alt.domain}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label"><i class="fa-solid fa-network-wired"></i> Source Client IP</span>
        <span class="status-row-value" style="font-family: var(--font-mono);">${alt.client_ip}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label"><i class="fa-solid fa-gauge"></i> Severity Level</span>
        <span class="status-row-value">${alt.severity}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label"><i class="fa-solid fa-circle-info"></i> Incident Status</span>
        <span class="status-row-value">${alt.status}</span>
      </div>
      <div style="margin-top: 14px;">
        <label class="form-label">Detection Context &amp; Threat Signature</label>
        <div style="background: var(--bg-surface-elevated); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-color); font-size: 13px; color: var(--text-main); line-height: 1.5;">
          ${alt.description}
        </div>
      </div>
    </div>
  `;

  // Role-gated action buttons in alert detail modal
  const btnDirectBlock = document.getElementById('btn-modal-direct-block');
  const btnRequestBlock = document.getElementById('btn-modal-request-block');
  const hasDomain = alt.domain && alt.domain.trim() !== '' && alt.domain !== alt.client_ip;

  if (btnDirectBlock) {
    btnDirectBlock.style.display = (typeof isAdmin === 'function' && isAdmin() && hasDomain) ? 'inline-flex' : 'none';
  }
  if (btnRequestBlock) {
    btnRequestBlock.style.display = (typeof isAnalyst === 'function' && isAnalyst() && hasDomain) ? 'inline-flex' : 'none';
  }

  openModal('modal-alert-details');
}

function closeAlertModal() {
  closeModal('modal-alert-details');
}

async function openDirectBlockFromAlert(btn) {
  if (!currentSelectedAlert) return;
  const domain = currentSelectedAlert.domain;
  const clientIp = currentSelectedAlert.client_ip;
  const reason = `Blocked from Alert #${currentSelectedAlert.id}: ${currentSelectedAlert.alert_type || 'Malicious DNS Activity'}${clientIp ? ` (Client: ${clientIp})` : ''}`;
  const targetBtn = btn || document.getElementById('btn-modal-direct-block');

  if (typeof executeDomainBlock === 'function') {
    await executeDomainBlock(targetBtn, domain, {
      reason: reason,
      onSuccess: () => {
        setTimeout(() => {
          closeAlertModal();
          if (typeof fetchAlerts === 'function') {
            fetchAlerts(typeof currentAlertPage !== 'undefined' ? currentAlertPage : 1);
          }
        }, 500);
      }
    });
  } else if (typeof openDirectBlockModal === 'function') {
    closeAlertModal();
    openDirectBlockModal(domain, clientIp);
  }
}

function openRequestBlockFromAlert() {
  if (!currentSelectedAlert) return;
  const domain = currentSelectedAlert.domain;
  const clientIp = currentSelectedAlert.client_ip;
  const detInfo = currentSelectedAlert.description || currentSelectedAlert.alert_type;
  closeAlertModal();
  if (typeof openRequestBlockModal === 'function') {
    openRequestBlockModal(domain, clientIp, detInfo);
  }
}

async function updateCurrentAlertStatus(newStatus) {
  if (!currentSelectedAlert) return;
  try {
    const res = await fetch(`/api/alerts/${currentSelectedAlert.id || currentSelectedAlert.alert_id}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    const data = await res.json();
    if (data.success) {
      closeAlertModal();
      fetchAlertCounts();
      fetchAlerts(currentAlertPage);
      showToast(`Incident marked as ${newStatus}`, 'success');
    } else {
      showToast('Failed to update alert: ' + data.message, 'danger');
    }
  } catch (err) {
    console.error('Error updating alert status:', err);
    showToast('Failed to update status', 'danger');
  }
}
