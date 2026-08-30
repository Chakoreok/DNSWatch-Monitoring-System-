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

async function fetchAlerts(page = 1) {
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

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('alerts-tbody');

    if (data.success && data.alerts && data.alerts.length > 0) {
      cachedAlerts = data.alerts;
      tbody.innerHTML = data.alerts.map(alt => {
        const timeStr = alt.time_only || (alt.timestamp ? alt.timestamp.split(' ')[1] : '-');
        const sevClass = (alt.severity || 'HIGH').toLowerCase() === 'high' ? 'badge-high' : 
                         ((alt.severity || '').toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low');
        
        let statusBadge = '<span class="badge-status-new">New</span>';
        if ((alt.status || '').toLowerCase() === 'acknowledged') {
          statusBadge = '<span class="badge-status-ack">Acknowledged</span>';
        } else if ((alt.status || '').toLowerCase() === 'resolved') {
          statusBadge = '<span class="badge-status-resolved">Resolved</span>';
        }

        const domainHtml = alt.domain ? `<span style="font-weight: 500;">${alt.domain}</span>` : `<span style="font-family: monospace;">${alt.client_ip}</span>`;

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap;">${timeStr}</td>
            <td style="font-weight: 600;">${alt.alert_type}</td>
            <td>${domainHtml}</td>
            <td style="font-family: monospace; font-size: 12px;">${alt.client_ip || 'Unknown'}</td>
            <td><span class="${sevClass}">${alt.severity || 'MEDIUM'}</span></td>
            <td>${statusBadge}</td>
            <td>
              <button class="btn btn-outline btn-sm" onclick="openAlertModal('${alt.id || alt.alert_id}')" title="View Alert Details">
                <i class="fa-regular fa-eye"></i>
              </button>
            </td>
          </tr>
        `;
      }).join('');

      renderAlertsPagination(data.pagination);
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 35px;">
            No security alerts match your criteria.
          </td>
        </tr>
      `;
      document.getElementById('alerts-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('alerts-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    console.error('Error fetching alerts:', err);
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

  const modal = document.getElementById('modal-alert-details');
  document.getElementById('modal-alert-title').textContent = `${alt.alert_type} (${alt.alert_id || 'Alert'})`;

  document.getElementById('modal-alert-body').innerHTML = `
    <div class="system-status-list">
      <div class="status-row">
        <span class="status-row-label">Timestamp</span>
        <span class="status-row-value">${alt.timestamp}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label">Target Domain</span>
        <span class="status-row-value" style="font-family: monospace;">${alt.domain}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label">Client / Source IP</span>
        <span class="status-row-value" style="font-family: monospace;">${alt.client_ip}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label">Severity</span>
        <span class="status-row-value">${alt.severity}</span>
      </div>
      <div class="status-row">
        <span class="status-row-label">Current Status</span>
        <span class="status-row-value">${alt.status}</span>
      </div>
      <div style="margin-top: 12px;">
        <label class="form-label">Description & Detection Cause</label>
        <div style="background: #f8fafc; padding: 12px; border-radius: 6px; border: 1px solid var(--border-color); font-size: 12.5px; color: var(--text-main); line-height: 1.5;">
          ${alt.description}
        </div>
      </div>
    </div>
  `;

  modal.classList.add('show');
}

function closeAlertModal() {
  const modal = document.getElementById('modal-alert-details');
  if (modal) modal.classList.remove('show');
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
    } else {
      alert('Failed to update alert: ' + data.message);
    }
  } catch (err) {
    console.error('Error updating alert status:', err);
  }
}
