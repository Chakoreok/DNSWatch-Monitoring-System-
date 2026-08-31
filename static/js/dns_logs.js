// ==========================================================================
// DNSWatch DNS / Network Logs JavaScript Controller
// ==========================================================================

let currentPage = 1;
const perPage = 10;
let searchTimeout = null;

document.addEventListener('DOMContentLoaded', () => {
  fetchLogs(1);
  
  // Auto-refresh when on page 1 and no search query
  setInterval(() => {
    const search = document.getElementById('logs-search-input').value.trim();
    if (currentPage === 1 && !search && globalMonitoringActive) {
      fetchLogs(1, true);
    }
  }, 2000);

  document.addEventListener('monitoringStateChanged', () => {
    fetchLogs(currentPage, true);
  });
});

function debounceLogsSearch() {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    fetchLogs(1);
  }, 350);
}

async function fetchLogs(page = 1, isBackground = false) {
  currentPage = page;
  const search = document.getElementById('logs-search-input').value.trim();
  const status = document.getElementById('logs-status-filter').value;
  const qtype = document.getElementById('logs-qtype-filter').value;
  const dateVal = document.getElementById('logs-date-filter').value;

  const url = new URL('/api/dns/logs', window.location.origin);
  url.searchParams.set('page', page);
  url.searchParams.set('per_page', perPage);
  if (search) url.searchParams.set('search', search);
  if (status && status !== 'ALL') url.searchParams.set('status', status);
  if (qtype && qtype !== 'ALL') url.searchParams.set('query_type', qtype);
  if (dateVal) url.searchParams.set('date', dateVal);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('logs-tbody');

    if (data.success && data.logs && data.logs.length > 0) {
      tbody.innerHTML = data.logs.map(log => {
        const timeStr = log.time_only || (log.timestamp ? log.timestamp.split(' ')[1] : '-');
        const domain = log.domain || log.query_domain;
        const iconHtml = getDomainIcon(domain);
        const badgeHtml = getStatusBadge(log.status);
        const respIp = log.response_ip && log.response_ip !== '-' ? log.response_ip : '-';
        const infoStr = log.info || log.detection_reason || 'Standard query';

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap;">${timeStr}</td>
            <td style="font-family: monospace; font-size: 12px; font-weight: 500;">${log.client_ip || 'Unknown'}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${iconHtml}</span>
                <span style="font-weight: 500;">${domain}</span>
              </div>
            </td>
            <td><span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600;">${log.query_type || 'A'}</span></td>
            <td style="font-family: monospace; font-size: 12px; color: ${respIp !== '-' ? 'var(--text-main)' : 'var(--text-light)'};">${respIp}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${log.ttl || 300}</td>
            <td>${badgeHtml}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${infoStr}</td>
          </tr>
        `;
      }).join('');

      renderPagination(data.pagination);
    } else {
      const msg = globalMonitoringActive ?
        'Waiting for DNS requests... No log entries match current filter.' :
        'Monitoring is currently Inactive. Existing logs remain saved. Click <strong>Start Monitoring</strong> to capture live traffic.';
        
      tbody.innerHTML = `
        <tr>
          <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 35px;">
            ${msg}
          </td>
        </tr>
      `;
      document.getElementById('logs-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('logs-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    if (!isBackground) console.error('Error fetching DNS logs:', err);
  }
}

function renderPagination(p) {
  const start = (p.page - 1) * p.per_page + 1;
  const end = Math.min(p.page * p.per_page, p.total);
  document.getElementById('logs-pagination-info').textContent = `Showing ${start} to ${end} of ${p.total.toLocaleString()} entries`;

  const container = document.getElementById('logs-pagination-controls');
  let html = '';

  html += `<button class="page-btn" ${p.page <= 1 ? 'disabled' : ''} onclick="fetchLogs(${p.page - 1})"><i class="fa-solid fa-chevron-left"></i></button>`;

  const totalPages = p.pages || 1;
  let startPage = Math.max(1, p.page - 2);
  let endPage = Math.min(totalPages, startPage + 4);
  if (endPage - startPage < 4) {
    startPage = Math.max(1, endPage - 4);
  }

  for (let i = startPage; i <= endPage; i++) {
    html += `<button class="page-btn ${i === p.page ? 'active' : ''}" onclick="fetchLogs(${i})">${i}</button>`;
  }

  html += `<button class="page-btn" ${p.page >= totalPages ? 'disabled' : ''} onclick="fetchLogs(${p.page + 1})"><i class="fa-solid fa-chevron-right"></i></button>`;

  container.innerHTML = html;
}

function refreshLogs() {
  fetchLogs(currentPage);
}
