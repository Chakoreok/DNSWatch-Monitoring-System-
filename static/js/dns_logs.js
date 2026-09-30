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

  const refreshIcon = document.querySelector('.toolbar-right button i.fa-rotate-right');
  if (refreshIcon && !isBackground) refreshIcon.classList.add('fa-spin');

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
        const qtypeBadge = typeof getQueryTypeBadge === 'function' ? getQueryTypeBadge(log.query_type) : `<span class="qtype-badge qtype-A">${log.query_type || 'A'}</span>`;
        const respIp = log.response_ip && log.response_ip !== '-' ? log.response_ip : '-';
        const clientIp = log.client_ip || 'Unknown';
        const infoStr = log.info || log.detection_reason || 'Normal resolution';
        const actionHtml = typeof renderActionCell === 'function' ? 
          renderActionCell(domain, log.client_ip, infoStr, log.status) : '-';

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap; font-family: var(--font-mono);">${timeStr}</td>
            <td>
              <span class="ip-chip" onclick="copyToClipboard('${clientIp}', 'Client IP')" title="Click to copy IP">
                ${clientIp} <i class="fa-regular fa-copy"></i>
              </span>
            </td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${iconHtml}</span>
                <span style="font-weight: 600; cursor: pointer;" onclick="copyToClipboard('${domain}', 'Domain')" title="Click to copy">${domain}</span>
              </div>
            </td>
            <td>${qtypeBadge}</td>
            <td>
              ${respIp !== '-' ? `
                <span class="ip-chip" onclick="copyToClipboard('${respIp}', 'Response IP')" title="Click to copy IP">
                  ${respIp} <i class="fa-regular fa-copy"></i>
                </span>
              ` : '<span style="color: var(--text-light); font-family: var(--font-mono);">-</span>'}
            </td>
            <td style="color: var(--text-muted); font-size: 11.5px; font-family: var(--font-mono);">${log.ttl || 300}s</td>
            <td>${badgeHtml}</td>
            <td style="color: var(--text-muted); font-size: 12px; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${infoStr}">${infoStr}</td>
            <td style="white-space: nowrap;">${actionHtml}</td>
          </tr>
        `;
      }).join('');

      renderPagination(data.pagination);
    } else {
      const msg = globalMonitoringActive ?
        'Waiting for DNS requests... No log entries match current filter.' :
        'Monitoring is currently Inactive. Existing logs remain saved. Click <strong>Start Sniffer</strong> to capture live traffic.';
        
      tbody.innerHTML = `
        <tr>
          <td colspan="9" style="text-align: center; color: var(--text-muted); padding: 40px;">
            <i class="fa-solid fa-database" style="font-size: 24px; margin-bottom: 8px; color: var(--text-light);"></i>
            <div>${msg}</div>
          </td>
        </tr>
      `;
      document.getElementById('logs-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('logs-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    if (!isBackground) console.error('Error fetching DNS logs:', err);
  } finally {
    if (refreshIcon) refreshIcon.classList.remove('fa-spin');
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
