// ==========================================================================
// DNSWatch Website Activity Controller
// ==========================================================================

let currentWebPage = 1;
const webPerPage = 10;
let webSearchTimeout = null;

document.addEventListener('DOMContentLoaded', () => {
  fetchWebsiteActivity(1);
  
  // Auto-refresh periodically if on page 1 and no search query
  setInterval(() => {
    const search = document.getElementById('web-search-input').value.trim();
    if (currentWebPage === 1 && !search && globalMonitoringActive) {
      fetchWebsiteActivity(1, true);
    }
  }, 2000);

  // Listen to global monitoring state transitions
  document.addEventListener('monitoringStateChanged', (e) => {
    fetchWebsiteActivity(currentWebPage, true);
  });
});

function debounceWebSearch() {
  clearTimeout(webSearchTimeout);
  webSearchTimeout = setTimeout(() => {
    fetchWebsiteActivity(1);
  }, 350);
}

async function fetchWebsiteActivity(page = 1, isBackground = false) {
  currentWebPage = page;
  const search = document.getElementById('web-search-input').value.trim();
  const status = document.getElementById('web-status-filter').value;
  const dateVal = document.getElementById('web-date-filter').value;

  const url = new URL('/api/website-activity', window.location.origin);
  url.searchParams.set('page', page);
  url.searchParams.set('per_page', webPerPage);
  if (search) url.searchParams.set('search', search);
  if (status && status !== 'ALL') url.searchParams.set('status', status);
  if (dateVal) url.searchParams.set('date', dateVal);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('web-activity-tbody');

    if (data.success && data.activities && data.activities.length > 0) {
      tbody.innerHTML = data.activities.map(act => {
        const timeStr = act.time || (act.timestamp ? act.timestamp.split(' ')[1] : '-');
        const iconHtml = getDomainIcon(act.domain);
        const badgeHtml = getStatusBadge(act.status);
        
        let typeIcon = '<i class="fa-solid fa-desktop" style="color:#2563EB"></i> Workstation';
        const dtype = (act.device_type || '').toLowerCase();
        if (dtype.includes('android') || dtype.includes('mobile')) {
          typeIcon = '<i class="fa-brands fa-android" style="color:#10B981"></i> Android';
        } else if (dtype.includes('apple') || dtype.includes('ios') || dtype.includes('mac')) {
          typeIcon = '<i class="fa-brands fa-apple" style="color:#64748B"></i> Apple';
        } else if (dtype.includes('windows')) {
          typeIcon = '<i class="fa-brands fa-windows" style="color:#00A4EF"></i> Windows';
        } else {
          typeIcon = '<i class="fa-solid fa-network-wired" style="color:#64748B"></i> ' + (act.device_type || 'Host');
        }

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap;">${timeStr}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${iconHtml}</span>
                <span style="font-weight: 500;">${act.domain}</span>
              </div>
            </td>
            <td style="font-weight: 500;">${act.device_name}</td>
            <td style="font-family: monospace; font-size: 12px;">${act.client_ip}</td>
            <td>${typeIcon}</td>
            <td>${badgeHtml}</td>
          </tr>
        `;
      }).join('');

      renderWebPagination(data.pagination);
    } else {
      const msg = globalMonitoringActive ? 
        'Waiting for DNS requests... Run DNS queries to see live activity.' : 
        'Monitoring is currently Inactive. Existing logs remain saved. Click <strong>Start Monitoring</strong> to capture live network traffic.';
        
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 35px;">
            ${msg}
          </td>
        </tr>
      `;
      document.getElementById('web-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('web-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    if (!isBackground) console.error('Error fetching website activity:', err);
  }
}

function renderWebPagination(p) {
  const start = (p.page - 1) * p.per_page + 1;
  const end = Math.min(p.page * p.per_page, p.total);
  document.getElementById('web-pagination-info').textContent = `Showing ${start} to ${end} of ${p.total.toLocaleString()} entries`;

  const container = document.getElementById('web-pagination-controls');
  let html = '';

  html += `<button class="page-btn" ${p.page <= 1 ? 'disabled' : ''} onclick="fetchWebsiteActivity(${p.page - 1})"><i class="fa-solid fa-chevron-left"></i></button>`;

  const totalPages = p.pages || 1;
  let startPage = Math.max(1, p.page - 2);
  let endPage = Math.min(totalPages, startPage + 4);
  if (endPage - startPage < 4) {
    startPage = Math.max(1, endPage - 4);
  }

  for (let i = startPage; i <= endPage; i++) {
    html += `<button class="page-btn ${i === p.page ? 'active' : ''}" onclick="fetchWebsiteActivity(${i})">${i}</button>`;
  }

  html += `<button class="page-btn" ${p.page >= totalPages ? 'disabled' : ''} onclick="fetchWebsiteActivity(${p.page + 1})"><i class="fa-solid fa-chevron-right"></i></button>`;

  container.innerHTML = html;
}
