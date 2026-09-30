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
  document.addEventListener('monitoringStateChanged', () => {
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

  const refreshIcon = document.querySelector('.toolbar-right button i.fa-rotate-right');
  if (refreshIcon && !isBackground) refreshIcon.classList.add('fa-spin');

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('web-activity-tbody');

    if (data.success && data.activities && data.activities.length > 0) {
      tbody.innerHTML = data.activities.map(act => {
        const timeStr = act.time || (act.timestamp ? act.timestamp.split(' ')[1] : '-');
        const iconHtml = getDomainIcon(act.domain);
        const badgeHtml = getStatusBadge(act.status);
        
        let typeIcon = '<i class="fa-solid fa-desktop" style="color:#60a5fa"></i> Workstation';
        const dtype = (act.device_type || '').toLowerCase();
        if (dtype.includes('android') || dtype.includes('mobile')) {
          typeIcon = '<i class="fa-brands fa-android" style="color:#34d399"></i> Android';
        } else if (dtype.includes('apple') || dtype.includes('ios') || dtype.includes('mac')) {
          typeIcon = '<i class="fa-brands fa-apple" style="color:#cbd5e1"></i> Apple';
        } else if (dtype.includes('windows')) {
          typeIcon = '<i class="fa-brands fa-windows" style="color:#38bdf8"></i> Windows';
        } else {
          typeIcon = '<i class="fa-solid fa-network-wired" style="color:var(--text-light)"></i> ' + (act.device_type || 'Host');
        }

        const clientIp = act.client_ip || 'Unknown';
        const actionHtml = typeof renderActionCell === 'function' ? 
          renderActionCell(act.domain, clientIp, '', act.status) : '-';

        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap; font-family: var(--font-mono);">${timeStr}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${iconHtml}</span>
                <span style="font-weight: 600; cursor: pointer;" onclick="copyToClipboard('${act.domain}', 'Domain')" title="Click to copy">${act.domain}</span>
              </div>
            </td>
            <td style="font-weight: 600; color: var(--text-main);">${act.device_name}</td>
            <td>
              <span class="ip-chip" onclick="copyToClipboard('${clientIp}', 'Client IP')" title="Click to copy IP">
                ${clientIp} <i class="fa-regular fa-copy"></i>
              </span>
            </td>
            <td>${typeIcon}</td>
            <td>${badgeHtml}</td>
            <td style="white-space: nowrap;">${actionHtml}</td>
          </tr>
        `;
      }).join('');

      renderWebPagination(data.pagination);
    } else {
      const msg = globalMonitoringActive ? 
        'Waiting for DNS requests... Run DNS queries to see live web destinations.' : 
        'Monitoring is currently Inactive. Existing logs remain saved. Click <strong>Start Sniffer</strong> to capture live network traffic.';
        
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">
            <i class="fa-solid fa-globe" style="font-size: 24px; margin-bottom: 8px; color: var(--text-light);"></i>
            <div>${msg}</div>
          </td>
        </tr>
      `;
      document.getElementById('web-pagination-info').textContent = 'Showing 0 to 0 of 0 entries';
      document.getElementById('web-pagination-controls').innerHTML = '';
    }
  } catch (err) {
    if (!isBackground) console.error('Error fetching website activity:', err);
  } finally {
    if (refreshIcon) refreshIcon.classList.remove('fa-spin');
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
