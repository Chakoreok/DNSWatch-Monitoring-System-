// ==========================================================================
// DNSWatch Reports & Analytics Controller
// ==========================================================================

let queriesChart = null;
let statusDonutChart = null;
let lastChartData = null;

document.addEventListener('DOMContentLoaded', () => {
  // Set default dates (past 7 days)
  const today = new Date();
  const prior = new Date(today);
  prior.setDate(prior.getDate() - 6);

  const formatIsoDate = (d) => {
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  const fromEl = document.getElementById('rep-date-from');
  const toEl = document.getElementById('rep-date-to');
  if (fromEl) fromEl.value = formatIsoDate(prior);
  if (toEl) toEl.value = formatIsoDate(today);

  populateDeviceFilter();
  fetchReports();

  // Re-render charts when theme changes
  document.addEventListener('themeChanged', () => {
    if (lastChartData) {
      renderQueriesChart(lastChartData.labels, lastChartData.queries_over_time);
      renderStatusDonutChart(lastChartData.status_distribution);
    }
  });
});

async function populateDeviceFilter() {
  try {
    const res = await fetch('/api/devices');
    const data = await res.json();
    if (data.success && data.devices) {
      const select = document.getElementById('rep-device-filter');
      if (!select) return;
      const currentVal = select.value;
      
      let html = '<option value="ALL">All Connected Devices</option>';
      data.devices.forEach(dev => {
        const ip = dev.ip_address || dev.client_ip;
        const name = dev.device_name || ip;
        html += `<option value="${ip}">${name} (${ip})</option>`;
      });
      select.innerHTML = html;
      select.value = currentVal || 'ALL';
    }
  } catch (err) {
    console.error('Error loading devices for report filter:', err);
  }
}

async function fetchReports() {
  const dateFrom = document.getElementById('rep-date-from')?.value;
  const dateTo = document.getElementById('rep-date-to')?.value;
  const device = document.getElementById('rep-device-filter')?.value;
  const status = document.getElementById('rep-status-filter')?.value;

  const url = new URL('/api/reports/summary', window.location.origin);
  if (dateFrom) url.searchParams.set('date_from', dateFrom);
  if (dateTo) url.searchParams.set('date_to', dateTo);
  if (device && device !== 'ALL') url.searchParams.set('device', device);
  if (status && status !== 'ALL') url.searchParams.set('status', status);

  // Update CSV Export link with current filters
  const exportUrl = new URL('/api/reports/export', window.location.origin);
  if (dateFrom) exportUrl.searchParams.set('date_from', dateFrom);
  if (dateTo) exportUrl.searchParams.set('date_to', dateTo);
  if (device && device !== 'ALL') exportUrl.searchParams.set('device', device);
  if (status && status !== 'ALL') exportUrl.searchParams.set('status', status);
  const exportBtn = document.getElementById('btn-export-csv');
  if (exportBtn) exportBtn.href = exportUrl.toString();

  try {
    const res = await fetch(url);
    const data = await res.json();

    if (data.success) {
      lastChartData = {
        labels: data.charts.labels,
        queries_over_time: data.charts.queries_over_time,
        status_distribution: data.charts.status_distribution
      };

      renderSummaryCards(data.summary);
      renderQueriesChart(data.charts.labels, data.charts.queries_over_time);
      renderStatusDonutChart(data.charts.status_distribution);
      renderTopDomainsTable(data.top_domains);
      renderTopDevicesTable(data.top_devices);
      renderAlertsSummaryTable(data.alerts_summary);
    }
  } catch (err) {
    console.error('Error fetching reports data:', err);
  }
}

function renderSummaryCards(s) {
  const total = s.total_queries || 0;
  const safe = s.safe_requests || 0;
  const susp = s.suspicious_requests || 0;
  const blk = s.blocked_requests || 0;

  const totalEl = document.getElementById('rep-cnt-total');
  const safeEl = document.getElementById('rep-cnt-safe');
  const suspEl = document.getElementById('rep-cnt-suspicious');
  const blkEl = document.getElementById('rep-cnt-blocked');
  const devEl = document.getElementById('rep-cnt-devices');

  if (totalEl) totalEl.textContent = total.toLocaleString();
  if (safeEl) safeEl.textContent = safe.toLocaleString();
  if (suspEl) suspEl.textContent = susp.toLocaleString();
  if (blkEl) blkEl.textContent = blk.toLocaleString();
  if (devEl) devEl.textContent = (s.active_devices || 0).toLocaleString();

  const safePct = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;
  const suspPct = total > 0 ? ((susp / total) * 100).toFixed(1) : 0;
  const blkPct = total > 0 ? ((blk / total) * 100).toFixed(1) : 0;

  const pSafe = document.getElementById('rep-pct-safe');
  const pSusp = document.getElementById('rep-pct-suspicious');
  const pBlk = document.getElementById('rep-pct-blocked');

  if (pSafe) pSafe.textContent = `${safePct}% of total`;
  if (pSusp) pSusp.textContent = `${suspPct}% of total`;
  if (pBlk) pBlk.textContent = `${blkPct}% of total`;
}

function renderQueriesChart(labels, values) {
  const canvas = document.getElementById('chart-queries-time');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (queriesChart) queriesChart.destroy();

  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const gridColor = isDark ? 'rgba(255, 255, 255, 0.06)' : 'rgba(0, 0, 0, 0.06)';
  const textColor = isDark ? '#94a3b8' : '#64748b';

  // Create gradient
  const gradient = ctx.createLinearGradient(0, 0, 0, 240);
  gradient.addColorStop(0, 'rgba(59, 130, 246, 0.28)');
  gradient.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

  queriesChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'DNS Queries',
        data: values,
        borderColor: '#3b82f6',
        backgroundColor: gradient,
        fill: true,
        tension: 0.38,
        borderWidth: 2.5,
        pointBackgroundColor: '#3b82f6',
        pointBorderColor: isDark ? '#0f172a' : '#ffffff',
        pointBorderWidth: 2,
        pointRadius: 4,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: isDark ? '#1e293b' : '#0f172a',
          titleColor: '#ffffff',
          bodyColor: '#e2e8f0',
          borderColor: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
          borderWidth: 1,
          padding: 10,
          displayColors: false,
          callbacks: {
            label: (ctx) => ` DNS Queries: ${ctx.parsed.y}`
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1,
            precision: 0,
            font: { size: 11, family: 'JetBrains Mono' },
            color: textColor
          },
          grid: { color: gridColor }
        },
        x: {
          grid: { display: false },
          ticks: { font: { size: 11 }, color: textColor }
        }
      }
    }
  });
}

function renderStatusDonutChart(dist) {
  const canvas = document.getElementById('chart-status-donut');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (statusDonutChart) statusDonutChart.destroy();

  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const textColor = isDark ? '#f1f5f9' : '#0f172a';
  const borderColor = isDark ? '#0f172a' : '#ffffff';

  const safe = dist.safe || 0;
  const susp = dist.suspicious || 0;
  const blk = dist.blocked || 0;
  const hasData = (safe + susp + blk) > 0;

  statusDonutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe Traffic', 'Suspicious', 'Blocked Threats'],
      datasets: [{
        data: hasData ? [safe, susp, blk] : [1, 0, 0],
        backgroundColor: hasData ? ['#10B981', '#F59E0B', '#EF4444'] : ['#334155', '#334155', '#334155'],
        borderWidth: 3,
        borderColor: borderColor
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '72%',
      plugins: {
        legend: {
          position: 'right',
          labels: {
            font: { size: 11.5, family: 'Plus Jakarta Sans', weight: '600' },
            boxWidth: 12,
            color: textColor,
            padding: 12
          }
        },
        tooltip: {
          backgroundColor: isDark ? '#1e293b' : '#0f172a',
          titleColor: '#ffffff',
          bodyColor: '#e2e8f0',
          borderColor: isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)',
          borderWidth: 1,
          padding: 10
        }
      }
    }
  });
}

function renderTopDomainsTable(domains) {
  const tbody = document.getElementById('rep-top-domains-tbody');
  if (!tbody) return;
  if (!domains || domains.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 25px;">No domain traffic recorded</td></tr>';
    return;
  }
  tbody.innerHTML = domains.map(d => `
    <tr>
      <td>
        <div class="domain-cell">
          <span class="domain-icon">${getDomainIcon(d.domain)}</span>
          <span style="font-weight: 600; cursor: pointer;" onclick="copyToClipboard('${d.domain}', 'Domain')" title="Click to copy">${d.domain}</span>
        </div>
      </td>
      <td style="text-align: right; font-weight: 700; font-family: var(--font-mono);">${d.queries.toLocaleString()}</td>
    </tr>
  `).join('');
}

function renderTopDevicesTable(devices) {
  const tbody = document.getElementById('rep-top-devices-tbody');
  if (!tbody) return;
  if (!devices || devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 25px;">No client device activity</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map(dev => `
    <tr>
      <td style="font-weight: 600; color: var(--text-main);">${dev.device_name}</td>
      <td>
        <span class="ip-chip" onclick="copyToClipboard('${dev.ip_address}', 'Client IP')" title="Click to copy IP">
          ${dev.ip_address} <i class="fa-regular fa-copy"></i>
        </span>
      </td>
      <td style="text-align: right; font-weight: 700; font-family: var(--font-mono);">${dev.queries.toLocaleString()}</td>
    </tr>
  `).join('');
}

function renderAlertsSummaryTable(alerts) {
  const tbody = document.getElementById('rep-alerts-summary-tbody');
  if (!tbody) return;
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 25px;">Zero security incidents logged</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a => {
    const sev = (a.severity || 'HIGH').toUpperCase();
    let sevBadge = '<span class="badge-high">HIGH</span>';
    if (sev === 'MEDIUM') sevBadge = '<span class="badge-medium">MEDIUM</span>';
    else if (sev === 'LOW') sevBadge = '<span class="badge-low">LOW</span>';

    return `
      <tr>
        <td>${sevBadge}</td>
        <td style="font-weight: 700; font-family: var(--font-mono);">${a.alerts}</td>
        <td style="text-align: right; color: var(--text-muted); font-size: 11.5px; font-weight: 600;">${a.trend}</td>
      </tr>
    `;
  }).join('');
}
