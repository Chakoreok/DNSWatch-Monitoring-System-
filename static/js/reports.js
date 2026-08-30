// ==========================================================================
// DNSWatch Reports & Analytics Controller
// ==========================================================================

let queriesChart = null;
let statusDonutChart = null;

document.addEventListener('DOMContentLoaded', () => {
  // Set default dates (today)
  const today = new Date();
  const prior = new Date(today);
  prior.setDate(prior.getDate() - 6);

  const formatIsoDate = (d) => {
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  document.getElementById('rep-date-from').value = formatIsoDate(prior);
  document.getElementById('rep-date-to').value = formatIsoDate(today);

  populateDeviceFilter();
  fetchReports();
});

async function populateDeviceFilter() {
  try {
    const res = await fetch('/api/devices');
    const data = await res.json();
    if (data.success && data.devices) {
      const select = document.getElementById('rep-device-filter');
      const currentVal = select.value;
      
      let html = '<option value="ALL">All Devices</option>';
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
  const dateFrom = document.getElementById('rep-date-from').value;
  const dateTo = document.getElementById('rep-date-to').value;
  const device = document.getElementById('rep-device-filter').value;
  const status = document.getElementById('rep-status-filter').value;

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
  document.getElementById('btn-export-csv').href = exportUrl.toString();

  try {
    const res = await fetch(url);
    const data = await res.json();

    if (data.success) {
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

  document.getElementById('rep-cnt-total').textContent = total.toLocaleString();
  document.getElementById('rep-cnt-safe').textContent = safe.toLocaleString();
  document.getElementById('rep-cnt-suspicious').textContent = susp.toLocaleString();
  document.getElementById('rep-cnt-blocked').textContent = blk.toLocaleString();
  document.getElementById('rep-cnt-devices').textContent = s.active_devices || 0;

  const safePct = total > 0 ? ((safe / total) * 100).toFixed(1) : 100;
  const suspPct = total > 0 ? ((susp / total) * 100).toFixed(1) : 0;
  const blkPct = total > 0 ? ((blk / total) * 100).toFixed(1) : 0;

  document.getElementById('rep-pct-safe').textContent = `${safePct}% of total`;
  document.getElementById('rep-pct-suspicious').textContent = `${suspPct}% of total`;
  document.getElementById('rep-pct-blocked').textContent = `${blkPct}% of total`;
}

function renderQueriesChart(labels, values) {
  const ctx = document.getElementById('chart-queries-time').getContext('2d');
  if (queriesChart) queriesChart.destroy();

  queriesChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labels,
      datasets: [{
        label: 'DNS Queries',
        data: values,
        borderColor: '#2563EB',
        backgroundColor: 'rgba(37, 99, 235, 0.08)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointBackgroundColor: '#2563EB',
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
          callbacks: {
            label: (ctx) => ` Queries: ${ctx.parsed.y}`
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            stepSize: 1,
            precision: 0,
            font: { size: 11 }
          },
          grid: { color: '#F1F5F9' }
        },
        x: {
          grid: { display: false },
          ticks: { font: { size: 11 } }
        }
      }
    }
  });
}

function renderStatusDonutChart(dist) {
  const ctx = document.getElementById('chart-status-donut').getContext('2d');
  if (statusDonutChart) statusDonutChart.destroy();

  const safe = dist.safe || 0;
  const susp = dist.suspicious || 0;
  const blk = dist.blocked || 0;
  const hasData = (safe + susp + blk) > 0;

  statusDonutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Blocked'],
      datasets: [{
        data: hasData ? [safe, susp, blk] : [1, 0, 0],
        backgroundColor: hasData ? ['#10B981', '#F59E0B', '#EF4444'] : ['#E2E8F0', '#E2E8F0', '#E2E8F0'],
        borderWidth: 2,
        borderColor: '#FFFFFF'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'right',
          labels: { font: { size: 11 }, boxWidth: 12 }
        }
      }
    }
  });
}

function renderTopDomainsTable(domains) {
  const tbody = document.getElementById('rep-top-domains-tbody');
  if (!domains || domains.length === 0) {
    tbody.innerHTML = '<tr><td colspan="2" style="text-align: center; color: var(--text-muted); padding: 18px;">No data available</td></tr>';
    return;
  }
  tbody.innerHTML = domains.map(d => `
    <tr>
      <td>
        <div class="domain-cell">
          <span class="domain-icon">${getDomainIcon(d.domain)}</span>
          <span style="font-weight: 500;">${d.domain}</span>
        </div>
      </td>
      <td style="text-align: right; font-weight: 600;">${d.queries.toLocaleString()}</td>
    </tr>
  `).join('');
}

function renderTopDevicesTable(devices) {
  const tbody = document.getElementById('rep-top-devices-tbody');
  if (!devices || devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 18px;">No data available</td></tr>';
    return;
  }
  tbody.innerHTML = devices.map(dev => `
    <tr>
      <td style="font-weight: 600;">${dev.device_name}</td>
      <td style="font-family: monospace; font-size: 11.5px;">${dev.ip_address}</td>
      <td style="text-align: right; font-weight: 600;">${dev.queries.toLocaleString()}</td>
    </tr>
  `).join('');
}

function renderAlertsSummaryTable(alerts) {
  const tbody = document.getElementById('rep-alerts-summary-tbody');
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-muted); padding: 18px;">No data available</td></tr>';
    return;
  }
  tbody.innerHTML = alerts.map(a => {
    const sevClass = a.severity.toLowerCase() === 'high' ? 'badge-high' : (a.severity.toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low');
    return `
      <tr>
        <td><span class="${sevClass}">${a.severity}</span></td>
        <td style="font-weight: 600;">${a.alerts}</td>
        <td style="text-align: right; color: var(--text-muted); font-size: 11.5px; font-weight: 500;">${a.trend}</td>
      </tr>
    `;
  }).join('');
}
