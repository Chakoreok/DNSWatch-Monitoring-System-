// ==========================================================================
// DNSWatch Live Dashboard JavaScript Controller
// ==========================================================================

let dashboardPollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  refreshDashboard();
  // Live polling every 1.5 seconds for real-time responsiveness
  dashboardPollInterval = setInterval(refreshDashboard, 1500);
});

async function refreshDashboard() {
  await Promise.all([
    fetchDashboardStats(),
    fetchLiveDNSLogs(),
    fetchRecentAlerts(),
    fetchSystemStatus()
  ]);
}

// 1. Fetch & Render Summary Stat Cards
async function fetchDashboardStats() {
  try {
    const res = await fetch('/api/dns/stats');
    const data = await res.json();
    if (data.success) {
      document.getElementById('dash-total-queries').textContent = Number(data.total_queries).toLocaleString();
      document.getElementById('dash-suspicious-queries').textContent = Number(data.suspicious_queries).toLocaleString();
      document.getElementById('dash-blocked-queries').textContent = Number(data.blocked_queries).toLocaleString();
    }
  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
  }
}

// 2. Fetch & Render Live DNS Queries Table
async function fetchLiveDNSLogs() {
  try {
    const res = await fetch('/api/dns/recent?limit=10');
    const data = await res.json();
    const tbody = document.getElementById('dash-dns-tbody');
    
    if (data.success && data.logs && data.logs.length > 0) {
      tbody.innerHTML = data.logs.map(log => {
        const timeStr = log.time_only || (log.timestamp ? log.timestamp.split(' ')[1] : '-');
        const iconHtml = getDomainIcon(log.domain || log.query_domain);
        const badgeHtml = getStatusBadge(log.status);
        const respIp = log.response_ip && log.response_ip !== '-' ? log.response_ip : '-';
        
        return `
          <tr>
            <td style="color: var(--text-muted); font-size: 11.5px; white-space: nowrap;">${timeStr}</td>
            <td style="font-family: monospace; font-size: 12px; font-weight: 500;">${log.client_ip || 'Unknown'}</td>
            <td>
              <div class="domain-cell">
                <span class="domain-icon">${iconHtml}</span>
                <span style="font-weight: 500;">${log.domain || log.query_domain}</span>
              </div>
            </td>
            <td><span style="background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600;">${log.query_type || 'A'}</span></td>
            <td style="font-family: monospace; font-size: 12px; color: ${respIp !== '-' ? 'var(--text-main)' : 'var(--text-light)'};">${respIp}</td>
            <td>${badgeHtml}</td>
          </tr>
        `;
      }).join('');
      
      document.getElementById('dash-dns-counter').textContent = `Showing 1 to ${data.logs.length} live entries`;
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">
            No DNS queries recorded yet. Click <strong>Start Monitoring</strong> or run queries on port 53.
          </td>
        </tr>
      `;
      document.getElementById('dash-dns-counter').textContent = 'Showing 0 entries';
    }
  } catch (err) {
    console.error('Error fetching live DNS logs:', err);
  }
}

// 3. Fetch & Render Recent Security Alerts Widget
async function fetchRecentAlerts() {
  try {
    const res = await fetch('/api/alerts/recent?limit=4');
    const data = await res.json();
    const container = document.getElementById('dash-alerts-container');
    
    if (data.success && data.alerts && data.alerts.length > 0) {
      container.innerHTML = data.alerts.map(alt => {
        const sevClass = (alt.severity || 'HIGH').toLowerCase() === 'high' ? 'badge-high' : 
                         ((alt.severity || '').toLowerCase() === 'medium' ? 'badge-medium' : 'badge-low');
        const timeStr = alt.time_only || (alt.timestamp ? alt.timestamp.split(' ')[1] : '-');
        
        return `
          <div class="alert-widget-item">
            <div class="alert-widget-left">
              <div class="alert-widget-title">${alt.alert_type}</div>
              <div class="alert-widget-domain">${alt.domain || alt.client_ip}</div>
            </div>
            <div class="alert-widget-right">
              <span class="${sevClass}" style="font-size: 11px;">${alt.severity}</span>
              <span class="alert-widget-time">${timeStr}</span>
            </div>
          </div>
        `;
      }).join('');
    } else {
      container.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 20px 0; font-size: 12px;">
          <i class="fa-solid fa-circle-check" style="color: var(--success); font-size: 18px; margin-bottom: 6px;"></i>
          <div>No security threats detected.</div>
        </div>
      `;
    }
  } catch (err) {
    console.error('Error fetching recent alerts:', err);
  }
}

// 4. Fetch & Render System Status Panel
async function fetchSystemStatus() {
  try {
    const res = await fetch('/api/monitoring/status');
    const data = await res.json();
    if (data.success && data.monitoring) {
      const mon = data.monitoring;
      
      const badge = document.getElementById('status-mon-badge');
      if (mon.is_running) {
        badge.className = 'badge badge-safe';
        badge.textContent = 'Active';
      } else {
        badge.className = 'badge';
        badge.style.background = '#f1f5f9';
        badge.style.color = '#64748b';
        badge.textContent = 'Inactive';
      }
      
      document.getElementById('status-packets-count').textContent = Number(mon.total_queries).toLocaleString();
      document.getElementById('status-last-packet').textContent = mon.last_packet_time || 'None';
      document.getElementById('status-uptime').textContent = mon.uptime || '00:00:00';
    }
  } catch (err) {
    console.error('Error fetching system status:', err);
  }
}
