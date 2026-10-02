// ==========================================================================
// DNSWatch Live Dashboard JavaScript Controller
// ==========================================================================

let dashboardPollInterval = null;
let viewersPollInterval = null;

document.addEventListener('DOMContentLoaded', () => {
  refreshDashboard();
  // Live polling every 4 seconds when monitoring is active (paused when tab in background)
  dashboardPollInterval = setInterval(() => {
    if (globalMonitoringActive && !document.hidden) {
      refreshDashboard();
    }
  }, 4000);

  // Listen to monitoring state changes
  document.addEventListener('monitoringStateChanged', () => {
    refreshDashboard();
  });

  // Portal viewers: load immediately, then every 20s (admin/analyst only, paused when in background)
  if (typeof IS_ADMIN !== 'undefined' && (IS_ADMIN || IS_ANALYST)) {
    loadPortalViewers();
    viewersPollInterval = setInterval(() => {
      if (!document.hidden) {
        loadPortalViewers();
      }
    }, 20000);
  }
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
      animateValue('dash-total-queries', Number(data.total_queries));
      animateValue('dash-suspicious-queries', Number(data.suspicious_queries));
      animateValue('dash-blocked-queries', Number(data.blocked_queries));
    }
  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
  }
}

// Helper: Animate Counter Numbers smoothly
function animateValue(id, value) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = value.toLocaleString();
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
        const domain = log.domain || log.query_domain;
        const iconHtml = getDomainIcon(domain);
        const badgeHtml = getStatusBadge(log.status);
        const qtypeBadge = typeof getQueryTypeBadge === 'function' ? getQueryTypeBadge(log.query_type) : `<span class="qtype-badge qtype-A">${log.query_type || 'A'}</span>`;
        const respIp = log.response_ip && log.response_ip !== '-' ? log.response_ip : '-';
        const clientIp = log.client_ip || 'Unknown';
        
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
            <td>${badgeHtml}</td>
          </tr>
        `;
      }).join('');
      
      document.getElementById('dash-dns-counter').textContent = `Showing 1 to ${data.logs.length} live entries`;
    } else {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align: center; color: var(--text-muted); padding: 30px;">
            <div style="font-size: 13px; font-weight: 500;">No DNS queries recorded yet</div>
            <div style="font-size: 11.5px; color: var(--text-light); margin-top: 4px;">Click <strong>Start Sniffer</strong> in the sidebar to begin live packet capture on port 53.</div>
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
        const sev = (alt.severity || 'HIGH').toUpperCase();
        let sevItemClass = '';
        let sevBadge = '<span class="badge-high"><i class="fa-solid fa-triangle-exclamation"></i> HIGH</span>';
        if (sev === 'MEDIUM') {
          sevItemClass = 'sev-medium';
          sevBadge = '<span class="badge-medium"><i class="fa-solid fa-triangle-exclamation"></i> MEDIUM</span>';
        } else if (sev === 'LOW') {
          sevItemClass = 'sev-low';
          sevBadge = '<span class="badge-low"><i class="fa-solid fa-circle-info"></i> LOW</span>';
        }
        
        const timeStr = alt.time_only || (alt.timestamp ? alt.timestamp.split(' ')[1] : '-');
        
        return `
          <div class="alert-widget-item ${sevItemClass}">
            <div class="alert-widget-left">
              <div class="alert-widget-title">${alt.alert_type}</div>
              <div class="alert-widget-domain">${alt.domain || alt.client_ip}</div>
            </div>
            <div class="alert-widget-right">
              ${sevBadge}
              <span class="alert-widget-time">${timeStr}</span>
            </div>
          </div>
        `;
      }).join('');
    } else {
      container.innerHTML = `
        <div style="text-align: center; color: var(--text-muted); padding: 25px 0; font-size: 12.5px;">
          <i class="fa-solid fa-circle-check" style="color: var(--brand-success); font-size: 24px; margin-bottom: 8px;"></i>
          <div style="font-weight: 600; color: var(--text-main);">Zero Active Incidents</div>
          <div style="font-size: 11.5px; color: var(--text-light); margin-top: 2px;">No malicious activity detected in recent packets.</div>
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
      if (badge) {
        if (mon.is_running) {
          badge.className = 'badge badge-safe';
          badge.innerHTML = '<i class="fa-solid fa-bolt"></i> Active';
        } else {
          badge.className = 'badge';
          badge.style.background = 'var(--bg-surface-elevated)';
          badge.style.color = 'var(--text-light)';
          badge.innerHTML = '<i class="fa-solid fa-power-off"></i> Inactive';
        }
      }
      
      const packetsEl = document.getElementById('status-packets-count');
      if (packetsEl) packetsEl.textContent = Number(mon.total_queries || 0).toLocaleString();
      
      const lastPktEl = document.getElementById('status-last-packet');
      if (lastPktEl) lastPktEl.textContent = mon.last_packet_time || 'None';
      
      const uptimeEl = document.getElementById('status-uptime');
      if (uptimeEl) uptimeEl.textContent = mon.uptime || '00:00:00';
    }
  } catch (err) {
    console.error('Error fetching system status:', err);
  }
}

// ==========================================================================
// 5. Portal Viewers — Live session table
// ==========================================================================
async function loadPortalViewers() {
  const tbody = document.getElementById('portal-viewers-tbody');
  if (!tbody) return;

  const roleFilter = (document.getElementById('viewer-role-filter') || {}).value || '';
  let url = '/api/portal-sessions';
  if (roleFilter) url += `?role=${encodeURIComponent(roleFilter)}`;

  try {
    const res = await fetch(url);
    const data = await res.json();

    if (!data.success) return;

    const sessions = data.sessions || [];
    const onlineCount = data.online_count || 0;

    // Update counters
    const onlineBadge = document.getElementById('online-viewers-badge');
    if (onlineBadge) onlineBadge.textContent = onlineCount;

    const onlineEl = document.getElementById('viewers-online-count');
    if (onlineEl) onlineEl.textContent = onlineCount;

    const totalEl = document.getElementById('viewers-total-count');
    if (totalEl) totalEl.textContent = sessions.length;

    const refreshEl = document.getElementById('viewers-last-refresh');
    if (refreshEl) refreshEl.textContent = new Date().toLocaleTimeString();

    const counterEl = document.getElementById('viewers-counter');
    if (counterEl) counterEl.textContent = `${onlineCount} online · ${sessions.length} total session(s)`;

    if (sessions.length === 0) {
      const cols = IS_ADMIN ? 9 : 8;
      tbody.innerHTML = `<tr><td colspan="${cols}" style="text-align:center;color:var(--text-muted);padding:40px;">
        <i class="fa-solid fa-users-slash" style="font-size:26px;margin-bottom:10px;color:var(--text-light);"></i>
        <div style="font-weight:600;color:var(--text-main);margin-bottom:4px;">No active portal sessions</div>
        <div style="font-size:12px;">No users are currently logged in to the web portal.</div>
      </td></tr>`;
      return;
    }

    tbody.innerHTML = sessions.map(s => {
      const isOnline = s.is_online;
      const statusDot = isOnline
        ? `<span style="display:inline-flex;align-items:center;gap:6px;"><span class="status-dot active" style="width:8px;height:8px;"></span><span style="color:var(--brand-success);font-size:12px;font-weight:600;">Online</span></span>`
        : `<span style="display:inline-flex;align-items:center;gap:6px;"><span class="status-dot" style="width:8px;height:8px;background:var(--text-light);"></span><span style="color:var(--text-muted);font-size:12px;">Offline</span></span>`;

      // Role badge
      const role = s.role_name || 'Viewer';
      let roleBadgeClass = 'badge';
      if (role.toLowerCase().includes('admin')) roleBadgeClass += ' badge-blocked';
      else if (role.toLowerCase().includes('analyst')) roleBadgeClass += ' badge-suspicious';
      else roleBadgeClass += ' badge-safe';

      // Browser icon
      const browserIcons = { Chrome: 'fa-brands fa-chrome', Firefox: 'fa-brands fa-firefox-browser', Safari: 'fa-brands fa-safari', Edge: 'fa-brands fa-edge', Opera: 'fa-brands fa-opera' };
      const browserIcon = browserIcons[s.browser] || 'fa-solid fa-globe';

      // Page display name
      const pageDisplay = s.current_page === '/' ? 'Home' : (s.current_page || '/').replace(/^\//, '').replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) || 'Dashboard';

      const adminAction = IS_ADMIN ? `<td><button class="btn btn-outline btn-sm" onclick="endPortalSession(${s.id}, '${s.username}')" style="color:var(--brand-danger);border-color:rgba(239,68,68,0.3);font-size:11px;" title="Force end this session"><i class="fa-solid fa-plug-circle-xmark"></i> End</button></td>` : '';

      return `<tr>
        <td>${statusDot}</td>
        <td>
          <div style="font-weight:600;color:var(--text-main);">${s.username}</div>
          <div style="font-size:11px;color:var(--text-muted);">ID: ${s.user_id}</div>
        </td>
        <td><span class="${roleBadgeClass}" style="font-size:11px;">${role}</span></td>
        <td>
          <span class="ip-chip" onclick="copyToClipboard('${s.ip_address}', 'IP Address')" title="Click to copy IP address">
            ${s.ip_address} <i class="fa-regular fa-copy"></i>
          </span>
        </td>
        <td>
          <div style="font-size:12px;"><i class="${browserIcon}" style="margin-right:4px;color:var(--brand-info);"></i>${s.browser}</div>
          <div style="font-size:11px;color:var(--text-muted);">${s.os}</div>
        </td>
        <td>
          <span style="font-size:12px;font-family:var(--font-mono);color:var(--text-main);">${s.current_page || '/'}</span>
          <div style="font-size:11px;color:var(--text-muted);">${pageDisplay}</div>
        </td>
        <td style="font-family:var(--font-mono);font-size:12px;color:var(--text-main);">${s.session_duration}</td>
        <td style="font-size:12px;color:var(--text-muted);">${s.last_seen_ago}</td>
        ${adminAction}
      </tr>`;
    }).join('');

  } catch (err) {
    console.error('Error fetching portal viewers:', err);
  }
}

async function endPortalSession(sessionId, username) {
  if (!confirm(`Force end the portal session for user "${username}"? They will be disconnected on their next action.`)) return;

  try {
    const res = await fetch(`/api/portal-sessions/${sessionId}/end`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin'
    });
    const data = await res.json();
    if (data.success) {
      if (typeof showToast === 'function') showToast(data.message, 'success');
      loadPortalViewers();
    } else {
      if (typeof showToast === 'function') showToast(data.message || 'Failed to end session.', 'danger');
    }
  } catch (err) {
    console.error('Error ending portal session:', err);
  }
}

