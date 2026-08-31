// ==========================================================================
// DNSWatch Global JavaScript Application Core
// ==========================================================================

let globalMonitoringActive = false;
let previousMonitoringRunning = false;

// 1. Initialize Global App State
document.addEventListener('DOMContentLoaded', () => {
  if (document.body && document.body.dataset && document.body.dataset.monitoringActive) {
    globalMonitoringActive = document.body.dataset.monitoringActive === 'true';
    previousMonitoringRunning = globalMonitoringActive;
  }
  pollGlobalStatus();
  // Poll monitoring status every 1.5 seconds for instant synchronization
  setInterval(pollGlobalStatus, 1500);
});

// 2. Poll Status from Backend
async function pollGlobalStatus() {
  try {
    const res = await fetch('/api/monitoring/status');
    const data = await res.json();
    if (data && data.monitoring) {
      updateMonitoringUI(data.monitoring);
    }
  } catch (err) {
    console.error('Error fetching monitoring status:', err);
  }

  try {
    const alertRes = await fetch('/api/alerts/counts');
    const alertData = await alertRes.json();
    if (alertData && alertData.total !== undefined) {
      const badge = document.getElementById('header-alert-count');
      if (badge) {
        badge.textContent = alertData.total;
        badge.style.display = alertData.total > 0 ? 'flex' : 'none';
      }
    }
  } catch (err) {
    // Ignore transient count fetch error
  }
}

// 3. Update Monitoring UI state across all views
function updateMonitoringUI(mon) {
  const stateChanged = (previousMonitoringRunning !== mon.is_running);
  previousMonitoringRunning = mon.is_running;
  globalMonitoringActive = mon.is_running;
  
  const sideDot = document.getElementById('sidebar-status-dot');
  const sideText = document.getElementById('sidebar-status-text');
  const sideStarted = document.getElementById('sidebar-started-at');
  const sideBtn = document.getElementById('btn-toggle-monitoring');
  
  const headDot = document.getElementById('header-status-dot');
  const headText = document.getElementById('header-status-text');
  const headBadge = document.getElementById('header-status-badge');
  const dashBadge = document.getElementById('status-mon-badge');

  if (mon.is_running) {
    if (sideDot) sideDot.className = 'status-dot active';
    if (sideText) sideText.textContent = 'Monitoring Active';
    if (sideStarted) sideStarted.textContent = `Started at ${mon.started_at}`;
    if (headDot) headDot.className = 'status-dot active';
    if (headText) headText.textContent = 'Monitoring Active';
    if (headBadge) headBadge.className = 'live-badge active';
    
    if (dashBadge) {
      dashBadge.className = 'badge badge-safe';
      dashBadge.removeAttribute('style');
      dashBadge.textContent = 'Active';
    }
    
    if (sideBtn) {
      sideBtn.className = 'btn-monitoring-toggle btn-stop';
      sideBtn.innerHTML = '<i class="fa-solid fa-stop"></i> <span>Stop Monitoring</span>';
    }
  } else {
    if (sideDot) sideDot.className = 'status-dot';
    if (sideText) sideText.textContent = 'Monitoring Inactive';
    if (sideStarted) sideStarted.textContent = 'Capture Inactive';
    if (headDot) headDot.className = 'status-dot';
    if (headText) headText.textContent = 'Monitoring Inactive';
    if (headBadge) headBadge.className = 'live-badge inactive';
    
    if (dashBadge) {
      dashBadge.className = 'badge';
      dashBadge.style.background = '#f1f5f9';
      dashBadge.style.color = '#64748b';
      dashBadge.textContent = 'Inactive';
    }
    
    if (sideBtn) {
      sideBtn.className = 'btn-monitoring-toggle btn-start';
      sideBtn.innerHTML = '<i class="fa-solid fa-play"></i> <span>Start Monitoring</span>';
    }
  }

  // Broadcast state change event to active page controllers only when state transitions
  if (stateChanged) {
    document.dispatchEvent(new CustomEvent('monitoringStateChanged', { detail: mon }));
  }
}

// 4. Toggle Monitoring (Start / Stop)
async function toggleGlobalMonitoring() {
  const btn = document.getElementById('btn-toggle-monitoring');
  if (btn) btn.disabled = true;
  
  try {
    const endpoint = globalMonitoringActive ? '/api/monitoring/stop' : '/api/monitoring/start';
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (data.monitoring) {
      updateMonitoringUI(data.monitoring);
    }
    
    // Call page-specific refresh if defined
    if (typeof refreshDashboard === 'function') refreshDashboard();
    if (typeof fetchWebsiteActivity === 'function') fetchWebsiteActivity(1);
    if (typeof fetchLogs === 'function') fetchLogs(1);
    if (typeof fetchDevices === 'function') fetchDevices();
  } catch (err) {
    console.error('Error toggling monitoring:', err);
    alert('Failed to toggle monitoring: ' + err.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

// 5. Helper: Domain Icon Generator
function getDomainIcon(domain) {
  if (!domain) return '<i class="fa-solid fa-globe"></i>';
  const d = domain.toLowerCase();
  if (d.includes('google')) return '<i class="fa-brands fa-google" style="color:#4285F4"></i>';
  if (d.includes('facebook')) return '<i class="fa-brands fa-facebook" style="color:#1877F2"></i>';
  if (d.includes('youtube')) return '<i class="fa-brands fa-youtube" style="color:#FF0000"></i>';
  if (d.includes('microsoft') || d.includes('windows')) return '<i class="fa-brands fa-microsoft" style="color:#00A4EF"></i>';
  if (d.includes('apple')) return '<i class="fa-brands fa-apple"></i>';
  if (d.includes('netflix')) return '<span style="color:#E50914;font-weight:900;">N</span>';
  if (d.includes('discord')) return '<i class="fa-brands fa-discord" style="color:#5865F2"></i>';
  if (d.includes('github')) return '<i class="fa-brands fa-github"></i>';
  if (d.includes('malicious') || d.includes('phishing') || d.includes('bad') || d.includes('malware')) {
    return '<i class="fa-solid fa-triangle-exclamation" style="color:#EF4444"></i>';
  }
  return '<i class="fa-solid fa-globe" style="color:#64748b"></i>';
}

// 6. Helper: Status Badge HTML Generator
function getStatusBadge(status) {
  const s = (status || 'SAFE').toUpperCase();
  if (s === 'BLOCKED') return '<span class="badge badge-blocked">BLOCKED</span>';
  if (s === 'SUSPICIOUS') return '<span class="badge badge-suspicious">SUSPICIOUS</span>';
  return '<span class="badge badge-safe">SAFE</span>';
}

function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  const mainWrapper = document.querySelector('.main-wrapper');
  if (sidebar) {
    sidebar.classList.toggle('collapsed');
  }
}
