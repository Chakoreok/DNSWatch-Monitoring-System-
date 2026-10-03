// ==========================================================================
// DNSWatch Global JavaScript Application Core
// ==========================================================================

let globalMonitoringActive = false;
let previousMonitoringRunning = false;

// 1. Initialize Global App State
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initCommandPalette();

  if (document.body && document.body.dataset && document.body.dataset.monitoringActive) {
    globalMonitoringActive = document.body.dataset.monitoringActive === 'true';
    previousMonitoringRunning = globalMonitoringActive;
  }
  pollGlobalStatus();
  // Poll monitoring status every 5 seconds (paused when tab is hidden in background)
  setInterval(() => {
    if (!document.hidden) {
      pollGlobalStatus();
    }
  }, 5000);
});

// --------------------------------------------------------------------------
// 2. Dark / Light Theme Manager
// --------------------------------------------------------------------------
function initTheme() {
  const savedTheme = localStorage.getItem('dnswatch_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const newTheme = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('dnswatch_theme', newTheme);
  updateThemeIcon(newTheme);
  
  // Broadcast theme change event so charts can re-render with new colors
  document.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme: newTheme } }));
  showToast(`Switched to ${newTheme === 'dark' ? 'Dark Cyber SOC' : 'Light Clean'} mode`, 'info', 1800);
}

function updateThemeIcon(theme) {
  const icon = document.getElementById('theme-icon');
  if (icon) {
    if (theme === 'dark') {
      icon.className = 'fa-solid fa-sun';
    } else {
      icon.className = 'fa-solid fa-moon';
    }
  }
}

// --------------------------------------------------------------------------
// 3. Command Palette (Ctrl+K / Cmd+K)
// --------------------------------------------------------------------------
function initCommandPalette() {
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      toggleCommandPalette();
    }
    if (e.key === 'Escape') {
      closeCommandPalette();
    }
  });

  const cmdInput = document.getElementById('cmd-input');
  if (cmdInput) {
    cmdInput.addEventListener('input', filterCommandPalette);
  }
}

function openCommandPalette() {
  const modal = document.getElementById('modal-cmd-palette');
  const input = document.getElementById('cmd-input');
  if (modal) {
    modal.classList.add('active');
    if (input) {
      input.value = '';
      setTimeout(() => input.focus(), 50);
      filterCommandPalette();
    }
  }
}

function closeCommandPalette() {
  const modal = document.getElementById('modal-cmd-palette');
  if (modal) {
    modal.classList.remove('active');
  }
}

function toggleCommandPalette() {
  const modal = document.getElementById('modal-cmd-palette');
  if (modal && modal.classList.contains('active')) {
    closeCommandPalette();
  } else {
    openCommandPalette();
  }
}

function handleCmdBackdropClick(e) {
  if (e.target && e.target.id === 'modal-cmd-palette') {
    closeCommandPalette();
  }
}

function filterCommandPalette() {
  const input = document.getElementById('cmd-input');
  const term = (input ? input.value : '').toLowerCase().trim();
  const items = document.querySelectorAll('.cmd-item');

  items.forEach(item => {
    const text = item.textContent.toLowerCase();
    if (!term || text.includes(term)) {
      item.style.display = 'flex';
    } else {
      item.style.display = 'none';
    }
  });
}

// --------------------------------------------------------------------------
// 4. Poll Status from Backend
// --------------------------------------------------------------------------
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

// --------------------------------------------------------------------------
// 5. Update Monitoring UI state across all views
// --------------------------------------------------------------------------
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
      sideBtn.innerHTML = '<i class="fa-solid fa-stop"></i> <span>Stop Sniffer</span>';
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
      dashBadge.style.background = 'var(--bg-surface-elevated)';
      dashBadge.style.color = 'var(--text-light)';
      dashBadge.textContent = 'Inactive';
    }
    
    if (sideBtn) {
      sideBtn.className = 'btn-monitoring-toggle btn-start';
      sideBtn.innerHTML = '<i class="fa-solid fa-play"></i> <span>Start Sniffer</span>';
    }
  }

  // Broadcast state change event to active page controllers only when state transitions
  if (stateChanged) {
    document.dispatchEvent(new CustomEvent('monitoringStateChanged', { detail: mon }));
  }
}

// --------------------------------------------------------------------------
// 6. Toggle Monitoring (Start / Stop)
// --------------------------------------------------------------------------
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
    if (data.message) {
      showToast(data.message, data.success ? 'success' : 'warning', 4000);
    } else if (data.monitoring) {
      showToast(
        data.monitoring.is_running ? 'DNS Packet Sniffer activated successfully' : 'DNS Packet Sniffer stopped',
        data.monitoring.is_running ? 'success' : 'warning'
      );
    }
    
    // Call page-specific refresh if defined
    if (typeof refreshDashboard === 'function') refreshDashboard();
    if (typeof fetchWebsiteActivity === 'function') fetchWebsiteActivity(1);
    if (typeof fetchLogs === 'function') fetchLogs(1);
    if (typeof fetchDevices === 'function') fetchDevices();
  } catch (err) {
    console.error('Error toggling monitoring:', err);
    showToast('Failed to toggle monitoring: ' + err.message, 'danger');
  } finally {
    if (btn) btn.disabled = false;
  }
}

// --------------------------------------------------------------------------
// 7. Clipboard & Tool Helpers
// --------------------------------------------------------------------------
function copyToClipboard(text, label = 'Copied') {
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    showToast(`${label}: ${text}`, 'success', 1800);
  }).catch(() => {
    showToast(`Failed to copy: ${text}`, 'danger', 1800);
  });
}

// --------------------------------------------------------------------------
// 8. Helper: Domain Icon Generator
// --------------------------------------------------------------------------
function getDomainIcon(domain) {
  if (!domain) return '<i class="fa-solid fa-globe"></i>';
  const d = domain.toLowerCase();
  if (d.includes('google')) return '<i class="fa-brands fa-google" style="color:#4285F4"></i>';
  if (d.includes('facebook') || d.includes('fb.com')) return '<i class="fa-brands fa-facebook" style="color:#1877F2"></i>';
  if (d.includes('youtube')) return '<i class="fa-brands fa-youtube" style="color:#FF0000"></i>';
  if (d.includes('microsoft') || d.includes('windows') || d.includes('live.com') || d.includes('office')) return '<i class="fa-brands fa-microsoft" style="color:#00A4EF"></i>';
  if (d.includes('apple') || d.includes('icloud')) return '<i class="fa-brands fa-apple" style="color:#A2AAAD"></i>';
  if (d.includes('netflix')) return '<span style="color:#E50914;font-weight:900;font-size:11px;">N</span>';
  if (d.includes('discord')) return '<i class="fa-brands fa-discord" style="color:#5865F2"></i>';
  if (d.includes('github')) return '<i class="fa-brands fa-github"></i>';
  if (d.includes('twitter') || d.includes('x.com')) return '<i class="fa-brands fa-x-twitter"></i>';
  if (d.includes('amazon') || d.includes('aws')) return '<i class="fa-brands fa-amazon" style="color:#FF9900"></i>';
  if (d.includes('malicious') || d.includes('phishing') || d.includes('bad') || d.includes('malware') || d.includes('exploit') || d.includes('c2')) {
    return '<i class="fa-solid fa-triangle-exclamation" style="color:#EF4444"></i>';
  }
  return '<i class="fa-solid fa-globe" style="color:var(--text-muted)"></i>';
}

// --------------------------------------------------------------------------
// 9. Helper: Status Badge HTML Generator
// --------------------------------------------------------------------------
function getStatusBadge(status) {
  const s = (status || 'SAFE').toUpperCase();
  if (s === 'BLOCKED') return '<span class="badge badge-blocked"><i class="fa-solid fa-ban"></i> BLOCKED</span>';
  if (s === 'SUSPICIOUS') return '<span class="badge badge-suspicious"><i class="fa-solid fa-triangle-exclamation"></i> SUSPICIOUS</span>';
  return '<span class="badge badge-safe"><i class="fa-solid fa-check"></i> SAFE</span>';
}

// Helper: Query Type Badge
function getQueryTypeBadge(qtype) {
  const t = (qtype || 'A').toUpperCase();
  return `<span class="qtype-badge qtype-${t}">${t}</span>`;
}

function toggleSidebar() {
  const sidebar = document.querySelector('.sidebar');
  if (sidebar) {
    sidebar.classList.toggle('collapsed');
  }
}

// --------------------------------------------------------------------------
// 10. Toast Notification System
// --------------------------------------------------------------------------
function showToast(message, type = 'info', duration = 3000) {
  let container = document.getElementById('global-toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'global-toast-container';
    container.className = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast-item toast-${type}`;

  let iconHtml = '<i class="fa-solid fa-circle-info"></i>';
  if (type === 'success') iconHtml = '<i class="fa-solid fa-circle-check"></i>';
  if (type === 'danger') iconHtml = '<i class="fa-solid fa-circle-xmark"></i>';
  if (type === 'warning') iconHtml = '<i class="fa-solid fa-triangle-exclamation"></i>';

  toast.innerHTML = `
    ${iconHtml}
    <div style="flex: 1; line-height: 1.35;">${message}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('toast-hiding');
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
      }
    }, 250);
  }, duration);
}
