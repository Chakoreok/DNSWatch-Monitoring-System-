// ==========================================================================
// DNSWatch Manual DNS Blocking & Block Request Workflow (Global JS)
// ==========================================================================

function getUserRole() {
  const role = (document.body && document.body.dataset && document.body.dataset.userRole) || '';
  return role.trim() || 'Viewer';
}

function isAdmin() {
  const r = getUserRole().toLowerCase();
  return r === 'administrator' || r === 'admin';
}

function isAnalyst() {
  const r = getUserRole().toLowerCase();
  return r.includes('analyst') || r === 'security analyst' || r === 'senior analyst';
}

function canRequestBlock() {
  return isAdmin() || isAnalyst();
}

function escapeHtml(str) {
  if (!str && str !== 0) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function openModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) {
    el.classList.add('show');
    el.classList.add('active');
    el.style.display = 'flex';
    el.style.opacity = '1';
    el.style.pointerEvents = 'auto';
  }
}

function closeModal(modalId) {
  const el = document.getElementById(modalId);
  if (el) {
    el.classList.remove('show');
    el.classList.remove('active');
    el.style.display = 'none';
    el.style.opacity = '0';
    el.style.pointerEvents = 'none';
  }
}

// Close modal when clicking on backdrop outside modal dialog
document.addEventListener('click', (e) => {
  if (e.target && e.target.classList && e.target.classList.contains('modal-backdrop')) {
    closeModal(e.target.id);
  }
});

// --------------------------------------------------------------------------
// Click Handlers using Data Attributes (Prevents Quote/Syntax Breakage)
// --------------------------------------------------------------------------

function handleDirectBlockClick(btn) {
  if (!btn) return;
  const domain = btn.getAttribute('data-domain') || '';
  const ip = btn.getAttribute('data-ip') || '';
  openDirectBlockModal(domain, ip);
}

function handleRequestBlockClick(btn) {
  if (!btn) return;
  const domain = btn.getAttribute('data-domain') || '';
  const ip = btn.getAttribute('data-ip') || '';
  const info = btn.getAttribute('data-info') || '';
  openRequestBlockModal(domain, ip, info);
}

// --------------------------------------------------------------------------
// Request Block Modal Flow (Security Analyst & Admin)
// --------------------------------------------------------------------------

function openRequestBlockModal(domain, clientIp, detectionInfo) {
  if (!canRequestBlock()) {
    alert('Only Security Analysts and Administrators may submit block requests.');
    return;
  }
  const domInput = document.getElementById('rbModal-domain');
  const ipInput = document.getElementById('rbModal-clientip');
  const ipGroup = document.getElementById('rbModal-ip-group');
  const detInput = document.getElementById('rbModal-detinfo');
  const detGroup = document.getElementById('rbModal-detinfo-group');
  const reasonInput = document.getElementById('rbModal-reason');
  const feedback = document.getElementById('rbModal-feedback');

  if (domInput) domInput.value = domain || '';
  if (ipInput) {
    ipInput.value = clientIp || '';
    if (ipGroup) ipGroup.style.display = clientIp ? 'block' : 'none';
  }
  if (detInput) {
    detInput.value = detectionInfo || '';
    if (detGroup) detGroup.style.display = detectionInfo ? 'block' : 'none';
  }
  if (reasonInput) {
    reasonInput.value = '';
    reasonInput.disabled = false;
  }
  if (feedback) {
    feedback.innerHTML = '';
    feedback.style.display = 'none';
  }

  const btn = document.getElementById('rbModal-submit-btn');
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Request';
  }

  openModal('modal-request-block');
}

async function submitBlockRequest() {
  const domain = (document.getElementById('rbModal-domain')?.value || '').trim();
  const client_ip = (document.getElementById('rbModal-clientip')?.value || '').trim();
  const detection_info = (document.getElementById('rbModal-detinfo')?.value || '').trim();
  const reason = (document.getElementById('rbModal-reason')?.value || '').trim();
  const feedback = document.getElementById('rbModal-feedback');
  const btn = document.getElementById('rbModal-submit-btn');

  if (!reason) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.color = 'var(--danger)';
      feedback.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Please provide a reason for the block request.';
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';
  }

  try {
    const res = await fetch('/api/blocking/requests', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, client_ip, detection_info, reason })
    });
    const data = await res.json();

    if (data.success) {
      if (feedback) {
        feedback.style.display = 'block';
        feedback.style.color = 'var(--success)';
        feedback.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${escapeHtml(data.message || 'Block request submitted.')}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message || 'Block request submitted successfully.', 'success');
      }
      setTimeout(() => {
        closeModal('modal-request-block');
        refreshActivePageTables();
      }, 700);
    } else {
      if (feedback) {
        feedback.style.display = 'block';
        feedback.style.color = 'var(--danger)';
        feedback.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(data.message || 'Failed to submit request.')}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message || 'Failed to submit request.', 'danger');
      }
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Request';
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.color = 'var(--danger)';
      feedback.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Network error: ${escapeHtml(err.message)}`;
    }
    if (typeof showToast === 'function') {
      showToast('Network error: ' + err.message, 'danger');
    }
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Request';
    }
  }
}

// --------------------------------------------------------------------------
// Direct Block Modal Flow (Administrator Only)
// --------------------------------------------------------------------------

function openDirectBlockModal(domain, clientIp) {
  if (!isAdmin()) {
    // If analyst, fallback seamlessly to request block modal
    if (canRequestBlock()) {
      openRequestBlockModal(domain, clientIp, '');
      return;
    }
    alert('Administrator access is required to block domains directly.');
    return;
  }
  const domInput = document.getElementById('dbModal-domain');
  const ipInput = document.getElementById('dbModal-clientip');
  const ipGroup = document.getElementById('dbModal-ip-group');
  const reasonInput = document.getElementById('dbModal-reason');
  const feedback = document.getElementById('dbModal-feedback');

  if (domInput) domInput.value = domain || '';
  if (ipInput) {
    ipInput.value = clientIp || '';
    if (ipGroup) ipGroup.style.display = clientIp ? 'block' : 'none';
  }
  if (reasonInput) {
    reasonInput.value = '';
    reasonInput.disabled = false;
  }
  if (feedback) {
    feedback.innerHTML = '';
    feedback.style.display = 'none';
  }

  const btn = document.getElementById('dbModal-submit-btn');
  if (btn) {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-ban"></i> Block Domain Now';
  }

  openModal('modal-direct-block');
}

async function submitDirectBlock() {
  const domain = (document.getElementById('dbModal-domain')?.value || '').trim();
  const reason = (document.getElementById('dbModal-reason')?.value || '').trim();
  const feedback = document.getElementById('dbModal-feedback');
  const btn = document.getElementById('dbModal-submit-btn');

  if (!domain) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.color = 'var(--danger)';
      feedback.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i> Domain is required.';
    }
    return;
  }

  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Blocking...';
  }

  try {
    const res = await fetch('/api/blocking/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, reason })
    });
    const data = await res.json();

    if (data.success) {
      if (feedback) {
        feedback.style.display = 'block';
        feedback.style.color = 'var(--success)';
        feedback.innerHTML = `<i class="fa-solid fa-circle-check"></i> ${escapeHtml(data.message || 'Domain blocked successfully.')}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message || 'Domain blocked successfully.', 'success');
      }
      setTimeout(() => {
        closeModal('modal-direct-block');
        refreshActivePageTables();
      }, 700);
    } else {
      if (feedback) {
        feedback.style.display = 'block';
        feedback.style.color = 'var(--danger)';
        feedback.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(data.message || 'Failed to block domain.')}`;
      }
      if (typeof showToast === 'function') {
        showToast(data.message || 'Failed to block domain.', 'danger');
      }
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-ban"></i> Block Domain Now';
      }
    }
  } catch (err) {
    if (feedback) {
      feedback.style.display = 'block';
      feedback.style.color = 'var(--danger)';
      feedback.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i> Network error: ${escapeHtml(err.message)}`;
    }
    if (typeof showToast === 'function') {
      showToast('Network error: ' + err.message, 'danger');
    }
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<i class="fa-solid fa-ban"></i> Block Domain Now';
    }
  }
}

// --------------------------------------------------------------------------
// Table Action Cell Generator (Safe HTML Attribute Encoding)
// --------------------------------------------------------------------------

function renderActionCell(domain, clientIp, detectionInfo, status) {
  if (!domain) return '-';
  const cleanDomain = escapeHtml(String(domain).trim());
  const cleanIp = escapeHtml(String(clientIp || '').trim());
  const cleanInfo = escapeHtml(String(detectionInfo || '').trim());

  if (isAdmin()) {
    return `<button type="button" class="btn btn-outline btn-sm" style="color: var(--brand-danger); border-color: rgba(239,68,68,0.3); font-size: 11px; padding: 3px 8px;" title="Block domain" data-domain="${cleanDomain}" data-ip="${cleanIp}" onclick="handleDirectBlockClick(this)">
      <i class="fa-solid fa-ban"></i> <span>Block</span>
    </button>`;
  } else if (isAnalyst()) {
    return `<button type="button" class="btn btn-outline btn-sm" style="color: var(--brand-warning); border-color: rgba(245,158,11,0.3); font-size: 11px; padding: 3px 8px;" title="Request domain block" data-domain="${cleanDomain}" data-ip="${cleanIp}" data-info="${cleanInfo}" onclick="handleRequestBlockClick(this)">
      <i class="fa-solid fa-shield-halved"></i> <span>Request Block</span>
    </button>`;
  }
  return '<span style="color: var(--text-light); font-size: 11px;">-</span>';
}

function refreshActivePageTables() {
  if (typeof fetchLogs === 'function') fetchLogs(typeof currentPage !== 'undefined' ? currentPage : 1);
  if (typeof fetchWebsiteActivity === 'function') fetchWebsiteActivity(typeof currentWebPage !== 'undefined' ? currentWebPage : 1);
  if (typeof fetchAlerts === 'function') fetchAlerts(typeof currentAlertPage !== 'undefined' ? currentAlertPage : 1);
  if (typeof loadBlockRules === 'function') loadBlockRules();
  if (typeof loadBlockRequests === 'function') loadBlockRequests();
}
