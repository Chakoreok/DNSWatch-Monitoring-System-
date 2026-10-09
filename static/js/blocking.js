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
  if (!btn || btn.disabled) return;
  const domain = btn.getAttribute('data-domain') || '';
  const ip = btn.getAttribute('data-ip') || '';
  const reason = btn.getAttribute('data-reason') || (ip ? `Blocked for client IP ${ip}` : 'Manual block from table');
  if (!domain) return;

  // Execute directly on the clicked button with loading animation & row removal
  executeDomainBlock(btn, domain, { reason });
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

  await executeDomainBlock(btn, domain, {
    reason: reason,
    onSuccess: () => {
      setTimeout(() => {
        closeModal('modal-direct-block');
        refreshActivePageTables();
      }, 500);
    }
  });
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
  if (typeof loadBlockRules === 'function') loadBlockRules();
  if (typeof loadBlockRequests === 'function') loadBlockRequests();
}

// ==========================================================================
// Domain Block Enforcement Cyber Animation
// ==========================================================================

let _domainBlockAnimTimer = null;

function playBlockSoundEffect() {
  try {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const now = ctx.currentTime;
    
    // Sub-bass impact oscillator
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sawtooth';
    osc.frequency.setValueAtTime(140, now);
    osc.frequency.exponentialRampToValueAtTime(32, now + 0.28);
    
    gain.gain.setValueAtTime(0.18, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
    
    // Cyber shimmer oscillator
    const shimmer = ctx.createOscillator();
    const shimmerGain = ctx.createGain();
    shimmer.type = 'sine';
    shimmer.frequency.setValueAtTime(720, now);
    shimmer.frequency.exponentialRampToValueAtTime(220, now + 0.16);
    shimmerGain.gain.setValueAtTime(0.07, now);
    shimmerGain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
    
    osc.connect(gain);
    gain.connect(ctx.destination);
    shimmer.connect(shimmerGain);
    shimmerGain.connect(ctx.destination);
    
    osc.start(now);
    shimmer.start(now);
    osc.stop(now + 0.36);
    shimmer.stop(now + 0.22);
  } catch (e) {
    // Gracefully ignore audio restrictions
  }
}

function triggerDomainBlockAnimation(domain, options = {}) {
  const cleanDomain = String(domain || '').trim().toLowerCase().replace(/\.+$/, '');
  const reason = options.reason || 'Tier-0 Sinkhole Policy Enforcement';

  // 1. Futuristic cyber synthesizer sound effect
  playBlockSoundEffect();

  // 2. Populate HUD elements
  const overlay = document.getElementById('domain-block-overlay');
  const domainEl = document.getElementById('hud-blocked-domain');
  const reasonEl = document.getElementById('hud-blocked-reason');

  if (domainEl) domainEl.textContent = cleanDomain;
  if (reasonEl) reasonEl.textContent = reason;

  if (overlay) {
    if (_domainBlockAnimTimer) {
      clearTimeout(_domainBlockAnimTimer);
      _domainBlockAnimTimer = null;
    }
    overlay.classList.add('active');

    // 3. Highlight / pulse Blocked DNS in sidebar
    const blockedNav = document.querySelector('a[href*="/blocked-dns"]');
    if (blockedNav) {
      blockedNav.classList.add('nav-link-pulse');
      setTimeout(() => blockedNav.classList.remove('nav-link-pulse'), 2500);
    }

    // 4. Auto-dismiss HUD smoothly
    _domainBlockAnimTimer = setTimeout(() => {
      dismissDomainBlockAnimation();
    }, 1800);
  }
}

function dismissDomainBlockAnimation() {
  const overlay = document.getElementById('domain-block-overlay');
  if (overlay) {
    overlay.classList.remove('active');
  }
  if (_domainBlockAnimTimer) {
    clearTimeout(_domainBlockAnimTimer);
    _domainBlockAnimTimer = null;
  }
}

// ==========================================================================
// Central Universal Domain Blocking Engine
// ==========================================================================

async function executeDomainBlock(buttonElement, domain, options = {}) {
  if (!domain) return false;
  const cleanDomain = String(domain).trim().toLowerCase().replace(/\.+$/, '');
  const reason = options.reason || 'Manual block from table';

  // 1. Loading Animation on the Button
  let originalHtml = '';
  let originalClass = '';
  if (buttonElement) {
    originalHtml = buttonElement.innerHTML;
    originalClass = buttonElement.className;
    buttonElement.disabled = true;
    buttonElement.className = (originalClass ? originalClass + ' ' : '') + 'btn-blocking';
    buttonElement.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Blocking...';
  }

  try {
    // 2. Call backend API to enforce block in database
    const res = await fetch('/api/blocking/rules', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain: cleanDomain, reason: reason })
    });
    const data = await res.json();

    if (data.success) {
      // 3. Short "Blocked Successfully" Animation on Button
      if (buttonElement) {
        buttonElement.className = 'btn btn-sm btn-blocked-success';
        buttonElement.innerHTML = '<i class="fa-solid fa-check"></i> Blocked Successfully';
      }

      // Trigger Cyber HUD overlay animation
      if (typeof triggerDomainBlockAnimation === 'function') {
        triggerDomainBlockAnimation(cleanDomain, { reason });
      }

      // 4. Smoothly remove domain from current list (disappears completely, NOT left with BLOCKED status)
      setTimeout(() => {
        removeDomainRowsFromCurrentPage(cleanDomain);
        if (typeof options.onSuccess === 'function') {
          options.onSuccess(data);
        }
      }, 500);

      if (typeof showToast === 'function') {
        showToast(data.message || `Domain '${cleanDomain}' blocked and moved to Blocked DNS`, 'success');
      }

      // Refresh Blocked DNS tables if on Blocked DNS / Settings view
      if (typeof loadBlockRules === 'function') {
        setTimeout(loadBlockRules, 600);
      }

      return true;
    } else {
      // 5. Backend reported error (e.g. duplicate block rule)
      if (buttonElement) {
        buttonElement.disabled = false;
        buttonElement.className = originalClass;
        buttonElement.innerHTML = originalHtml;
      }

      if (typeof showToast === 'function') {
        showToast(data.message || `Failed to block domain '${cleanDomain}'`, 'warning');
      }

      if (typeof options.onError === 'function') {
        options.onError(data);
      }

      return false;
    }
  } catch (err) {
    console.error('Error executing domain block:', err);
    if (buttonElement) {
      buttonElement.disabled = false;
      buttonElement.className = originalClass;
      buttonElement.innerHTML = originalHtml;
    }

    if (typeof showToast === 'function') {
      showToast(`Network error: ${err.message}`, 'danger');
    }

    if (typeof options.onError === 'function') {
      options.onError(err);
    }

    return false;
  }
}

function removeDomainRowsFromCurrentPage(domain) {
  if (!domain) return;
  const lowerDomain = domain.toLowerCase().trim();

  // If on Blocked DNS page itself, do not remove the row
  if (window.location.pathname.includes('/blocked-dns')) return;

  const rows = document.querySelectorAll('table tbody tr');
  let removedCount = 0;

  rows.forEach(tr => {
    const dataDomain = (tr.getAttribute('data-domain') || '').toLowerCase().trim();
    let isMatch = (dataDomain === lowerDomain);

    if (!isMatch) {
      const cells = tr.querySelectorAll('td');
      for (let i = 0; i < Math.min(cells.length, 3); i++) {
        const txt = cells[i].textContent.toLowerCase().trim();
        if (txt === lowerDomain || txt.split(/\s+/).includes(lowerDomain)) {
          isMatch = true;
          break;
        }
      }
    }

    if (isMatch) {
      tr.classList.add('row-disappear');
      removedCount++;
      setTimeout(() => {
        if (tr.parentNode) {
          tr.parentNode.removeChild(tr);
        }
      }, 480);
    }
  });

  // Update in-memory threat cache if on threat detection page
  if (typeof cachedDomains !== 'undefined' && Array.isArray(cachedDomains)) {
    cachedDomains = cachedDomains.filter(d => (d.domain || '').toLowerCase().trim() !== lowerDomain);
  }

  // Decrement counters on page if present
  const countBadge = document.getElementById('malicious-domains-count-badge');
  if (countBadge && removedCount > 0) {
    const current = parseInt(countBadge.textContent.replace(/[^0-9]/g, '')) || 0;
    if (current >= removedCount) {
      countBadge.textContent = `${(current - removedCount).toLocaleString()} Domains`;
    }
  }
  const counterBar = document.getElementById('collapsed-domains-counter');
  if (counterBar && removedCount > 0) {
    const current = parseInt(counterBar.textContent.replace(/[^0-9]/g, '')) || 0;
    if (current >= removedCount) {
      counterBar.textContent = `${(current - removedCount).toLocaleString()} domains`;
    }
  }
}

// Expose on window
window.executeDomainBlock = executeDomainBlock;
window.removeDomainRowsFromCurrentPage = removeDomainRowsFromCurrentPage;
window.triggerDomainBlockAnimation = triggerDomainBlockAnimation;
window.dismissDomainBlockAnimation = dismissDomainBlockAnimation;

