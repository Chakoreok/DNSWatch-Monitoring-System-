// ==========================================================================
// DNSWatch Devices Controller
// ==========================================================================

let devicesSearchTimeout = null;

document.addEventListener('DOMContentLoaded', () => {
  fetchDevices();
  // Auto refresh periodically
  setInterval(() => {
    fetchDevices();
  }, 10000);

  document.addEventListener('monitoringStateChanged', () => {
    fetchDevices();
  });

  // Listen to live DNS stream to update devices table in real-time
  document.addEventListener('liveDnsLog', () => {
    if (!devicesSearchTimeout) {
      devicesSearchTimeout = setTimeout(() => {
        devicesSearchTimeout = null;
        fetchDevices();
      }, 4000);
    }
  });
});

function debounceDevicesSearch() {
  clearTimeout(devicesSearchTimeout);
  devicesSearchTimeout = setTimeout(fetchDevices, 300);
}

async function fetchDevices() {
  const searchInput = document.getElementById('devices-search-input');
  const search = searchInput ? searchInput.value.trim() : '';
  const statusFilter = document.getElementById('devices-status-filter');
  const status = statusFilter ? statusFilter.value : 'ALL';
  const typeFilterEl = document.getElementById('devices-type-filter');
  const typeFilter = typeFilterEl ? typeFilterEl.value : '';

  const url = new URL('/api/devices', window.location.origin);
  if (search) url.searchParams.set('search', search);
  if (status && status !== 'ALL') url.searchParams.set('status', status);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('devices-tbody');
    if (!tbody) return;

    if (data.success) {
      const totalEl = document.getElementById('dev-cnt-total');
      if (totalEl) totalEl.textContent = data.total_devices || 0;

      const activeEl = document.getElementById('dev-cnt-active');
      if (activeEl) activeEl.textContent = data.active_devices || 0;

      const inactiveEl = document.getElementById('dev-cnt-inactive');
      if (inactiveEl) inactiveEl.textContent = data.inactive_devices || 0;

      const queriesEl = document.getElementById('dev-cnt-queries');
      if (queriesEl) queriesEl.textContent = Number(data.total_queries || 0).toLocaleString();

      // Count portal visitors for badge
      const portalCount = (data.devices || []).filter(d => (d.device_type || '').includes('Portal') || (d.device_name || '').includes('Portal')).length;
      const portalBadge = document.getElementById('dev-cnt-portal');
      if (portalBadge) portalBadge.textContent = portalCount;

      // Apply client-side type filter
      let devices = data.devices || [];
      if (typeFilter === 'portal') {
        devices = devices.filter(d => (d.device_type || '').includes('Portal') || (d.device_name || '').includes('Portal'));
      } else if (typeFilter === 'dns') {
        devices = devices.filter(d => !(d.device_type || '').includes('Portal') && !(d.device_name || '').includes('Portal'));
      }

      if (devices.length > 0) {
        tbody.innerHTML = devices.map(dev => {
          const dtype = (dev.device_type || '').toLowerCase();
          const isPortalVisitor = dtype.includes('portal');

          // Build device type icon
          let typeIcon;
          if (isPortalVisitor) {
            // Special portal visitor styling
            let osIcon = 'fa-solid fa-globe';
            let osColor = 'var(--brand-purple)';
            if (dtype.includes('android'))       { osIcon = 'fa-brands fa-android'; osColor = '#34d399'; }
            else if (dtype.includes('ios'))      { osIcon = 'fa-brands fa-apple';   osColor = '#cbd5e1'; }
            else if (dtype.includes('windows'))  { osIcon = 'fa-brands fa-windows'; osColor = '#38bdf8'; }
            else if (dtype.includes('macos'))    { osIcon = 'fa-brands fa-apple';   osColor = '#cbd5e1'; }
            else if (dtype.includes('linux'))    { osIcon = 'fa-brands fa-linux';   osColor = '#fbbf24'; }
            typeIcon = `<span style="display:inline-flex;align-items:center;gap:6px;">
              <i class="${osIcon}" style="color:${osColor}"></i>
              <span style="color:var(--brand-purple);font-weight:600;font-size:12px;">${dev.device_type}</span>
            </span>`;
          } else if (dtype.includes('android') || dtype.includes('mobile')) {
            typeIcon = '<i class="fa-brands fa-android" style="color:#34d399"></i> Android';
          } else if (dtype.includes('apple') || dtype.includes('ios') || dtype.includes('mac')) {
            typeIcon = '<i class="fa-brands fa-apple" style="color:#cbd5e1"></i> Apple';
          } else if (dtype.includes('windows')) {
            typeIcon = '<i class="fa-brands fa-windows" style="color:#38bdf8"></i> Windows';
          } else if (dtype.includes('linux')) {
            typeIcon = '<i class="fa-brands fa-linux" style="color:#fbbf24"></i> Linux';
          } else {
            typeIcon = '<i class="fa-solid fa-network-wired" style="color:var(--text-light)"></i> ' + (dev.device_type || 'Client Host');
          }

          const statBadge = (dev.status || 'Active').toLowerCase() === 'active'
            ? '<span class="badge badge-safe"><i class="fa-solid fa-circle-check"></i> Active</span>'
            : '<span class="badge" style="background:var(--bg-surface-elevated); color:var(--text-light);"><i class="fa-solid fa-power-off"></i> Inactive</span>';

          const clientIp = dev.ip_address || dev.client_ip;

          // Portal visitors get a glowing row highlight and special name icon
          const nameIcon = isPortalVisitor
            ? `<i class="fa-solid fa-eye" style="color:var(--brand-purple); margin-right:6px;" title="Web Portal Visitor"></i>`
            : `<i class="fa-solid fa-laptop" style="color:var(--brand-primary); margin-right:6px;"></i>`;

          const rowStyle = isPortalVisitor
            ? 'style="border-left: 3px solid var(--brand-purple);"'
            : '';

          // DNS logs button — portal visitors may have no logs
          const logsBtn = isPortalVisitor
            ? `<span style="color:var(--text-muted);font-size:11.5px;font-style:italic;">Portal Access</span>`
            : `<a href="/dns-logs?search=${encodeURIComponent(clientIp)}" class="btn btn-outline btn-sm" title="View Query Stream for this Device">
                <i class="fa-solid fa-arrow-up-right-from-square"></i> Logs
               </a>`;

          return `
            <tr ${rowStyle}>
              <td style="font-weight: 600; color: var(--text-main);">
                ${nameIcon}${dev.device_name}
              </td>
              <td>
                <span class="ip-chip" onclick="copyToClipboard('${clientIp}', 'Client IP')" title="Click to copy IP">
                  ${clientIp} <i class="fa-regular fa-copy"></i>
                </span>
              </td>
              <td style="font-family: var(--font-mono); font-size: 11.5px; color: var(--text-muted);">${dev.mac_address || '-'}</td>
              <td>${typeIcon}</td>
              <td style="font-weight: 700; font-family: var(--font-mono); color: var(--text-main);">${Number(dev.dns_queries || 0).toLocaleString()}</td>
              <td style="color: var(--text-muted); font-size: 11.5px; font-family: var(--font-mono);">${dev.last_seen || '-'}</td>
              <td>${statBadge}</td>
              <td>${logsBtn}</td>
            </tr>
          `;
        }).join('');

        document.getElementById('devices-counter-info').textContent = `Showing ${devices.length} of ${data.total_devices} devices`;
      } else {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 40px;">
              <i class="fa-solid fa-laptop-file" style="font-size: 24px; margin-bottom: 8px; color: var(--text-light);"></i>
              <div>No client devices found matching filter criteria.</div>
            </td>
          </tr>
        `;
        document.getElementById('devices-counter-info').textContent = 'Showing 0 devices';
      }
    }
  } catch (err) {
    console.error('Error fetching devices:', err);
  }
}

