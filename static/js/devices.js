// ==========================================================================
// DNSWatch Devices Controller
// ==========================================================================

let devicesSearchTimeout = null;

document.addEventListener('DOMContentLoaded', () => {
  fetchDevices();
  // Auto refresh periodically when monitoring is active
  setInterval(() => {
    if (globalMonitoringActive) {
      fetchDevices();
    }
  }, 3000);

  document.addEventListener('monitoringStateChanged', () => {
    fetchDevices();
  });
});

function debounceDevicesSearch() {
  clearTimeout(devicesSearchTimeout);
  devicesSearchTimeout = setTimeout(fetchDevices, 300);
}

async function fetchDevices() {
  const search = document.getElementById('devices-search-input').value.trim();
  const status = document.getElementById('devices-status-filter').value;

  const url = new URL('/api/devices', window.location.origin);
  if (search) url.searchParams.set('search', search);
  if (status && status !== 'ALL') url.searchParams.set('status', status);

  try {
    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById('devices-tbody');

    if (data.success) {
      document.getElementById('dev-cnt-total').textContent = data.total_devices || 0;
      document.getElementById('dev-cnt-active').textContent = data.active_devices || 0;
      document.getElementById('dev-cnt-inactive').textContent = data.inactive_devices || 0;
      document.getElementById('dev-cnt-queries').textContent = Number(data.total_queries || 0).toLocaleString();

      if (data.devices && data.devices.length > 0) {
        tbody.innerHTML = data.devices.map(dev => {
          let typeIcon = '<i class="fa-solid fa-desktop" style="color:#2563EB"></i> Workstation';
          const dtype = (dev.device_type || '').toLowerCase();
          if (dtype.includes('android') || dtype.includes('mobile')) {
            typeIcon = '<i class="fa-brands fa-android" style="color:#10B981"></i> Android';
          } else if (dtype.includes('apple') || dtype.includes('ios') || dtype.includes('mac')) {
            typeIcon = '<i class="fa-brands fa-apple" style="color:#64748B"></i> Apple';
          } else if (dtype.includes('windows')) {
            typeIcon = '<i class="fa-brands fa-windows" style="color:#00A4EF"></i> Windows';
          } else {
            typeIcon = '<i class="fa-solid fa-network-wired" style="color:#64748B"></i> ' + (dev.device_type || 'Host');
          }

          const statBadge = (dev.status || 'Active').toLowerCase() === 'active'
            ? '<span class="badge badge-safe">Active</span>'
            : '<span class="badge" style="background:#f1f5f9; color:#64748b;">Inactive</span>';

          return `
            <tr>
              <td style="font-weight: 600;">${dev.device_name}</td>
              <td style="font-family: monospace; font-size: 12px; font-weight: 500;">${dev.ip_address || dev.client_ip}</td>
              <td style="font-family: monospace; font-size: 11.5px; color: var(--text-muted);">${dev.mac_address || '-'}</td>
              <td>${typeIcon}</td>
              <td style="font-weight: 600;">${Number(dev.dns_queries || 0).toLocaleString()}</td>
              <td style="color: var(--text-muted); font-size: 11.5px;">${dev.last_seen || '-'}</td>
              <td>${statBadge}</td>
              <td>
                <a href="/dns-logs?search=${encodeURIComponent(dev.ip_address || dev.client_ip)}" class="btn-icon" title="View Device DNS Logs">
                  <i class="fa-regular fa-eye"></i>
                </a>
              </td>
            </tr>
          `;
        }).join('');

        document.getElementById('devices-counter-info').textContent = `Showing 1 to ${data.devices.length} of ${data.total_devices} devices`;
      } else {
        tbody.innerHTML = `
          <tr>
            <td colspan="8" style="text-align: center; color: var(--text-muted); padding: 35px;">
              No client devices found matching filter criteria.
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
