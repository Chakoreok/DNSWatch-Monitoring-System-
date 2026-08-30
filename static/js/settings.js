// ==========================================================================
// DNSWatch Settings Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  loadNetworkInterfaces();
  loadUsers();
});

async function loadNetworkInterfaces() {
  try {
    const res = await fetch('/api/monitoring/interfaces');
    const data = await res.json();
    const select = document.getElementById('settings-iface-select');

    if (data.success && data.interfaces && data.interfaces.length > 0) {
      select.innerHTML = '<option value="">Auto-Detect / All Interfaces</option>' +
        data.interfaces.map(iface => {
          const ipStr = iface.ip ? ` (${iface.ip})` : '';
          return `<option value="${iface.name}">${iface.description || iface.name}${ipStr}</option>`;
        }).join('');
    }
  } catch (err) {
    console.error('Error loading interfaces:', err);
  }
}

async function loadUsers() {
  try {
    const res = await fetch('/api/users');
    const data = await res.json();
    const tbody = document.getElementById('users-tbody');

    if (data.success && data.users && data.users.length > 0) {
      tbody.innerHTML = data.users.map(u => {
        const roleBadge = u.role.toLowerCase() === 'administrator'
          ? '<span class="badge" style="background:#fee2e2; color:#991b1b; font-weight:700;">Administrator</span>'
          : (u.role.toLowerCase() === 'security analyst' 
             ? '<span class="badge" style="background:#fef3c7; color:#92400e; font-weight:600;">Security Analyst</span>'
             : '<span class="badge" style="background:#f1f5f9; color:#64748b;">Viewer</span>');

        return `
          <tr>
            <td style="font-weight: 600;">${u.username}</td>
            <td>${u.full_name || '-'}</td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${u.email}</td>
            <td>${roleBadge}</td>
            <td><span class="badge badge-safe">${u.status}</span></td>
            <td style="color: var(--text-muted); font-size: 11.5px;">${u.created_at || '-'}</td>
          </tr>
        `;
      }).join('');
    } else {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 25px;">No users found.</td></tr>';
    }
  } catch (err) {
    console.error('Error loading users:', err);
  }
}

function openCreateUserModal() {
  document.getElementById('form-create-user').reset();
  document.getElementById('modal-create-user').classList.add('show');
}

async function submitCreateUser(e) {
  e.preventDefault();
  const payload = {
    username: document.getElementById('input-new-username').value.trim(),
    full_name: document.getElementById('input-new-fullname').value.trim(),
    email: document.getElementById('input-new-email').value.trim(),
    password: document.getElementById('input-new-password').value.trim(),
    role_id: parseInt(document.getElementById('input-new-role').value)
  };

  try {
    const res = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (data.success) {
      closeModal('modal-create-user');
      loadUsers();
    } else {
      alert('Error creating user: ' + data.message);
    }
  } catch (err) {
    console.error('Error submitting user creation:', err);
  }
}

function saveCaptureSettings() {
  const selectedIface = document.getElementById('settings-iface-select').value;
  alert(`Interface selection saved: ${selectedIface || 'Auto-Detect'}. Active when monitoring starts.`);
}

async function clearAllData() {
  if (!confirm("Are you sure you want to completely clear all recorded DNS logs, security alerts, devices, and website activity?")) return;
  try {
    const res = await fetch('/api/monitoring/clear', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const data = await res.json();
    if (data.success) {
      alert("All sample activity data has been successfully cleared!");
      window.location.href = '/dashboard';
    } else {
      alert("Error: " + data.message);
    }
  } catch (err) {
    console.error("Error clearing data:", err);
    alert("Failed to clear data: " + err.message);
  }
}
