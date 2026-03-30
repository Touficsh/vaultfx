<?php
/**
 * VaultFX — User Management Page (Super Admin only)
 */

RBAC::assertRole(RBAC::SUPER_ADMIN);
$pageTitle = 'User Management';

$users = DB::rows(
    "SELECT u.id, u.username, u.email, u.role, u.can_view_passwords, u.can_manage_managers, u.is_active,
            u.totp_enabled, u.force_password_change, u.last_login_at, u.last_login_ip,
            u.locked_until, u.failed_login_count, u.created_at,
            c.username AS created_by_name,
            COUNT(usa.server_id) AS server_access_count
     FROM users u
     LEFT JOIN users c ON c.id = u.created_by
     LEFT JOIN user_server_access usa ON usa.user_id = u.id
     GROUP BY u.id
     ORDER BY u.created_at DESC"
);

$allServers = DB::rows("SELECT id, name, platform_type FROM servers WHERE is_active = 1 ORDER BY name ASC");

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">User Management</h1>
    <p class="page-subtitle"><?= e(count($users)) ?> users in system</p>
  </div>
  <div class="page-header-actions">
    <button class="btn btn-primary" onclick="openAddUser()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
      Add User
    </button>
  </div>
</div>

<div class="table-container card">
  <table>
    <thead>
      <tr>
        <th>User</th>
        <th>Role</th>
        <th>Servers</th>
        <th>Can Manage</th>
        <th>2FA</th>
        <th>Last Login</th>
        <th>Status</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($users as $u): ?>
      <tr id="user-row-<?= (int)$u['id'] ?>">
        <td>
          <div style="font-weight:600"><?= e($u['username']) ?></div>
          <div class="text-xs text-muted"><?= e($u['email']) ?></div>
          <?php if ($u['force_password_change']): ?>
          <span class="badge badge-warning" style="margin-top:3px">pw change required</span>
          <?php endif; ?>
        </td>
        <td>
          <span class="badge <?= e(RBAC::roleBadgeClass($u['role'])) ?>"><?= e(RBAC::roleLabel($u['role'])) ?></span>
        </td>
        <td>
          <?php if ($u['role'] === 'super_admin'): ?>
          <span class="text-muted text-sm">All</span>
          <?php else: ?>
          <span class="text-sm"><?= (int)$u['server_access_count'] ?> server<?= $u['server_access_count'] != 1 ? 's' : '' ?></span>
          <?php endif; ?>
        </td>
        <td>
          <div style="display:flex;gap:4px;flex-wrap:wrap">
            <?php if ($u['can_view_passwords']): ?>
            <span class="badge" style="font-size:0.7rem;background:rgba(99,102,241,0.15);color:#a5b4fc">View Pwd</span>
            <?php endif; ?>
            <?php if ($u['can_manage_managers']): ?>
            <span class="badge" style="font-size:0.7rem;background:rgba(16,185,129,0.15);color:#6ee7b7">Manager Edit</span>
            <?php endif; ?>
            <?php if (!$u['can_view_passwords'] && !$u['can_manage_managers']): ?>
            <span class="text-muted text-xs">—</span>
            <?php endif; ?>
          </div>
        </td>
        <td>
          <?php if ($u['totp_enabled']): ?>
          <span style="color:var(--success)" title="2FA enabled">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          </span>
          <?php else: ?>
          <span style="color:var(--text-muted)" title="2FA not set up">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
          </span>
          <?php endif; ?>
        </td>
        <td>
          <?php if ($u['last_login_at']): ?>
          <div class="text-sm"><?= e(time_ago($u['last_login_at'])) ?></div>
          <div class="text-xs text-muted font-mono"><?= e($u['last_login_ip'] ?? '—') ?></div>
          <?php else: ?>
          <span class="text-muted text-sm">Never</span>
          <?php endif; ?>
        </td>
        <td>
          <?php if (!$u['is_active']): ?>
          <span class="badge badge-inactive">Inactive</span>
          <?php elseif ($u['locked_until'] && strtotime($u['locked_until']) > time()): ?>
          <span class="badge badge-critical">Locked</span>
          <?php else: ?>
          <span class="badge badge-active">Active</span>
          <?php endif; ?>
        </td>
        <td>
          <div style="display:flex;gap:4px">
            <button class="btn btn-ghost btn-icon btn-sm" title="Edit user"
              onclick="openEditUser(<?= (int)$u['id'] ?>)">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
            </button>
            <button class="btn btn-ghost btn-icon btn-sm" title="Manage server access"
              onclick="openServerAccess(<?= (int)$u['id'] ?>, '<?= e($u['username']) ?>')">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2"></rect><rect x="2" y="14" width="20" height="8" rx="2"></rect></svg>
            </button>
            <button class="btn btn-ghost btn-sm" title="Manager Access" onclick="openManagerAccess(<?= (int)$u['id'] ?>, <?= e(json_encode($u['username'])) ?>)">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 7V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v2"/></svg>
              Managers
            </button>
            <?php if ($u['totp_enabled']): ?>
            <button class="btn btn-ghost btn-icon btn-sm" title="Reset 2FA"
              onclick="reset2FA(<?= (int)$u['id'] ?>, '<?= e($u['username']) ?>')">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
            </button>
            <?php endif; ?>
            <?php if ($u['id'] != Auth::userField('id') && $u['role'] !== 'super_admin'): ?>
            <button class="btn btn-ghost btn-icon btn-sm" title="Delete user" style="color:var(--danger)"
              onclick="deleteUser(<?= (int)$u['id'] ?>, '<?= e($u['username']) ?>')">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path></svg>
            </button>
            <?php endif; ?>
          </div>
        </td>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
</div>

<!-- Add/Edit User Modal -->
<div class="modal-overlay" id="modal-user">
  <div class="modal" style="max-width:600px">
    <div class="modal-header">
      <h3 class="modal-title" id="user-modal-title">Add User</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-user')">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <form id="user-form" autocomplete="off">
        <input type="hidden" id="user-id" name="id" value="0">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Username <span class="required">*</span></label>
            <input type="text" id="user-username" name="username" class="form-control" maxlength="50" autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Email <span class="required">*</span></label>
            <input type="email" id="user-email" name="email" class="form-control" maxlength="255">
          </div>
        </div>
        <div class="form-grid mt-4">
          <div class="form-group">
            <label class="form-label" id="pw-label">Password <span class="required">*</span></label>
            <div class="password-field">
              <input type="password" id="user-password" name="password" class="form-control" autocomplete="new-password" maxlength="255">
              <button type="button" class="password-toggle" onclick="document.getElementById('user-password').type=document.getElementById('user-password').type==='password'?'text':'password'">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              </button>
            </div>
            <div id="pw-hint" class="form-hint">Min 12 chars, upper, lower, digit, special</div>
          </div>
          <div class="form-group">
            <label class="form-label">Role <span class="required">*</span></label>
            <select id="user-role" name="role" class="form-control">
              <option value="viewer">Viewer</option>
              <option value="restricted_viewer">Restricted Viewer</option>
              <option value="admin">Admin</option>
              <option value="super_admin">Super Admin</option>
            </select>
          </div>
        </div>
        <div style="display:flex;gap:20px;margin-top:16px;flex-wrap:wrap">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.875rem">
            <label class="toggle">
              <input type="checkbox" id="user-can-view-pw" name="can_view_passwords" value="1">
              <span class="toggle-slider"></span>
            </label>
            Can view passwords
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.875rem">
            <label class="toggle">
              <input type="checkbox" id="user-can-manage-managers" name="can_manage_managers" value="1">
              <span class="toggle-slider"></span>
            </label>
            Can manage managers
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.875rem">
            <label class="toggle">
              <input type="checkbox" id="user-force-pw" name="force_password_change" value="1">
              <span class="toggle-slider"></span>
            </label>
            Force password change on login
          </label>
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer;font-size:0.875rem">
            <label class="toggle">
              <input type="checkbox" id="user-active" name="is_active" value="1" checked>
              <span class="toggle-slider"></span>
            </label>
            Account active
          </label>
        </div>
        <div id="user-error" class="form-error mt-4" style="display:none"></div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-user')">Cancel</button>
      <button class="btn btn-primary" onclick="saveUser()">
        <span id="user-save-label">Create User</span>
      </button>
    </div>
  </div>
</div>

<!-- Server Access Modal -->
<div class="modal-overlay" id="modal-server-access">
  <div class="modal" style="max-width:520px">
    <div class="modal-header">
      <h3 class="modal-title" id="access-modal-title">Server Access</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-server-access')">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <input type="hidden" id="access-user-id" value="0">
      <p class="text-sm text-muted mb-4">Select which servers this user can access. Super Admins always have access to all servers.</p>
      <div style="display:flex;flex-direction:column;gap:6px;max-height:320px;overflow-y:auto" id="server-checkboxes">
        <?php foreach ($allServers as $srv): ?>
        <label style="display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:8px;cursor:pointer;border:1px solid var(--border);transition:background var(--transition)"
               onmouseover="this.style.background='var(--bg-hover)'" onmouseout="this.style.background=''">
          <input type="checkbox" name="server_ids[]" value="<?= (int)$srv['id'] ?>" class="server-access-cb">
          <span class="badge <?= e(platform_badge_class($srv['platform_type'])) ?>"><?= e($srv['platform_type']) ?></span>
          <span style="font-size:0.875rem"><?= e($srv['name']) ?></span>
        </label>
        <?php endforeach; ?>
        <?php if (empty($allServers)): ?>
        <div class="text-muted text-sm" style="text-align:center;padding:20px">No servers created yet.</div>
        <?php endif; ?>
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-server-access')">Cancel</button>
      <button class="btn btn-primary" onclick="saveServerAccess()">Save Access</button>
    </div>
  </div>
</div>

<!-- Manager Access Modal -->
<div class="modal-overlay" id="modal-manager-access">
  <div class="modal" style="width:520px;max-width:95vw">
    <div class="modal-header">
      <h3 class="modal-title" id="manager-access-title">Manager Access</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-manager-access')" aria-label="Close">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <p class="text-sm text-muted mb-4">Select which manager accounts this user can access directly. These are in addition to any server-level access grants.</p>
      <input type="hidden" id="manager-access-user-id">
      <div id="manager-access-list" style="max-height:400px;overflow-y:auto"></div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-manager-access')">Cancel</button>
      <button class="btn btn-primary" onclick="saveManagerAccess()">Save Manager Access</button>
    </div>
  </div>
</div>

<?php
// Embed user data for JS
$usersJson = json_encode(array_map(fn($u) => [
    'id' => (int)$u['id'],
    'username' => $u['username'],
    'email' => $u['email'],
    'role' => $u['role'],
    'can_view_passwords' => (bool)$u['can_view_passwords'],
    'can_manage_managers' => (bool)$u['can_manage_managers'],
    'is_active' => (bool)$u['is_active'],
    'force_password_change' => (bool)$u['force_password_change'],
], $users), JSON_HEX_TAG | JSON_HEX_AMP);

$inlineJs = <<<JS
const ALL_USERS = {$usersJson};

// Load current server access for a user
async function loadServerAccess(userId) {
  const res = await VaultFX.fetch('api/users.php?action=get-server-access&id=' + userId);
  const grantedIds = res.ok && res.data.success ? (res.data.data.server_ids ?? []) : [];
  document.querySelectorAll('.server-access-cb').forEach(cb => {
    cb.checked = grantedIds.includes(parseInt(cb.value));
  });
}

function openAddUser() {
  document.getElementById('user-id').value       = '0';
  document.getElementById('user-username').value = '';
  document.getElementById('user-email').value    = '';
  document.getElementById('user-password').value = '';
  document.getElementById('user-role').value     = 'viewer';
  document.getElementById('user-can-view-pw').checked        = false;
  document.getElementById('user-can-manage-managers').checked = false;
  document.getElementById('user-force-pw').checked            = false;
  document.getElementById('user-active').checked              = true;
  document.getElementById('user-modal-title').textContent = 'Add User';
  document.getElementById('user-save-label').textContent  = 'Create User';
  document.getElementById('pw-label').innerHTML = 'Password <span class="required">*</span>';
  document.getElementById('pw-hint').textContent = 'Min 12 chars, upper, lower, digit, special';
  document.getElementById('user-username').disabled = false;
  document.getElementById('user-error').style.display = 'none';
  VaultFX.openModal('modal-user');
}

function openEditUser(id) {
  const u = ALL_USERS.find(x => x.id === id);
  if (!u) return;
  document.getElementById('user-id').value       = u.id;
  document.getElementById('user-username').value = u.username;
  document.getElementById('user-username').disabled = true;
  document.getElementById('user-email').value    = u.email;
  document.getElementById('user-password').value = '';
  document.getElementById('user-role').value     = u.role;
  document.getElementById('user-can-view-pw').checked        = u.can_view_passwords;
  document.getElementById('user-can-manage-managers').checked = u.can_manage_managers;
  document.getElementById('user-force-pw').checked            = u.force_password_change;
  document.getElementById('user-active').checked              = u.is_active;
  document.getElementById('user-modal-title').textContent = 'Edit User: ' + u.username;
  document.getElementById('user-save-label').textContent  = 'Update User';
  document.getElementById('pw-label').innerHTML = 'New Password <span style="color:var(--text-muted);font-weight:400">(leave blank to keep current)</span>';
  document.getElementById('pw-hint').textContent = '';
  document.getElementById('user-error').style.display = 'none';
  VaultFX.openModal('modal-user');
}

async function saveUser() {
  const id  = document.getElementById('user-id').value;
  const errEl = document.getElementById('user-error');
  errEl.style.display = 'none';

  const fd = new FormData(document.getElementById('user-form'));
  if (!document.getElementById('user-can-view-pw').checked)        fd.set('can_view_passwords', '0');
  if (!document.getElementById('user-can-manage-managers').checked) fd.set('can_manage_managers', '0');
  if (!document.getElementById('user-force-pw').checked)            fd.set('force_password_change', '0');
  if (!document.getElementById('user-active').checked)              fd.set('is_active', '0');

  const action = id === '0' ? 'create' : 'edit';
  const res    = await VaultFX.postForm('api/users.php?action=' + action, fd);

  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-user');
    VaultFX.toast('success', res.data.message);
    setTimeout(() => location.reload(), 600);
  } else {
    const errs = res.data.errors ?? {};
    errEl.textContent = Object.values(errs)[0] || res.data.message || 'Failed to save user.';
    errEl.style.display = 'block';
  }
}

async function openServerAccess(userId, username) {
  document.getElementById('access-user-id').value = userId;
  document.getElementById('access-modal-title').textContent = 'Server Access — ' + username;
  await loadServerAccess(userId);
  VaultFX.openModal('modal-server-access');
}

async function saveServerAccess() {
  const userId    = document.getElementById('access-user-id').value;
  const serverIds = Array.from(document.querySelectorAll('.server-access-cb:checked')).map(cb => cb.value);
  const fd = new FormData();
  serverIds.forEach(id => fd.append('server_ids[]', id));
  fd.set('id', userId);

  const res = await VaultFX.postForm('api/users.php?action=assign-servers', fd);
  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-server-access');
    VaultFX.toast('success', 'Server access updated.');
    setTimeout(() => location.reload(), 600);
  } else {
    VaultFX.toast('error', res.data.message ?? 'Failed to update access.');
  }
}

async function reset2FA(userId, username) {
  const ok = await VaultFX.confirm({
    title: 'Reset 2FA',
    message: 'This will disable two-factor authentication for ' + username + '. They will need to re-enroll on next login.',
    confirmText: 'Reset 2FA',
    confirmClass: 'btn-danger',
  });
  if (!ok) return;
  const fd = new FormData();
  fd.set('id', userId);
  const res = await VaultFX.postForm('api/users.php?action=toggle-2fa-reset', fd);
  VaultFX.toast(res.data.success ? 'success' : 'error', res.data.message);
  if (res.data.success) setTimeout(() => location.reload(), 600);
}

async function deleteUser(userId, username) {
  const ok = await VaultFX.confirm({
    title: 'Deactivate User',
    message: 'Deactivate user "' + username + '"? They will no longer be able to log in.',
    confirmText: 'Deactivate',
    confirmClass: 'btn-danger',
    requireTyping: 'DELETE',
  });
  if (!ok) return;
  const fd = new FormData();
  fd.set('id', userId);
  fd.set('confirm', 'DELETE');
  const res = await VaultFX.postForm('api/users.php?action=delete', fd);
  VaultFX.toast(res.data.success ? 'success' : 'error', res.data.message);
  if (res.data.success) setTimeout(() => location.reload(), 600);
}

async function openManagerAccess(userId, username) {
  document.getElementById('manager-access-title').textContent = 'Manager Access — ' + username;
  document.getElementById('manager-access-user-id').value = userId;
  document.getElementById('manager-access-list').innerHTML = '<div class="text-muted text-sm" style="padding:16px">Loading…</div>';
  VaultFX.openModal('modal-manager-access');

  const res = await VaultFX.fetch('/api/users.php?action=get-manager-access&id=' + userId);
  if (!res.ok || !res.data.success) { VaultFX.toast('error', res.data.message || 'Failed to load manager access.'); return; }

  const managers = res.data.data.managers;
  const assignedIds = res.data.data.assigned_ids;

  if (managers.length === 0) {
    document.getElementById('manager-access-list').innerHTML = '<div class="text-muted text-sm" style="padding:16px">No manager accounts found.</div>';
    return;
  }

  // Group by server
  const byServer = {};
  managers.forEach(m => {
    const key = m.server_name;
    if (!byServer[key]) byServer[key] = { platform: m.platform_type, managers: [] };
    byServer[key].managers.push(m);
  });

  let html = '';
  for (const [serverName, group] of Object.entries(byServer)) {
    html += '<div style="margin-bottom:16px">'
          + '<div style="font-size:0.75rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;padding-bottom:4px;border-bottom:1px solid var(--border)">'
          + VaultFX.escapeHtml(serverName)
          + ' <span class="badge" style="margin-left:4px">' + VaultFX.escapeHtml(group.platform) + '</span>'
          + '</div>';
    group.managers.forEach(function(m) {
      const checked = assignedIds.includes(m.id);
      html += '<label style="display:flex;align-items:center;gap:10px;padding:8px 0;cursor:pointer;border-bottom:1px solid var(--border-subtle)">'
            + '<input type="checkbox" name="manager_ids[]" value="' + m.id + '" ' + (checked ? 'checked' : '') + ' style="width:16px;height:16px;accent-color:var(--primary)">'
            + '<div>'
            + '<div style="font-weight:500;font-size:0.875rem">' + VaultFX.escapeHtml(m.label) + '</div>'
            + '<div class="text-xs text-muted font-mono">Login: ' + VaultFX.escapeHtml(m.login_number) + '</div>'
            + '</div>'
            + '</label>';
    });
    html += '</div>';
  }
  document.getElementById('manager-access-list').innerHTML = html;
}

async function saveManagerAccess() {
  const userId = document.getElementById('manager-access-user-id').value;
  const checkboxes = document.querySelectorAll('#manager-access-list input[type=checkbox]:checked');
  const managerIds = Array.from(checkboxes).map(cb => cb.value);

  const form = new FormData();
  form.append('id', userId);
  managerIds.forEach(id => form.append('manager_ids[]', id));

  const res = await VaultFX.postForm('/api/users.php?action=assign-managers', form);
  if (res.ok && res.data.success) {
    VaultFX.toast('success', res.data.message);
    VaultFX.closeModal('modal-manager-access');
    setTimeout(() => location.reload(), 600);
  } else {
    VaultFX.toast('error', res.data.message || 'Failed to update manager access.');
  }
}
JS;

include WEB_ROOT . '/includes/footer.php';
?>
