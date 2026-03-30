<?php
/**
 * VaultFX — Users Management API (Super Admin only)
 * ===================================================
 * POST /api/users.php?action=list|create|edit|delete|toggle-2fa|assign-servers|setup-2fa
 */

define('VAULTFX_BOOT', true);
require_once dirname(__DIR__, 2) . '/config/config.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', PHP_ERROR_LOG);

require_once dirname(__DIR__) . '/includes/helpers.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/session.php';
require_once dirname(__DIR__) . '/includes/csrf.php';
require_once dirname(__DIR__) . '/includes/validation.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/encryption.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();
Auth::requireApi();

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

// ── set-theme: any authenticated user can update their own theme ──
if ($action === 'set-theme') {
    $theme  = post('theme');
    $userId = (int)Auth::userField('id');
    if (in_array($theme, ['dark', 'light', 'system'])) {
        DB::execute("UPDATE users SET theme_preference = ? WHERE id = ?", [$theme, $userId]);
    }
    json_success([], 'Theme updated.');
}

RBAC::assertRole(RBAC::SUPER_ADMIN, true);

switch ($action) {

    case 'list':
        $users = DB::rows(
            "SELECT u.id, u.username, u.email, u.role, u.can_view_passwords, u.can_manage_managers, u.is_active,
                    u.totp_enabled, u.force_password_change, u.last_login_at, u.last_login_ip,
                    u.locked_until, u.failed_login_count, u.created_at,
                    c.username AS created_by_username,
                    COUNT(usa.server_id) AS server_access_count
             FROM users u
             LEFT JOIN users c ON c.id = u.created_by
             LEFT JOIN user_server_access usa ON usa.user_id = u.id
             GROUP BY u.id
             ORDER BY u.created_at DESC"
        );

        foreach ($users as &$u) {
            unset($u['password_hash']); // Never expose hashes
        }

        json_success(['users' => $users]);
        break;

    case 'create':
        $username   = post('username');
        $email      = post('email');
        $password   = post('password');
        $role       = post('role');
        $canViewPw  = post('can_view_passwords') === '1' ? 1 : 0;
        $canMgr     = post('can_manage_managers') === '1' ? 1 : 0;
        $serverIds  = $_POST['server_ids'] ?? [];

        $v = new Validation();
        $v->required('username', $username, 'Username')
          ->username('username', $username)
          ->required('email', $email, 'Email')
          ->email('email', $email)
          ->required('password', $password, 'Password')
          ->strongPassword('password', $password)
          ->required('role', $role, 'Role')
          ->inEnum('role', $role, RBAC::allRoles(), 'Role');

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        // Check uniqueness
        $exists = DB::scalar("SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1", [$username, $email]);
        if ($exists) {
            json_error('Username or email already exists.', 409);
        }

        $hash   = password_hash($password, PASSWORD_ARGON2ID);
        $userId = (int)Auth::userField('id');

        DB::beginTransaction();
        try {
            DB::execute(
                "INSERT INTO users (username, email, password_hash, role, can_view_passwords, can_manage_managers,
                                    is_active, force_password_change, password_changed_at, created_by)
                 VALUES (?, ?, ?, ?, ?, ?, 1, 0, NOW(), ?)",
                [$username, $email, $hash, $role, $canViewPw, $canMgr, $userId]
            );

            $newUserId = (int)DB::lastInsertId();

            // Assign server access
            if (!empty($serverIds) && in_array($role, [RBAC::ADMIN, RBAC::VIEWER, RBAC::RESTRICTED_VIEWER])) {
                foreach ($serverIds as $sid) {
                    $sid = (int)$sid;
                    if ($sid > 0) {
                        DB::execute(
                            "INSERT IGNORE INTO user_server_access (user_id, server_id, granted_by) VALUES (?, ?, ?)",
                            [$newUserId, $sid, $userId]
                        );
                    }
                }
            }

            DB::commit();
        } catch (Exception $e) {
            DB::rollBack();
            app_log('error', 'User create failed: ' . $e->getMessage());
            json_error('Failed to create user. Please try again.', 500);
        }

        Audit::log($userId, Audit::USER_CREATE, 'user', $newUserId, [
            'username' => $username,
            'role'     => $role,
        ]);

        json_success(['id' => $newUserId], 'User created successfully.');
        break;

    case 'edit':
        $targetId  = param_int('id', 0, $_POST);
        $email     = post('email');
        $role      = post('role');
        $canViewPw = post('can_view_passwords') === '1' ? 1 : 0;
        $canMgr    = post('can_manage_managers') === '1' ? 1 : 0;
        $isActive  = post('is_active') === '1' ? 1 : 0;
        $forcePwCh = post('force_password_change') === '1' ? 1 : 0;
        $password  = post('password'); // Optional: only set if changing

        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        $target = DB::row("SELECT * FROM users WHERE id = ?", [$targetId]);
        if (!$target) {
            json_error('User not found.', 404);
        }

        $v = new Validation();
        $v->required('email', $email, 'Email')
          ->email('email', $email)
          ->required('role', $role, 'Role')
          ->inEnum('role', $role, RBAC::allRoles(), 'Role');

        if (!empty($password)) {
            $v->strongPassword('password', $password);
        }

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        // Check email uniqueness (excluding this user)
        $emailTaken = DB::scalar(
            "SELECT id FROM users WHERE email = ? AND id != ? LIMIT 1",
            [$email, $targetId]
        );
        if ($emailTaken) {
            json_error('Validation failed.', 422, ['email' => 'Email address is already in use.']);
        }

        $userId = (int)Auth::userField('id');

        $params = [$email, $role, $canViewPw, $canMgr, $isActive, $forcePwCh];
        $sql    = "UPDATE users SET email=?, role=?, can_view_passwords=?, can_manage_managers=?, is_active=?, force_password_change=?";

        if (!empty($password)) {
            $hash    = password_hash($password, PASSWORD_ARGON2ID);
            $sql    .= ", password_hash=?, password_changed_at=NOW()";
            $params[] = $hash;
        }

        $sql    .= " WHERE id=?";
        $params[] = $targetId;

        DB::execute($sql, $params);

        $changes = [
            'email'             => $email,
            'role'              => $role,
            'is_active'         => $isActive,
            'can_view_passwords'=> $canViewPw,
        ];

        if ($target['role'] !== $role) {
            Audit::log($userId, Audit::USER_ROLE_CHANGE, 'user', $targetId, [
                'old_role' => $target['role'],
                'new_role' => $role,
            ], 'warning');
        }

        Audit::log($userId, Audit::USER_EDIT, 'user', $targetId, $changes);

        json_success([], 'User updated successfully.');
        break;

    case 'delete':
        $targetId = param_int('id', 0, $_POST);
        $confirm  = post('confirm');

        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        if ($confirm !== 'DELETE') {
            json_error('Type DELETE to confirm.', 400);
        }

        // Cannot delete yourself
        if ($targetId === (int)Auth::userField('id')) {
            json_error('Cannot delete your own account.', 400);
        }

        // Cannot delete other super admins
        $target = DB::row("SELECT role, username FROM users WHERE id = ?", [$targetId]);
        if (!$target) {
            json_error('User not found.', 404);
        }

        if ($target['role'] === RBAC::SUPER_ADMIN) {
            json_error('Cannot delete a Super Admin account.', 403);
        }

        // Soft delete
        DB::execute("UPDATE users SET is_active = 0 WHERE id = ?", [$targetId]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::USER_DELETE, 'user', $targetId, [
            'username' => $target['username'],
        ], 'warning');

        json_success([], 'User deactivated.');
        break;

    case 'assign-servers':
        $targetId  = param_int('id', 0, $_POST);
        $serverIds = $_POST['server_ids'] ?? [];

        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        $userId = (int)Auth::userField('id');

        DB::beginTransaction();
        try {
            // Remove all existing access
            DB::execute("DELETE FROM user_server_access WHERE user_id = ?", [$targetId]);

            // Re-assign
            foreach ($serverIds as $sid) {
                $sid = (int)$sid;
                if ($sid > 0) {
                    DB::execute(
                        "INSERT INTO user_server_access (user_id, server_id, granted_by) VALUES (?, ?, ?)",
                        [$targetId, $sid, $userId]
                    );
                }
            }

            DB::commit();
        } catch (Exception $e) {
            DB::rollBack();
            json_error('Failed to update server access.', 500);
        }

        Audit::log($userId, Audit::USER_EDIT, 'user', $targetId, [
            'action'     => 'server_access_updated',
            'server_ids' => $serverIds,
        ]);

        json_success([], 'Server access updated.');
        break;

    case 'toggle-2fa-reset':
        // Super admin can reset/disable 2FA for a user
        $targetId = param_int('id', 0, $_POST);

        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        DB::execute(
            "UPDATE users SET totp_secret_encrypted=NULL, totp_enabled=0, backup_codes_hash=NULL WHERE id=?",
            [$targetId]
        );

        $userId = (int)Auth::userField('id');
        Audit::log($userId, '2fa_disabled', 'user', $targetId, [], 'warning');

        json_success([], '2FA has been reset for this user.');
        break;

    case 'get-server-access':
        $targetId = param_int('id', 0, $_GET);
        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        $assignedIds = array_column(
            DB::rows("SELECT server_id FROM user_server_access WHERE user_id = ?", [$targetId]),
            'server_id'
        );
        $assignedIds = array_map('intval', $assignedIds);

        $servers = DB::rows(
            "SELECT id, name, platform_type FROM servers WHERE is_active = 1 ORDER BY name"
        );

        foreach ($servers as &$s) {
            $s['has_access'] = in_array((int)$s['id'], $assignedIds);
        }
        unset($s);

        json_success(['servers' => $servers, 'assigned_ids' => $assignedIds]);
        break;

    case 'get-manager-access':
        $targetId = param_int('id', 0, $_GET);
        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        // Get IDs this user already has direct manager access to
        $assignedIds = array_column(
            DB::rows("SELECT manager_account_id FROM user_manager_access WHERE user_id = ?", [$targetId]),
            'manager_account_id'
        );
        $assignedIds = array_map('intval', $assignedIds);

        // Get all active managers with their server info
        $managers = DB::rows(
            "SELECT ma.id, ma.label, ma.login_number, ma.server_id,
                    s.name AS server_name, s.platform_type
             FROM manager_accounts ma
             JOIN servers s ON s.id = ma.server_id
             WHERE ma.is_active = 1 AND s.is_active = 1
             ORDER BY s.name ASC, ma.label ASC"
        );

        foreach ($managers as &$m) {
            $m['has_access'] = in_array((int)$m['id'], $assignedIds);
        }
        unset($m);

        json_success(['managers' => $managers, 'assigned_ids' => $assignedIds]);
        break;

    case 'assign-managers':
        $targetId   = param_int('id', 0, $_POST);
        $managerIds = $_POST['manager_ids'] ?? [];

        if ($targetId <= 0) {
            json_error('Invalid user ID.', 400);
        }

        $userId = (int)Auth::userField('id');

        DB::beginTransaction();
        try {
            DB::execute("DELETE FROM user_manager_access WHERE user_id = ?", [$targetId]);
            foreach ($managerIds as $mid) {
                $mid = (int)$mid;
                if ($mid > 0) {
                    DB::execute(
                        "INSERT INTO user_manager_access (user_id, manager_account_id, granted_by) VALUES (?, ?, ?)",
                        [$targetId, $mid, $userId]
                    );
                }
            }
            DB::commit();
        } catch (Exception $e) {
            DB::rollBack();
            json_error('Failed to update manager access.', 500);
        }

        Audit::log($userId, Audit::USER_EDIT, 'user', $targetId, [
            'action'      => 'manager_access_updated',
            'manager_ids' => $managerIds,
        ]);

        json_success([], 'Manager access updated.');
        break;

    default:
        json_error('Unknown action.', 400);
}
