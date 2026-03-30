<?php
/**
 * VaultFX — Manager Accounts CRUD API
 * =====================================
 * POST /api/managers.php?action=create|edit|delete|list|generate-password
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

switch ($action) {

    // ── List managers for a server ────────────────────────────
    case 'list':
        $serverId = param_int('server_id', 0, $_GET);
        if ($serverId <= 0) {
            json_error('Invalid server ID.', 400);
        }
        RBAC::assertServerAccess($serverId, true);

        $managers = DB::rows(
            "SELECT ma.id, ma.label, ma.login_number, ma.server_id, ma.tags, ma.notes,
                    ma.password_expires_at, ma.password_last_changed, ma.is_active,
                    ma.key_version, ma.created_at, ma.updated_at,
                    u.username AS created_by_username,
                    COUNT(ca.id) AS coverage_count
             FROM manager_accounts ma
             LEFT JOIN users u ON u.id = ma.created_by
             LEFT JOIN coverage_accounts ca ON ca.manager_account_id = ma.id AND ca.is_active = 1
             WHERE ma.server_id = ? AND ma.is_active = 1
             GROUP BY ma.id
             ORDER BY ma.label ASC",
            [$serverId]
        );

        // Add expiry status and last reveal info
        foreach ($managers as &$m) {
            $m['expiry_status'] = expiry_status($m['password_expires_at']);
            $m['last_reveal']   = Audit::lastReveal('manager', (int)$m['id']);
            $m['can_reveal']    = RBAC::canViewPasswords();
        }

        json_success(['managers' => $managers]);
        break;

    // ── Create ────────────────────────────────────────────────
    case 'create':
        RBAC::assert(RBAC::canManageManagers(), true);

        $serverId  = param_int('server_id', 0, $_POST);
        $label     = post('label');
        $login     = post('login_number');
        $password  = post('password');
        $expires   = post('password_expires_at');
        $notes     = post('notes');
        $tags      = post('tags');

        if ($serverId <= 0) {
            json_error('Invalid server ID.', 400);
        }

        RBAC::assertServerAccess($serverId, true);

        $v = new Validation();
        $v->required('label', $label, 'Label')
          ->maxLength('label', $label, 100, 'Label')
          ->required('login_number', $login, 'Login number')
          ->loginNumber('login_number', $login)
          ->required('password', $password, 'Password')
          ->maxLength('password', $password, 500, 'Password')
          ->noNullBytes('password', $password, 'Password')
          ->tags('tags', $tags)
          ->date('password_expires_at', $expires, 'Expiry date');

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        // Encrypt the credential password
        try {
            $encrypted = Encryption::encryptCredential($password);
        } catch (Exception $e) {
            app_log('error', 'Encryption failed on manager create: ' . $e->getMessage());
            json_error('Failed to encrypt password. Please try again.', 500);
        }

        $userId = (int)Auth::userField('id');

        DB::execute(
            "INSERT INTO manager_accounts
                (server_id, label, login_number, encrypted_password, password_salt, key_version,
                 password_expires_at, password_last_changed, notes, tags, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)",
            [
                $serverId,
                Validation::sanitizeText($label, 100),
                $login,
                $encrypted['encrypted_blob'],
                $encrypted['salt'],
                $encrypted['key_version'],
                $expires ?: null,
                Validation::sanitizeText($notes, 5000) ?: null,
                Validation::sanitizeText($tags, 500) ?: null,
                $userId,
            ]
        );

        $newId = (int)DB::lastInsertId();

        Audit::log($userId, Audit::CREDENTIAL_CREATE, 'manager_account', $newId, [
            'label'     => $label,
            'login'     => $login,
            'server_id' => $serverId,
        ]);

        json_success(['id' => $newId], 'Manager account created successfully.');
        break;

    // ── Edit ──────────────────────────────────────────────────
    case 'edit':
        RBAC::assert(RBAC::canManageManagers(), true);

        $id       = param_int('id', 0, $_POST);
        $label    = post('label');
        $login    = post('login_number');
        $password = post('password');       // Empty = keep existing
        $expires  = post('password_expires_at');
        $notes    = post('notes');
        $tags     = post('tags');

        if ($id <= 0) {
            json_error('Invalid manager ID.', 400);
        }

        if (!RBAC::canAccessManager($id)) {
            json_error('Permission denied.', 403);
        }

        $v = new Validation();
        $v->required('label', $label, 'Label')
          ->maxLength('label', $label, 100, 'Label')
          ->required('login_number', $login, 'Login number')
          ->loginNumber('login_number', $login)
          ->tags('tags', $tags)
          ->date('password_expires_at', $expires, 'Expiry date');

        if (!empty($password)) {
            $v->maxLength('password', $password, 500, 'Password')
              ->noNullBytes('password', $password, 'Password');
        }

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        $userId = (int)Auth::userField('id');

        if (!empty($password)) {
            // Re-encrypt with new password
            $encrypted = Encryption::encryptCredential($password);
            DB::execute(
                "UPDATE manager_accounts
                 SET label=?, login_number=?, encrypted_password=?, password_salt=?, key_version=?,
                     password_expires_at=?, password_last_changed=NOW(), notes=?, tags=?
                 WHERE id=?",
                [
                    Validation::sanitizeText($label, 100),
                    $login,
                    $encrypted['encrypted_blob'],
                    $encrypted['salt'],
                    $encrypted['key_version'],
                    $expires ?: null,
                    Validation::sanitizeText($notes, 5000) ?: null,
                    Validation::sanitizeText($tags, 500) ?: null,
                    $id,
                ]
            );
            Audit::log($userId, Audit::CREDENTIAL_EDIT, 'manager_account', $id, [
                'label'            => $label,
                'password_changed' => true,
            ]);
        } else {
            DB::execute(
                "UPDATE manager_accounts
                 SET label=?, login_number=?, password_expires_at=?, notes=?, tags=?
                 WHERE id=?",
                [
                    Validation::sanitizeText($label, 100),
                    $login,
                    $expires ?: null,
                    Validation::sanitizeText($notes, 5000) ?: null,
                    Validation::sanitizeText($tags, 500) ?: null,
                    $id,
                ]
            );
            Audit::log($userId, Audit::CREDENTIAL_EDIT, 'manager_account', $id, ['label' => $label]);
        }

        json_success([], 'Manager account updated successfully.');
        break;

    // ── Toggle Active/Inactive ────────────────────────────────
    case 'toggle-active':
        RBAC::assert(RBAC::canManageManagers(), true);

        $id     = param_int('id', 0, $_POST);
        $action = post('action'); // 'activate' or 'deactivate'

        if ($id <= 0) {
            json_error('Invalid manager ID.', 400);
        }

        if (!in_array($action, ['activate', 'deactivate'])) {
            json_error('Invalid action. Must be activate or deactivate.', 400);
        }

        if (!RBAC::canAccessManager($id)) {
            json_error('Permission denied.', 403);
        }

        $mgr = DB::row("SELECT id, label, login_number, server_id, is_active FROM manager_accounts WHERE id = ?", [$id]);
        if (!$mgr) {
            json_error('Manager account not found.', 404);
        }

        $newActive = $action === 'activate' ? 1 : 0;

        // Prevent activating a manager whose server is inactive
        if ($newActive === 1) {
            $serverActive = DB::scalar("SELECT is_active FROM servers WHERE id = ?", [(int)$mgr['server_id']]);
            if (!$serverActive) {
                json_error('Cannot activate a manager on an inactive server.', 409);
            }
        }

        DB::execute("UPDATE manager_accounts SET is_active = ? WHERE id = ?", [$newActive, $id]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::CREDENTIAL_EDIT, 'manager_account', $id, [
            'label'     => $mgr['label'],
            'login'     => $mgr['login_number'],
            'is_active' => $newActive,
            'action'    => $action,
        ], 'warning');

        $label = $newActive ? 'activated' : 'deactivated';
        json_success([], "Manager account {$label}.");
        break;

    // ── Delete ────────────────────────────────────────────────
    case 'delete':
        RBAC::assert(RBAC::canManageManagers(), true);

        $id      = param_int('id', 0, $_POST);
        $confirm = post('confirm');

        if ($id <= 0) {
            json_error('Invalid manager ID.', 400);
        }

        if ($confirm !== 'DELETE') {
            json_error('Confirmation required. Type DELETE to confirm.', 400);
        }

        if (!RBAC::canAccessManager($id)) {
            json_error('Permission denied.', 403);
        }

        // Check for coverage accounts
        $coverageCount = (int)DB::scalar(
            "SELECT COUNT(*) FROM coverage_accounts WHERE manager_account_id = ? AND is_active = 1",
            [$id]
        );

        if ($coverageCount > 0) {
            json_error('Cannot delete manager with active coverage accounts.', 409);
        }

        $mgrRow = DB::row("SELECT label, login_number, server_id FROM manager_accounts WHERE id = ?", [$id]);
        DB::execute("UPDATE manager_accounts SET is_active = 0 WHERE id = ?", [$id]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::CREDENTIAL_DELETE, 'manager_account', $id, [
            'label'      => $mgrRow['label'] ?? '',
            'login'      => $mgrRow['login_number'] ?? '',
            'server_id'  => $mgrRow['server_id'] ?? null,
        ], 'warning');

        json_success([], 'Manager account deleted.');
        break;

    // ── Search managers by name or login ─────────────────────
    case 'search':
        $q = trim($_GET['q'] ?? '');
        if (mb_strlen($q) < 2) {
            json_success(['managers' => []]);
        }

        $accessibleMgrIds = RBAC::accessibleManagerIdsSql();
        $like = '%' . str_replace(['%', '_'], ['\\%', '\\_'], $q) . '%';

        $managers = DB::rows(
            "SELECT ma.id, ma.label, ma.login_number, ma.server_id,
                    s.name AS server_name, s.platform_type
             FROM manager_accounts ma
             JOIN servers s ON s.id = ma.server_id
             WHERE ma.id IN $accessibleMgrIds
               AND ma.is_active = 1
               AND s.is_active = 1
               AND (ma.label LIKE ? OR ma.login_number LIKE ?)
             ORDER BY s.name ASC, ma.label ASC
             LIMIT 30",
            [$like, $like]
        );

        json_success(['managers' => $managers]);
        break;

    // ── Generate password ─────────────────────────────────────
    case 'generate-password':
        $length  = param_int('length', 20, $_GET ?: $_POST);
        $upper   = ($_GET['upper'] ?? $_POST['upper'] ?? '1') === '1';
        $lower   = ($_GET['lower'] ?? $_POST['lower'] ?? '1') === '1';
        $digits  = ($_GET['digits'] ?? $_POST['digits'] ?? '1') === '1';
        $special = ($_GET['special'] ?? $_POST['special'] ?? '1') === '1';

        try {
            $password = Encryption::generatePassword($length, $upper, $lower, $digits, $special);
            json_success(['password' => $password]);
        } catch (Exception $e) {
            json_error('Failed to generate password: ' . $e->getMessage(), 400);
        }
        break;

    default:
        json_error('Unknown action.', 400);
}
