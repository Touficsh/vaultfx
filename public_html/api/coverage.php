<?php
/**
 * VaultFX — Coverage Accounts CRUD API
 * ======================================
 * POST /api/coverage.php?action=create|edit|delete|list
 */

define('VAULTFX_BOOT', true);
require_once __DIR__ . '/bootstrap.php';

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

    case 'list':
        $managerId = param_int('manager_id', 0, $_GET);
        if ($managerId <= 0) {
            json_error('Invalid manager ID.', 400);
        }

        if (!RBAC::canAccessManager($managerId)) {
            json_error('Permission denied.', 403);
        }

        $coverage = DB::rows(
            "SELECT ca.id, ca.label, ca.login_number, ca.server_id, ca.manager_account_id,
                    ca.tags, ca.notes, ca.password_expires_at, ca.password_last_changed,
                    ca.is_active, ca.key_version, ca.created_at, ca.updated_at,
                    ca.encrypted_investor_password,
                    u.username AS created_by_username, s.name AS server_name
             FROM coverage_accounts ca
             LEFT JOIN users u ON u.id = ca.created_by
             LEFT JOIN servers s ON s.id = ca.server_id
             WHERE ca.manager_account_id = ? AND ca.is_active = 1
             ORDER BY ca.label ASC",
            [$managerId]
        );

        foreach ($coverage as &$c) {
            $c['has_investor_password'] = !empty($c['encrypted_investor_password']);
            unset($c['encrypted_investor_password']); // never expose encrypted blob
            $c['expiry_status'] = expiry_status($c['password_expires_at']);
            $c['last_reveal']   = Audit::lastReveal('coverage', (int)$c['id']);
            $c['can_reveal']    = RBAC::canViewPasswords();
        }

        json_success(['coverage' => $coverage]);
        break;

    case 'create':
        RBAC::assert(RBAC::canManageManagers(), true);

        $managerId       = param_int('manager_account_id', 0, $_POST);
        $serverId        = param_int('server_id', 0, $_POST);
        $label           = post('label');
        $login           = post('login_number');
        $password        = post('password');
        $investorPw      = post('investor_password');
        $expires         = post('password_expires_at');
        $notes           = post('notes');
        $tags            = post('tags');

        if ($managerId <= 0 || $serverId <= 0) {
            json_error('Invalid manager or server ID.', 400);
        }

        if (!RBAC::canAccessManager($managerId)) {
            json_error('Permission denied.', 403);
        }

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

        if (!empty($investorPw)) {
            $v->maxLength('investor_password', $investorPw, 500, 'Investor password')
              ->noNullBytes('investor_password', $investorPw, 'Investor password');
        }

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        $encrypted = Encryption::encryptCredential($password);
        $userId    = (int)Auth::userField('id');

        $encInvestor     = null;
        $investorSalt    = null;
        $investorVersion = null;
        if (!empty($investorPw)) {
            $encInv          = Encryption::encryptCredential($investorPw);
            $encInvestor     = $encInv['encrypted_blob'];
            $investorSalt    = $encInv['salt'];
            $investorVersion = $encInv['key_version'];
        }

        DB::execute(
            "INSERT INTO coverage_accounts
                (manager_account_id, server_id, label, login_number, encrypted_password, password_salt,
                 key_version, encrypted_investor_password, investor_password_salt, investor_key_version,
                 password_expires_at, password_last_changed, notes, tags, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)",
            [
                $managerId,
                $serverId,
                Validation::sanitizeText($label, 100),
                $login,
                $encrypted['encrypted_blob'],
                $encrypted['salt'],
                $encrypted['key_version'],
                $encInvestor,
                $investorSalt,
                $investorVersion,
                $expires ?: null,
                Validation::sanitizeText($notes, 5000) ?: null,
                Validation::sanitizeText($tags, 500) ?: null,
                $userId,
            ]
        );

        $newId = (int)DB::lastInsertId();

        Audit::log($userId, Audit::CREDENTIAL_CREATE, 'coverage_account', $newId, [
            'label'      => $label,
            'login'      => $login,
            'manager_id' => $managerId,
        ]);

        json_success(['id' => $newId], 'Coverage account created successfully.');
        break;

    case 'edit':
        RBAC::assert(RBAC::canManageManagers(), true);

        $id         = param_int('id', 0, $_POST);
        $label      = post('label');
        $login      = post('login_number');
        $password   = post('password');
        $investorPw = post('investor_password');
        $expires    = post('password_expires_at');
        $notes      = post('notes');
        $tags       = post('tags');

        if ($id <= 0) {
            json_error('Invalid coverage ID.', 400);
        }

        // Check manager-level access (coverage belongs to a manager)
        $covRow = DB::row("SELECT manager_account_id FROM coverage_accounts WHERE id = ? AND is_active = 1", [$id]);
        if (!$covRow || !RBAC::canAccessManager((int)$covRow['manager_account_id'])) {
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

        if (!empty($investorPw)) {
            $v->maxLength('investor_password', $investorPw, 500, 'Investor password')
              ->noNullBytes('investor_password', $investorPw, 'Investor password');
        }

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        $userId = (int)Auth::userField('id');

        // Build UPDATE dynamically based on what changed
        $setParts = ['label=?', 'login_number=?', 'password_expires_at=?', 'notes=?', 'tags=?'];
        $params   = [
            Validation::sanitizeText($label, 100),
            $login,
            $expires ?: null,
            Validation::sanitizeText($notes, 5000) ?: null,
            Validation::sanitizeText($tags, 500) ?: null,
        ];

        if (!empty($password)) {
            $encrypted  = Encryption::encryptCredential($password);
            $setParts[] = 'encrypted_password=?';
            $setParts[] = 'password_salt=?';
            $setParts[] = 'key_version=?';
            $setParts[] = 'password_last_changed=NOW()';
            $params[]   = $encrypted['encrypted_blob'];
            $params[]   = $encrypted['salt'];
            $params[]   = $encrypted['key_version'];
        }

        if (!empty($investorPw)) {
            $encInv     = Encryption::encryptCredential($investorPw);
            $setParts[] = 'encrypted_investor_password=?';
            $setParts[] = 'investor_password_salt=?';
            $setParts[] = 'investor_key_version=?';
            $params[]   = $encInv['encrypted_blob'];
            $params[]   = $encInv['salt'];
            $params[]   = $encInv['key_version'];
        }

        $params[] = $id;
        DB::execute(
            "UPDATE coverage_accounts SET " . implode(', ', $setParts) . " WHERE id=?",
            $params
        );

        Audit::log($userId, Audit::CREDENTIAL_EDIT, 'coverage_account', $id, [
            'label'            => $label,
            'password_changed' => !empty($password),
        ]);

        json_success([], 'Coverage account updated.');
        break;

    case 'delete':
        RBAC::assert(RBAC::canManageManagers(), true);

        $id      = param_int('id', 0, $_POST);
        $confirm = post('confirm');

        if ($id <= 0) {
            json_error('Invalid coverage ID.', 400);
        }

        if ($confirm !== 'DELETE') {
            json_error('Confirmation required.', 400);
        }

        $delRow = DB::row(
            "SELECT ca.manager_account_id, ca.label, ca.login_number, ma.server_id
             FROM coverage_accounts ca
             JOIN manager_accounts ma ON ma.id = ca.manager_account_id
             WHERE ca.id = ? AND ca.is_active = 1",
            [$id]
        );
        if (!$delRow || !RBAC::canAccessManager((int)$delRow['manager_account_id'])) {
            json_error('Permission denied.', 403);
        }

        DB::execute("UPDATE coverage_accounts SET is_active = 0 WHERE id = ?", [$id]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::CREDENTIAL_DELETE, 'coverage_account', $id, [
            'label'              => $delRow['label'] ?? '',
            'login'              => $delRow['login_number'] ?? '',
            'manager_account_id' => $delRow['manager_account_id'] ?? null,
            'server_id'          => $delRow['server_id'] ?? null,
        ], 'warning');

        json_success([], 'Coverage account deleted.');
        break;

    default:
        json_error('Unknown action.', 400);
}
