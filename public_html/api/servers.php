<?php
/**
 * VaultFX — Servers CRUD API
 * ===========================
 * POST /api/servers.php?action=create|edit|delete|list
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
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();
Auth::requireApi();

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

switch ($action) {

    // ── List ─────────────────────────────────────────────────
    case 'list':
        $serverIdsSql = RBAC::accessibleServerIdsSql();

        $servers = DB::rows(
            "SELECT s.*, u.username AS created_by_username,
                    COUNT(DISTINCT ma.id) AS manager_count,
                    COUNT(DISTINCT ca.id) AS coverage_count
             FROM servers s
             LEFT JOIN users u ON u.id = s.created_by
             LEFT JOIN manager_accounts ma ON ma.server_id = s.id AND ma.is_active = 1
             LEFT JOIN coverage_accounts ca ON ca.server_id = s.id AND ca.is_active = 1
             WHERE s.id IN {$serverIdsSql} AND s.is_active = 1
             GROUP BY s.id
             ORDER BY s.name ASC"
        );

        json_success(['servers' => $servers]);
        break;

    // ── Create ────────────────────────────────────────────────
    case 'create':
        RBAC::assertRole(RBAC::ADMIN, true);

        $name     = post('name');
        $ip       = post('ip_address');
        $platform = post('platform_type');
        $notes    = post('notes');
        $tags     = post('tags');

        $v = new Validation();
        $v->required('name', $name, 'Server name')
          ->minLength('name', $name, 2, 'Server name')
          ->maxLength('name', $name, 255, 'Server name')
          ->alphanumericDash('name', $name, 'Server name')
          ->maxLength('ip_address', $ip, 255, 'Server IP')
          ->inEnum('platform_type', $platform, ['MT4','MT5','cTrader','DXtrade','Other'], 'Platform')
          ->maxLength('notes', $notes, 5000, 'Notes')
          ->tags('tags', $tags);

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        $userId = (int)Auth::userField('id');

        DB::execute(
            "INSERT INTO servers (name, ip_address, platform_type, notes, tags, created_by)
             VALUES (?, ?, ?, ?, ?, ?)",
            [
                Validation::sanitizeText($name, 255),
                $ip ?: null,
                $platform,
                Validation::sanitizeText($notes, 5000) ?: null,
                Validation::sanitizeText($tags, 500) ?: null,
                $userId,
            ]
        );

        $newId = (int)DB::lastInsertId();

        // Admins automatically get access to servers they create
        if (!RBAC::isSuperAdmin()) {
            DB::execute(
                "INSERT IGNORE INTO user_server_access (user_id, server_id, granted_by) VALUES (?, ?, ?)",
                [$userId, $newId, $userId]
            );
        }

        Audit::log($userId, Audit::CREDENTIAL_CREATE, 'server', $newId, [
            'name'     => $name,
            'platform' => $platform,
        ]);

        json_success(['id' => $newId], 'Server created successfully.');
        break;

    // ── Edit ──────────────────────────────────────────────────
    case 'edit':
        RBAC::assertRole(RBAC::ADMIN, true);

        $id       = param_int('id', 0, $_POST);
        $name     = post('name');
        $ip       = post('ip_address');
        $platform = post('platform_type');
        $notes    = post('notes');
        $tags     = post('tags');
        $active   = post('is_active');

        if ($id <= 0) {
            json_error('Invalid server ID.', 400);
        }

        RBAC::assertServerAccess($id, true);

        $v = new Validation();
        $v->required('name', $name, 'Server name')
          ->minLength('name', $name, 2, 'Server name')
          ->maxLength('name', $name, 255, 'Server name')
          ->alphanumericDash('name', $name, 'Server name')
          ->maxLength('ip_address', $ip, 255, 'Server IP')
          ->inEnum('platform_type', $platform, ['MT4','MT5','cTrader','DXtrade','Other'], 'Platform')
          ->maxLength('notes', $notes, 5000, 'Notes')
          ->tags('tags', $tags);

        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        $userId = (int)Auth::userField('id');

        DB::execute(
            "UPDATE servers SET name=?, ip_address=?, platform_type=?, notes=?, tags=?, is_active=? WHERE id=?",
            [
                Validation::sanitizeText($name, 255),
                $ip ?: null,
                $platform,
                Validation::sanitizeText($notes, 5000) ?: null,
                Validation::sanitizeText($tags, 500) ?: null,
                $active === '1' ? 1 : 0,
                $id,
            ]
        );

        Audit::log($userId, Audit::CREDENTIAL_EDIT, 'server', $id, ['name' => $name]);
        json_success([], 'Server updated successfully.');
        break;

    // ── Update IP only ────────────────────────────────────────
    case 'update-ip':
        RBAC::assert(RBAC::canManageServers(), true);

        $id = param_int('id', 0, $_POST);
        $ip = trim(post('ip_address'));

        if ($id <= 0) {
            json_error('Invalid server ID.', 400);
        }

        RBAC::assertServerAccess($id, true);

        $v = new Validation();
        $v->maxLength('ip_address', $ip, 255, 'Server IP');
        if ($v->fails()) {
            json_error('Validation failed.', 422, $v->errors());
        }

        DB::execute("UPDATE servers SET ip_address = ? WHERE id = ?", [$ip ?: null, $id]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::CREDENTIAL_EDIT, 'server', $id, ['ip_address' => $ip]);
        json_success(['ip_address' => $ip], 'Server IP updated.');
        break;

    // ── Delete ────────────────────────────────────────────────
    case 'delete':
        RBAC::assertRole(RBAC::ADMIN, true);

        $id     = param_int('id', 0, $_POST);
        $confirm = post('confirm');

        if ($id <= 0) {
            json_error('Invalid server ID.', 400);
        }

        if ($confirm !== 'DELETE') {
            json_error('Confirmation required. Type DELETE to confirm.', 400);
        }

        RBAC::assertServerAccess($id, true);

        // Check if server has accounts — prevent deletion if so
        $managerCount = (int)DB::scalar(
            "SELECT COUNT(*) FROM manager_accounts WHERE server_id = ? AND is_active = 1",
            [$id]
        );

        if ($managerCount > 0) {
            json_error('Cannot delete server with active manager accounts. Deactivate or delete all accounts first.', 409);
        }

        // Soft delete (keep for audit trail)
        DB::execute("UPDATE servers SET is_active = 0 WHERE id = ?", [$id]);

        $userId = (int)Auth::userField('id');
        Audit::log($userId, Audit::CREDENTIAL_DELETE, 'server', $id, ['server_id' => $id], 'warning');

        json_success([], 'Server deleted successfully.');
        break;

    default:
        json_error('Unknown action.', 400);
}
