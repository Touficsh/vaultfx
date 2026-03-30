<?php
/**
 * VaultFX — Global Search API
 * =============================
 * Searches servers, manager accounts, and coverage accounts.
 * Results are always scoped to the user's accessible servers.
 * Passwords are NEVER included in search results.
 *
 * GET /api/search.php?q=...
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
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();

// For search, we allow GET — validate session but not CSRF (GET is read-only)
if (!Session::validate() || Session::is2FAPending()) {
    json_error('Authentication required.', 401);
}

$user = Auth::user();
if (!$user || !$user['is_active']) {
    json_error('Authentication required.', 401);
}

no_cache_headers();

$q = trim($_GET['q'] ?? '');
if (strlen($q) < 2) {
    json_success(['results' => [], 'total' => 0], 'Query too short.');
}

// Sanitize query — no SQL injection possible (using prepared statements)
// but limit length to prevent abuse
$q = mb_substr($q, 0, 100);

$serverIdsSql = RBAC::accessibleServerIdsSql();
$qSafe        = str_replace(['%', '_', '\\'], ['\\%', '\\_', '\\\\'], $q);
$like         = '%' . $qSafe . '%';
$results      = [];

// ── Search Servers ────────────────────────────────────────────
$servers = DB::rows(
    "SELECT id, name, ip_address, platform_type, tags, is_active
     FROM servers
     WHERE id IN {$serverIdsSql}
       AND is_active = 1
       AND (name LIKE ? OR ip_address LIKE ? OR tags LIKE ?)
     LIMIT 10",
    [$like, $like, $like]
);

foreach ($servers as $s) {
    $results[] = [
        'type'          => 'server',
        'id'            => (int)$s['id'],
        'label'         => $s['name'],
        'sublabel'      => $s['platform_type'],
        'ip_address'    => $s['ip_address'],
        'tags'          => $s['tags'],
        'url'           => '?page=server-detail&id=' . (int)$s['id'],
    ];
}

// ── Search Manager Accounts ───────────────────────────────────
$managers = DB::rows(
    "SELECT ma.id, ma.label, ma.login_number, ma.tags, ma.server_id, s.name AS server_name, s.platform_type
     FROM manager_accounts ma
     JOIN servers s ON s.id = ma.server_id
     WHERE ma.server_id IN {$serverIdsSql}
       AND ma.is_active = 1
       AND (ma.label LIKE ? OR ma.login_number LIKE ? OR ma.tags LIKE ?)
     LIMIT 15",
    [$like, $like, $like]
);

foreach ($managers as $m) {
    $results[] = [
        'type'          => 'manager',
        'id'            => (int)$m['id'],
        'label'         => $m['label'],
        'sublabel'      => 'Manager · ' . $m['server_name'],
        'login_number'  => $m['login_number'],
        'tags'          => $m['tags'],
        'url'           => '?page=server-detail&id=' . (int)$m['server_id'] . '&manager=' . (int)$m['id'],
    ];
}

// ── Search Coverage Accounts ──────────────────────────────────
$coverage = DB::rows(
    "SELECT ca.id, ca.label, ca.login_number, ca.tags, ca.server_id, ca.manager_account_id,
            s.name AS server_name, s.platform_type
     FROM coverage_accounts ca
     JOIN servers s ON s.id = ca.server_id
     WHERE ca.server_id IN {$serverIdsSql}
       AND ca.is_active = 1
       AND (ca.label LIKE ? OR ca.login_number LIKE ? OR ca.tags LIKE ?)
     LIMIT 15",
    [$like, $like, $like]
);

foreach ($coverage as $c) {
    $results[] = [
        'type'              => 'coverage',
        'id'                => (int)$c['id'],
        'label'             => $c['label'],
        'sublabel'          => 'Coverage · ' . $c['server_name'],
        'login_number'      => $c['login_number'],
        'tags'              => $c['tags'],
        'manager_id'        => (int)$c['manager_account_id'],
        'url'               => '?page=server-detail&id=' . (int)$c['server_id'] . '&manager=' . (int)$c['manager_account_id'] . '&coverage=' . (int)$c['id'],
    ];
}

json_success([
    'results' => $results,
    'total'   => count($results),
    'query'   => $q,
]);
