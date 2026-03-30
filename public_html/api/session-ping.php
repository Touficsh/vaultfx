<?php
/**
 * VaultFX — Session Ping (Keep-alive)
 * =====================================
 * Lightweight endpoint called every 5 minutes by session-monitor.js.
 * Updates session last_activity and returns time remaining.
 *
 * GET/POST /api/session-ping.php
 */

define('VAULTFX_BOOT', true);
require_once dirname(__DIR__, 2) . '/config/config.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', PHP_ERROR_LOG);

require_once dirname(__DIR__) . '/includes/helpers.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/session.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/csrf.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';

Session::start();

no_cache_headers();
header('Content-Type: application/json; charset=UTF-8');

if (!Session::validate() || Session::is2FAPending()) {
    http_response_code(401);
    echo json_safe(['authenticated' => false, 'remaining' => 0]);
    exit;
}

$user = Auth::user();
if (!$user) {
    http_response_code(401);
    echo json_safe(['authenticated' => false, 'remaining' => 0]);
    exit;
}

echo json_safe([
    'authenticated' => true,
    'remaining'     => Session::idleSecondsRemaining(),
    'csrf_token'    => CSRF::token(),
]);
