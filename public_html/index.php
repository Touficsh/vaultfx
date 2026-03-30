<?php
/**
 * VaultFX — Single Entry Point / Front Controller
 * =================================================
 * All requests are routed through this file.
 * Security is initialized here before anything else runs.
 */

// ── PHP built-in server: serve static files as-is ─────────────
if (PHP_SAPI === 'cli-server') {
    $file = __DIR__ . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    if (is_file($file)) {
        return false; // Let PHP serve it statically
    }
}

define('VAULTFX_BOOT', true);

// ── PHP Security Hardening ─────────────────────────────────────
ini_set('display_errors',  '0');
ini_set('log_errors',      '1');
ini_set('expose_php',      '0');
ini_set('allow_url_fopen', '0');
ini_set('allow_url_include', '0');
error_reporting(E_ALL);

// ── Load configuration (outside web root) ─────────────────────
// Auto-discover config by walking up the directory tree.
// Works whether deployed directly in public_html/ OR in a
// subdomain subfolder like public_html/fxvault/.
$configFile = null;
$searchDir  = __DIR__;
for ($i = 0; $i < 5; $i++) {
    $searchDir = dirname($searchDir);
    $candidate = $searchDir . '/config/config.php';
    if (file_exists($candidate)) {
        $configFile = $candidate;
        break;
    }
}
if ($configFile === null) {
    http_response_code(503);
    die('Application not configured. Please run the installer.');
}
require_once $configFile;

// Set error log path (now that config is loaded)
ini_set('error_log', PHP_ERROR_LOG);

// ── Set timezone ──────────────────────────────────────────────
date_default_timezone_set(APP_TIMEZONE);

// ── Check if installed ────────────────────────────────────────
if (!file_exists(INSTALL_LOCK_FILE)) {
    // Redirect to installer — path is relative to APP_ROOT, not web root
    $installerUrl = rtrim(APP_URL, '/') . '/../../install/install.php';
    // Simpler: use an absolute filesystem path redirect via direct include
    $installerPath = APP_ROOT . '/install/install.php';
    if (file_exists($installerPath)) {
        require_once $installerPath;
    } else {
        http_response_code(503);
        die('Installer not found. Please upload install/install.php to ' . APP_ROOT . '/install/');
    }
    exit;
}

// ── Load encryption key ───────────────────────────────────────
require_once ENCRYPTION_KEY_FILE;

// ── Load core includes ────────────────────────────────────────
require_once WEB_ROOT . '/includes/helpers.php';
require_once WEB_ROOT . '/includes/db.php';
require_once WEB_ROOT . '/includes/session.php';
require_once WEB_ROOT . '/includes/csrf.php';
require_once WEB_ROOT . '/includes/validation.php';
require_once WEB_ROOT . '/includes/audit.php';
require_once WEB_ROOT . '/includes/encryption.php';
require_once WEB_ROOT . '/includes/rate-limiter.php';
require_once WEB_ROOT . '/includes/rbac.php';
require_once WEB_ROOT . '/includes/auth.php';
require_once WEB_ROOT . '/lib/GoogleAuthenticator.php';
require_once WEB_ROOT . '/lib/QRCode.php';

// ── Start session ─────────────────────────────────────────────
Session::start();

// ── Route to page ─────────────────────────────────────────────
$page = preg_replace('/[^a-z0-9\-]/', '', strtolower($_GET['page'] ?? 'dashboard'));

// Public pages (no auth required)
$publicPages = ['login', '2fa-verify'];

if (in_array($page, $publicPages)) {
    include WEB_ROOT . '/pages/' . $page . '.php';
    exit;
}

// Handle logout
if ($page === 'logout') {
    Auth::logout();
    flash('success', 'You have been logged out.');
    redirect('?page=login');
}

// All other pages require authentication
Auth::require();

// Page map (whitelist — unknown pages → 404)
$pages = [
    'dashboard'     => 'dashboard.php',
    'servers'       => 'servers.php',
    'server-detail' => 'server-detail.php',
    'users'         => 'users.php',
    'audit-log'      => 'audit-log.php',
    'login-activity' => 'login-activity.php',
    'settings'       => 'settings.php',
    'my-account'    => 'my-account.php',
    '2fa-setup'     => '2fa-setup.php',
];

if (!isset($pages[$page])) {
    http_response_code(404);
    include WEB_ROOT . '/pages/404.php';
    exit;
}

include WEB_ROOT . '/pages/' . $pages[$page];
