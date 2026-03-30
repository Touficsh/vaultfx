<?php
/**
 * VaultFX — Application Configuration (EXAMPLE)
 * =============================================
 * Copy this file to config.php and fill in your values:
 *
 *   cp config/config.example.php config/config.php
 *
 * IMPORTANT:
 * • This file must live OUTSIDE the web root.
 * • Set permissions to 600 after editing: chmod 600 config/config.php
 * • NEVER commit config.php to version control.
 */

// ── Prevent direct web access ────────────────────────────────
if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

// ── Database ─────────────────────────────────────────────────
define('DB_HOST',    'localhost');
define('DB_PORT',    '3306');
define('DB_NAME',    'your_db_name');        // e.g. u123456_vaultfx
define('DB_USER',    'your_db_user');        // e.g. u123456_vaultfx
define('DB_PASS',    'your_db_password');
define('DB_CHARSET', 'utf8mb4');

// ── Database — privileged user (install only) ─────────────────
// Used only during the one-time install wizard — can match DB_USER on shared hosting
define('DB_INSTALL_USER', 'your_db_user');
define('DB_INSTALL_PASS', 'your_db_password');

// ── Paths ─────────────────────────────────────────────────────
// On Hostinger: APP_ROOT = /home/username  (one level above public_html)
// dirname(__DIR__) automatically resolves this if config/ sits beside public_html/
define('APP_ROOT',       dirname(__DIR__));
define('CONFIG_PATH',    APP_ROOT . '/config');
define('LOG_PATH',       APP_ROOT . '/logs');
define('EXPORT_PATH',    APP_ROOT . '/logs/audit_export');
define('WEB_ROOT',       APP_ROOT . '/public_html');

// ── Application ───────────────────────────────────────────────
define('APP_NAME',       'VaultFX');
define('APP_VERSION',    '1.1.0');
define('APP_URL',        'https://yourdomain.com');   // No trailing slash
define('APP_ENV',        'production');                // 'development' | 'production'
define('APP_TIMEZONE',   'UTC');

// ── Session ───────────────────────────────────────────────────
define('SESSION_NAME',          'vfx_sess');
define('SESSION_IDLE_TIMEOUT',  1800);      // 30 minutes
define('SESSION_ABSOLUTE_MAX',  28800);     // 8 hours

// ── Security ──────────────────────────────────────────────────
define('BCRYPT_COST',         12);
define('MIN_PASSWORD_LENGTH', 12);

// ── Error Logging ─────────────────────────────────────────────
define('PHP_ERROR_LOG', LOG_PATH . '/php_errors.log');
define('APP_LOG',       LOG_PATH . '/app.log');

// ── Email (alert notifications — configure in Settings → Alerts) ──
define('ALERT_EMAIL_ENABLED', false);
define('ALERT_EMAIL_FROM',    'noreply@yourdomain.com');
define('ALERT_EMAIL_TO',      'admin@yourdomain.com');

// ── Encryption Key File ───────────────────────────────────────
// This file is generated automatically by the installer.
// NEVER share or commit it — losing it means losing all encrypted data.
define('ENCRYPTION_KEY_FILE', CONFIG_PATH . '/encryption-key.php');

// ── Installation ──────────────────────────────────────────────
define('INSTALL_LOCK_FILE', CONFIG_PATH . '/install.lock');
