<?php
/**
 * VaultFX — Database Backup API
 * ================================
 * GET /api/backup.php
 *
 * Streams a SQL dump of all VaultFX tables as a downloadable file.
 * Encrypted credentials remain encrypted in the dump — the dump
 * contains no plaintext passwords.
 *
 * Super Admin only.
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

Session::start();
Auth::require();
RBAC::assert(RBAC::canBackup(), false);  // Non-API: shows 403 page on failure

$userId   = (int)Auth::userField('id');
$filename = 'vaultfx-backup-' . date('Y-m-d-His') . '.sql';

// ── Tables to dump (in dependency order) ─────────────────────
$tables = [
    'users',
    'servers',
    'manager_accounts',
    'coverage_accounts',
    'user_server_access',
    'user_manager_access',
    'audit_log',
    'login_attempts',
    'active_sessions',
    'settings',
    'password_reveals',
];

// ── Stream the SQL dump ───────────────────────────────────────
header('Content-Type: application/sql; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

$db = DB::pdo();

echo "-- VaultFX Database Backup\n";
echo "-- Generated: " . date('Y-m-d H:i:s T') . "\n";
echo "-- Server: " . DB_HOST . "\n";
echo "-- Database: " . DB_NAME . "\n";
echo "-- !! Encrypted credentials remain encrypted. Backup contains no plaintext passwords. !!\n\n";
echo "SET NAMES utf8mb4;\n";
echo "SET FOREIGN_KEY_CHECKS = 0;\n\n";

foreach ($tables as $table) {
    // Verify table exists
    $exists = $db->query("SHOW TABLES LIKE " . $db->quote($table))->fetchColumn();
    if (!$exists) continue;

    echo "-- ------------------------------------------------------------\n";
    echo "-- Table: `{$table}`\n";
    echo "-- ------------------------------------------------------------\n";

    // CREATE TABLE statement
    $createStmt = $db->query("SHOW CREATE TABLE `{$table}`")->fetch(PDO::FETCH_NUM);
    echo $createStmt[1] . ";\n\n";

    // Data rows
    $stmt = $db->query("SELECT * FROM `{$table}`");
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (!empty($rows)) {
        $cols = '`' . implode('`, `', array_keys($rows[0])) . '`';
        echo "INSERT INTO `{$table}` ({$cols}) VALUES\n";

        $valueLines = [];
        foreach ($rows as $row) {
            $vals = array_map(function ($val) use ($db) {
                if ($val === null) return 'NULL';
                return $db->quote($val);
            }, $row);
            $valueLines[] = '(' . implode(', ', $vals) . ')';
        }

        echo implode(",\n", $valueLines) . ";\n\n";
    }
}

echo "SET FOREIGN_KEY_CHECKS = 1;\n";

// ── Audit ─────────────────────────────────────────────────────
Audit::log($userId, Audit::BACKUP, 'system', null, [
    'tables' => count($tables),
    'file'   => $filename,
], 'warning');
