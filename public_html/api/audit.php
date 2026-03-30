<?php
/**
 * VaultFX — Audit Log Export API
 * ================================
 * GET /api/audit.php?action=export
 * Exports audit log as CSV (passwords are NEVER included).
 * Requires Super Admin re-authentication for bulk exports.
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
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();

if (!Session::validate() || Session::is2FAPending()) {
    json_error('Authentication required.', 401);
}

$user = Auth::user();
if (!$user || !RBAC::canExport()) {
    json_error('Permission denied.', 403);
}

$action = $_GET['action'] ?? '';

if ($action === 'export') {
    // Build filters from GET params (same as page)
    $filters = array_filter([
        'user_id'     => (int)($_GET['user_id'] ?? 0) ?: null,
        'action_type' => $_GET['action_type'] ?? '',
        'target_type' => $_GET['target_type'] ?? '',
        'severity'    => $_GET['severity'] ?? '',
        'date_from'   => $_GET['date_from'] ?? '',
        'date_to'     => $_GET['date_to'] ?? '',
        'ip'          => $_GET['ip'] ?? '',
    ]);

    // Log the export
    Audit::log((int)$user['id'], Audit::EXPORT, 'system', null, [
        'filters'  => $filters,
        'format'   => 'csv',
    ]);

    // Fetch all matching records (no pagination for export)
    $result = Audit::fetch($filters, 1, 50000);
    $rows   = $result['rows'];

    // Output CSV — no passwords ever included
    $filename = 'vaultfx-audit-' . date('Ymd-His') . '.csv';

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Cache-Control: no-store, no-cache');
    header('Pragma: no-cache');

    $out = fopen('php://output', 'w');
    fputcsv($out, ['ID', 'Timestamp (UTC)', 'User', 'Action', 'Target Type', 'Target ID', 'IP Address', 'Severity', 'Details']);

    foreach ($rows as $row) {
        fputcsv($out, [
            $row['id'],
            $row['created_at'],
            $row['username'] ?? '',
            $row['action_type'],
            $row['target_type'] ?? '',
            $row['target_id'] ?? '',
            $row['ip_address'],
            $row['severity'],
            $row['details'] ?? '',
        ]);
    }

    fclose($out);
    exit;
}

json_error('Unknown action.', 400);
