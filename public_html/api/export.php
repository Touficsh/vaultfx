<?php
/**
 * VaultFX — Credential Export API
 * =================================
 * GET /api/export.php?format=csv&include_passwords=0&server_id=N
 *
 * Exports accessible managers and coverage accounts.
 * Passwords are only included when the setting allows it AND
 * the user has can_view_passwords permission.
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
require_once ENCRYPTION_KEY_FILE;

Session::start();
Auth::require();
RBAC::assert(RBAC::canExport(), false);  // Non-API: shows 403 page on failure

$format           = $_GET['format'] ?? 'csv';
$includePasswords = ($_GET['include_passwords'] ?? '0') === '1' && RBAC::canViewPasswords();
$filterServerId   = param_int('server_id', 0, $_GET);

if ($format !== 'csv') {
    json_error('Unsupported format. Only csv is supported.', 400);
}

$managerIdsSql = RBAC::accessibleManagerIdsSql();

// Build query
$whereClauses = ["ma.id IN {$managerIdsSql}", "ma.is_active = 1", "s.is_active = 1"];
$params       = [];

if ($filterServerId > 0) {
    RBAC::assertServerAccess($filterServerId, true);
    $whereClauses[] = "ma.server_id = ?";
    $params[]       = $filterServerId;
}

$whereStr = implode(' AND ', $whereClauses);

$managers = DB::rows(
    "SELECT ma.id, ma.label, ma.login_number,
            ma.encrypted_password, ma.password_salt,
            ma.notes, ma.tags,
            s.name AS server_name, s.platform_type
     FROM manager_accounts ma
     JOIN servers s ON s.id = ma.server_id
     WHERE {$whereStr}
     ORDER BY s.name ASC, ma.label ASC",
    $params
);

// Load coverage for all these managers
$managerIds = array_column($managers, 'id');
$coverageByManager = [];

if (!empty($managerIds)) {
    $ph = implode(',', array_fill(0, count($managerIds), '?'));
    $allCoverage = DB::rows(
        "SELECT ca.id, ca.manager_account_id, ca.label, ca.login_number,
                ca.encrypted_password, ca.password_salt,
                ca.encrypted_investor_password, ca.investor_password_salt,
                ca.notes, ca.tags
         FROM coverage_accounts ca
         WHERE ca.manager_account_id IN ({$ph}) AND ca.is_active = 1
         ORDER BY ca.label ASC",
        $managerIds
    );
    foreach ($allCoverage as $cov) {
        $coverageByManager[(int)$cov['manager_account_id']][] = $cov;
    }
}

// ── Stream CSV ────────────────────────────────────────────────
$filename = 'vaultfx-export-' . date('Y-m-d-His') . '.csv';

header('Content-Type: text/csv; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

// UTF-8 BOM for Excel compatibility
echo "\xEF\xBB\xBF";

$out = fopen('php://output', 'w');

// Header row
$headers = ['Type', 'Server', 'Platform', 'Manager Name', 'Manager Login', 'Name', 'Login'];
if ($includePasswords) {
    $headers[] = 'Password';
    $headers[] = 'Investor Password';
}
$headers = array_merge($headers, ['Notes', 'Tags']);
fputcsv($out, $headers);

$userId = (int)Auth::userField('id');
$exportCount = 0;

foreach ($managers as $mgr) {
    $mgrPassword       = '';
    $mgrInvestorPw     = '';

    if ($includePasswords && !empty($mgr['encrypted_password']) && !empty($mgr['password_salt'])) {
        try {
            $mgrPassword = Encryption::decryptCredential($mgr['encrypted_password'], $mgr['password_salt']);
        } catch (Exception $e) {
            $mgrPassword = '[decryption error]';
        }
    }

    $row = [
        'Manager',
        $mgr['server_name'],
        $mgr['platform_type'],
        $mgr['label'],
        $mgr['login_number'],
        $mgr['label'],
        $mgr['login_number'],
    ];
    if ($includePasswords) {
        $row[] = $mgrPassword;
        $row[] = ''; // No investor pw on managers
    }
    $row[] = $mgr['notes'] ?? '';
    $row[] = $mgr['tags'] ?? '';
    fputcsv($out, $row);
    $exportCount++;

    // Coverage rows under this manager
    foreach ($coverageByManager[(int)$mgr['id']] ?? [] as $cov) {
        $covPassword   = '';
        $covInvestorPw = '';

        if ($includePasswords) {
            if (!empty($cov['encrypted_password']) && !empty($cov['password_salt'])) {
                try {
                    $covPassword = Encryption::decryptCredential($cov['encrypted_password'], $cov['password_salt']);
                } catch (Exception $e) {
                    $covPassword = '[decryption error]';
                }
            }
            if (!empty($cov['encrypted_investor_password']) && !empty($cov['investor_password_salt'])) {
                try {
                    $covInvestorPw = Encryption::decryptCredential(
                        $cov['encrypted_investor_password'],
                        $cov['investor_password_salt']
                    );
                } catch (Exception $e) {
                    $covInvestorPw = '[decryption error]';
                }
            }
        }

        $row = [
            'Coverage',
            $mgr['server_name'],
            $mgr['platform_type'],
            $mgr['label'],
            $mgr['login_number'],
            $cov['label'],
            $cov['login_number'],
        ];
        if ($includePasswords) {
            $row[] = $covPassword;
            $row[] = $covInvestorPw;
        }
        $row[] = $cov['notes'] ?? '';
        $row[] = $cov['tags'] ?? '';
        fputcsv($out, $row);
        $exportCount++;
    }
}

fclose($out);

Audit::log($userId, Audit::EXPORT, 'system', null, [
    'format'            => 'csv',
    'include_passwords' => $includePasswords,
    'rows_exported'     => $exportCount,
    'server_filter'     => $filterServerId ?: null,
], $includePasswords ? 'warning' : 'info');
