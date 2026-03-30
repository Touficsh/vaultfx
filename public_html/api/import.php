<?php
/**
 * VaultFX — Credential Import API
 * =================================
 * POST /api/import.php?action=preview|commit
 *
 * Imports manager and coverage accounts from a CSV file.
 * Expected CSV columns (case-insensitive):
 *   Type, Server, Platform, Manager Name, Manager Login,
 *   Name, Login, Password, Investor Password, Notes, Tags
 *
 * "Type" must be "Manager" or "Coverage".
 * Servers must already exist. Unrecognised server names are rejected.
 * Duplicate login numbers on the same server are skipped with a warning.
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
require_once ENCRYPTION_KEY_FILE;

Session::start();
Auth::requireApi();
RBAC::assert(RBAC::canImport(), true);

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

// ── Helper: parse uploaded CSV ────────────────────────────────
function parseImportCsv(): array
{
    if (empty($_FILES['csv_file']) || $_FILES['csv_file']['error'] !== UPLOAD_ERR_OK) {
        json_error('No CSV file uploaded.', 400);
    }

    $file = $_FILES['csv_file']['tmp_name'];
    $size = $_FILES['csv_file']['size'];

    if ($size > 2 * 1024 * 1024) {
        json_error('CSV file must be under 2 MB.', 400);
    }

    $handle = fopen($file, 'r');
    if (!$handle) {
        json_error('Failed to read uploaded file.', 500);
    }

    // Strip UTF-8 BOM if present
    $bom = fread($handle, 3);
    if ($bom !== "\xEF\xBB\xBF") {
        rewind($handle);
    }

    $rawHeaders = fgetcsv($handle);
    if (!$rawHeaders) {
        fclose($handle);
        json_error('CSV file is empty or unreadable.', 400);
    }

    $headers = array_map(fn($h) => strtolower(trim($h)), $rawHeaders);

    $required = ['type', 'server', 'name', 'login', 'password'];
    foreach ($required as $col) {
        if (!in_array($col, $headers)) {
            fclose($handle);
            json_error("Missing required CSV column: \"{$col}\".", 400);
        }
    }

    $rows = [];
    $lineNum = 1;
    while (($data = fgetcsv($handle)) !== false) {
        $lineNum++;
        if (count($data) < count($headers)) {
            continue; // Skip short rows silently
        }
        $row = array_combine($headers, array_slice($data, 0, count($headers)));
        $row['_line'] = $lineNum;
        $rows[]       = $row;
    }
    fclose($handle);
    return $rows;
}

// ── Preview ───────────────────────────────────────────────────
if ($action === 'preview') {
    $rows = parseImportCsv();

    // Load all active servers for lookup
    $serverMap = [];
    foreach (DB::rows("SELECT id, name, platform_type FROM servers WHERE is_active = 1") as $s) {
        $serverMap[strtolower(trim($s['name']))] = $s;
    }

    $preview  = [];
    $errors   = [];

    foreach ($rows as $row) {
        $line   = $row['_line'];
        $type   = strtolower(trim($row['type'] ?? ''));
        $srvKey = strtolower(trim($row['server'] ?? ''));
        $name   = trim($row['name'] ?? '');
        $login  = trim($row['login'] ?? '');
        $pass   = trim($row['password'] ?? '');

        if (!in_array($type, ['manager', 'coverage'])) {
            $errors[] = "Line {$line}: Unknown type \"{$row['type']}\". Must be Manager or Coverage.";
            continue;
        }

        if (!isset($serverMap[$srvKey])) {
            $errors[] = "Line {$line}: Server \"{$row['server']}\" not found.";
            continue;
        }

        if (empty($name)) {
            $errors[] = "Line {$line}: Name is required.";
            continue;
        }

        if (empty($login)) {
            $errors[] = "Line {$line}: Login is required.";
            continue;
        }

        if ($type === 'manager' && empty($pass)) {
            $errors[] = "Line {$line}: Password is required for manager rows.";
            continue;
        }

        if ($type === 'coverage') {
            $mgrLogin = trim($row['manager login'] ?? '');
            if (empty($mgrLogin)) {
                $errors[] = "Line {$line}: Coverage rows require a Manager Login column.";
                continue;
            }
        }

        $preview[] = [
            'line'           => $line,
            'type'           => $type,
            'server_name'    => $serverMap[$srvKey]['name'],
            'server_id'      => (int)$serverMap[$srvKey]['id'],
            'platform_type'  => $serverMap[$srvKey]['platform_type'],
            'manager_login'  => trim($row['manager login'] ?? ''),
            'name'           => $name,
            'login'          => $login,
            'has_password'   => !empty($pass),
            'has_investor_pw'=> !empty(trim($row['investor password'] ?? '')),
            'notes'          => trim($row['notes'] ?? ''),
            'tags'           => trim($row['tags'] ?? ''),
        ];
    }

    json_success([
        'preview' => $preview,
        'errors'  => $errors,
        'total'   => count($preview),
    ]);
}

// ── Commit ────────────────────────────────────────────────────
if ($action === 'commit') {
    $rows = parseImportCsv();

    $serverMap = [];
    foreach (DB::rows("SELECT id, name, platform_type FROM servers WHERE is_active = 1") as $s) {
        $serverMap[strtolower(trim($s['name']))] = $s;
    }

    $userId   = (int)Auth::userField('id');
    $imported = 0;
    $skipped  = 0;
    $errors   = [];

    DB::beginTransaction();
    try {
        foreach ($rows as $row) {
            $line   = $row['_line'];
            $type   = strtolower(trim($row['type'] ?? ''));
            $srvKey = strtolower(trim($row['server'] ?? ''));
            $name   = trim($row['name'] ?? '');
            $login  = trim($row['login'] ?? '');
            $pass   = trim($row['password'] ?? '');

            if (!in_array($type, ['manager', 'coverage'])) continue;
            if (!isset($serverMap[$srvKey])) continue;
            if (empty($name) || empty($login)) continue;

            $server = $serverMap[$srvKey];

            if ($type === 'manager') {
                if (empty($pass)) continue;

                // Skip duplicates (same server + login)
                $exists = DB::scalar(
                    "SELECT id FROM manager_accounts WHERE server_id = ? AND login_number = ? AND is_active = 1",
                    [(int)$server['id'], $login]
                );
                if ($exists) {
                    $skipped++;
                    $errors[] = "Line {$line}: Manager login {$login} on {$server['name']} already exists — skipped.";
                    continue;
                }

                $encrypted = Encryption::encryptCredential($pass);
                DB::execute(
                    "INSERT INTO manager_accounts
                        (server_id, label, login_number, encrypted_password, password_salt,
                         key_version, password_last_changed, notes, tags, created_by)
                     VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)",
                    [
                        (int)$server['id'],
                        Validation::sanitizeText($name, 100),
                        $login,
                        $encrypted['encrypted_blob'],
                        $encrypted['salt'],
                        $encrypted['key_version'],
                        Validation::sanitizeText($row['notes'] ?? '', 5000) ?: null,
                        Validation::sanitizeText($row['tags'] ?? '', 500) ?: null,
                        $userId,
                    ]
                );
                $imported++;

            } elseif ($type === 'coverage') {
                $mgrLogin    = trim($row['manager login'] ?? '');
                $investorPw  = trim($row['investor password'] ?? '');

                if (empty($mgrLogin) || empty($pass)) continue;

                // Find the parent manager
                $mgr = DB::row(
                    "SELECT id FROM manager_accounts WHERE server_id = ? AND login_number = ? AND is_active = 1",
                    [(int)$server['id'], $mgrLogin]
                );
                if (!$mgr) {
                    $errors[] = "Line {$line}: Manager login {$mgrLogin} not found on {$server['name']} — skipped.";
                    $skipped++;
                    continue;
                }

                // Skip duplicates
                $exists = DB::scalar(
                    "SELECT id FROM coverage_accounts WHERE manager_account_id = ? AND login_number = ? AND is_active = 1",
                    [(int)$mgr['id'], $login]
                );
                if ($exists) {
                    $skipped++;
                    $errors[] = "Line {$line}: Coverage login {$login} under manager {$mgrLogin} already exists — skipped.";
                    continue;
                }

                $encrypted = Encryption::encryptCredential($pass);

                $invBlob = $invSalt = null;
                $invVer  = null;
                if (!empty($investorPw)) {
                    $encInv  = Encryption::encryptCredential($investorPw);
                    $invBlob = $encInv['encrypted_blob'];
                    $invSalt = $encInv['salt'];
                    $invVer  = $encInv['key_version'];
                }

                DB::execute(
                    "INSERT INTO coverage_accounts
                        (manager_account_id, server_id, label, login_number,
                         encrypted_password, password_salt, key_version,
                         encrypted_investor_password, investor_password_salt, investor_key_version,
                         password_last_changed, notes, tags, created_by)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)",
                    [
                        (int)$mgr['id'],
                        (int)$server['id'],
                        Validation::sanitizeText($name, 100),
                        $login,
                        $encrypted['encrypted_blob'],
                        $encrypted['salt'],
                        $encrypted['key_version'],
                        $invBlob,
                        $invSalt,
                        $invVer,
                        Validation::sanitizeText($row['notes'] ?? '', 5000) ?: null,
                        Validation::sanitizeText($row['tags'] ?? '', 500) ?: null,
                        $userId,
                    ]
                );
                $imported++;
            }
        }

        DB::commit();
    } catch (Exception $e) {
        DB::rollBack();
        app_log('error', 'Import commit failed: ' . $e->getMessage());
        json_error('Import failed. Please check the CSV and try again.', 500);
    }

    Audit::log($userId, Audit::EXPORT, 'system', null, [
        'action'   => 'import',
        'imported' => $imported,
        'skipped'  => $skipped,
    ], 'warning');

    json_success([
        'imported' => $imported,
        'skipped'  => $skipped,
        'errors'   => $errors,
    ], "Import complete: {$imported} imported, {$skipped} skipped.");
}

json_error('Unknown action.', 400);
