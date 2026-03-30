<?php
/**
 * VaultFX — Key Rotation API
 * ============================
 * POST /api/keys.php?action=status|rotate
 *
 * status  → Returns count of credentials on each key version.
 * rotate  → Re-encrypts all credentials currently on older key versions
 *            with the current (latest) master key. Runs in a single
 *            transaction per table for atomicity.
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
require_once dirname(__DIR__) . '/includes/encryption.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();
Auth::requireApi();
RBAC::assert(RBAC::canRotateKeys(), true);

$action = $_GET['action'] ?? ($_POST['action'] ?? '');

$currentVersion = vaultfx_current_key_version();

// ── Status ────────────────────────────────────────────────────
if ($action === 'status') {
    $managerVersions = DB::rows(
        "SELECT key_version, COUNT(*) AS cnt
         FROM manager_accounts WHERE is_active = 1
         GROUP BY key_version ORDER BY key_version"
    );
    $coverageVersions = DB::rows(
        "SELECT key_version, COUNT(*) AS cnt
         FROM coverage_accounts WHERE is_active = 1
         GROUP BY key_version ORDER BY key_version"
    );
    $investorVersions = DB::rows(
        "SELECT investor_key_version AS key_version, COUNT(*) AS cnt
         FROM coverage_accounts
         WHERE is_active = 1 AND encrypted_investor_password IS NOT NULL
         GROUP BY investor_key_version ORDER BY investor_key_version"
    );

    $outdatedManagers  = 0;
    $outdatedCoverage  = 0;
    $outdatedInvestor  = 0;

    foreach ($managerVersions as $r) {
        if ((int)$r['key_version'] < $currentVersion) {
            $outdatedManagers += (int)$r['cnt'];
        }
    }
    foreach ($coverageVersions as $r) {
        if ((int)$r['key_version'] < $currentVersion) {
            $outdatedCoverage += (int)$r['cnt'];
        }
    }
    foreach ($investorVersions as $r) {
        if ((int)$r['key_version'] < $currentVersion) {
            $outdatedInvestor += (int)$r['cnt'];
        }
    }

    json_success([
        'current_key_version' => $currentVersion,
        'manager_versions'    => $managerVersions,
        'coverage_versions'   => $coverageVersions,
        'investor_versions'   => $investorVersions,
        'outdated_total'      => $outdatedManagers + $outdatedCoverage + $outdatedInvestor,
        'outdated_managers'   => $outdatedManagers,
        'outdated_coverage'   => $outdatedCoverage,
        'outdated_investor'   => $outdatedInvestor,
    ]);
}

// ── Rotate ────────────────────────────────────────────────────
if ($action === 'rotate') {
    $userId   = (int)Auth::userField('id');
    $rotated  = 0;
    $failed   = 0;
    $errors   = [];

    // ── Rotate manager passwords ─────────────────────────────
    $managers = DB::rows(
        "SELECT id, encrypted_password, password_salt, key_version
         FROM manager_accounts
         WHERE is_active = 1 AND key_version < ?",
        [$currentVersion]
    );

    foreach ($managers as $mgr) {
        DB::beginTransaction();
        try {
            $new = Encryption::rotateCredential($mgr['encrypted_password'], $mgr['password_salt']);
            DB::execute(
                "UPDATE manager_accounts
                 SET encrypted_password=?, password_salt=?, key_version=?
                 WHERE id=?",
                [$new['encrypted_blob'], $new['salt'], $new['key_version'], (int)$mgr['id']]
            );
            DB::commit();
            $rotated++;
        } catch (Exception $e) {
            DB::rollBack();
            $failed++;
            $errors[] = "Manager ID {$mgr['id']}: " . $e->getMessage();
            app_log('error', 'Key rotation failed for manager ' . $mgr['id'] . ': ' . $e->getMessage());
        }
    }

    // ── Rotate coverage passwords ─────────────────────────────
    $coverage = DB::rows(
        "SELECT id, encrypted_password, password_salt, key_version,
                encrypted_investor_password, investor_password_salt, investor_key_version
         FROM coverage_accounts
         WHERE is_active = 1
           AND (key_version < ?
                OR (encrypted_investor_password IS NOT NULL AND investor_key_version < ?))",
        [$currentVersion, $currentVersion]
    );

    foreach ($coverage as $cov) {
        DB::beginTransaction();
        try {
            $setParts = [];
            $params   = [];

            // Rotate main password if outdated
            if ((int)$cov['key_version'] < $currentVersion) {
                $new = Encryption::rotateCredential($cov['encrypted_password'], $cov['password_salt']);
                $setParts[] = 'encrypted_password=?, password_salt=?, key_version=?';
                $params[]   = $new['encrypted_blob'];
                $params[]   = $new['salt'];
                $params[]   = $new['key_version'];
                $rotated++;
            }

            // Rotate investor password if outdated
            if (
                !empty($cov['encrypted_investor_password']) &&
                !empty($cov['investor_password_salt']) &&
                (int)$cov['investor_key_version'] < $currentVersion
            ) {
                $newInv = Encryption::rotateCredential(
                    $cov['encrypted_investor_password'],
                    $cov['investor_password_salt']
                );
                $setParts[] = 'encrypted_investor_password=?, investor_password_salt=?, investor_key_version=?';
                $params[]   = $newInv['encrypted_blob'];
                $params[]   = $newInv['salt'];
                $params[]   = $newInv['key_version'];
                $rotated++;
            }

            if (!empty($setParts)) {
                $params[] = (int)$cov['id'];
                DB::execute(
                    "UPDATE coverage_accounts SET " . implode(', ', $setParts) . " WHERE id=?",
                    $params
                );
            }

            DB::commit();
        } catch (Exception $e) {
            DB::rollBack();
            $failed++;
            $errors[] = "Coverage ID {$cov['id']}: " . $e->getMessage();
            app_log('error', 'Key rotation failed for coverage ' . $cov['id'] . ': ' . $e->getMessage());
        }
    }

    Audit::log($userId, Audit::KEY_ROTATION, 'system', null, [
        'rotated'             => $rotated,
        'failed'              => $failed,
        'target_key_version'  => $currentVersion,
    ], $failed > 0 ? 'critical' : 'warning');

    $message = "Key rotation complete: {$rotated} credentials re-encrypted.";
    if ($failed > 0) {
        $message .= " {$failed} failed — check error log.";
    }

    json_success([
        'rotated' => $rotated,
        'failed'  => $failed,
        'errors'  => $errors,
    ], $message);
}

json_error('Unknown action.', 400);
