<?php
/**
 * VaultFX — Password Reveal Endpoint
 * =====================================
 * CRITICAL SECURITY ENDPOINT
 *
 * Passwords are NEVER pre-loaded into any page, HTML, or JS variable.
 * They are fetched only on explicit user request, subject to:
 *   1. Valid authenticated session (not 2FA-pending)
 *   2. Valid CSRF token
 *   3. user.can_view_passwords = true (or super_admin)
 *   4. NOT restricted_viewer role (absolute block)
 *   5. Server-level access check
 *   6. Full audit trail written before returning data
 *
 * POST /api/reveal-password.php
 * Required: csrf_token (header or field)
 * Required: type ('manager' | 'coverage')
 * Required: id (integer)
 */

define('VAULTFX_BOOT', true);
require_once dirname(__DIR__, 2) . '/config/config.php';

// ── PHP hardening ──────────────────────────────────────────────
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', PHP_ERROR_LOG);
error_reporting(E_ALL);

// ── Bootstrap ─────────────────────────────────────────────────
require_once dirname(__DIR__) . '/includes/helpers.php';
require_once dirname(__DIR__) . '/includes/db.php';
require_once dirname(__DIR__) . '/includes/session.php';
require_once dirname(__DIR__) . '/includes/csrf.php';
require_once dirname(__DIR__) . '/includes/audit.php';
require_once dirname(__DIR__) . '/includes/rbac.php';
require_once dirname(__DIR__) . '/includes/auth.php';
require_once dirname(__DIR__) . '/includes/encryption.php';
require_once dirname(__DIR__) . '/lib/GoogleAuthenticator.php';
require_once ENCRYPTION_KEY_FILE;

Session::start();

// ── Only accept POST ──────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_error('Method not allowed.', 405);
}

// ── Full authentication + CSRF check ─────────────────────────
Auth::requireApi();

$user = Auth::user();

// ── Role gate: restricted_viewer can NEVER reveal passwords ──
// NOTE: The reveal button must not even render in DOM for this role,
// but we enforce the rule on the server regardless.
if (RBAC::is(RBAC::RESTRICTED_VIEWER)) {
    Audit::log(
        (int)$user['id'],
        'password_reveal_denied',
        null, null,
        ['reason' => 'Role is restricted_viewer'],
        'warning'
    );
    json_error('Permission denied.', 403);
}

// ── Permission check: can_view_passwords ─────────────────────
if (!RBAC::canViewPasswords()) {
    Audit::log(
        (int)$user['id'],
        'password_reveal_denied',
        null, null,
        ['reason' => 'can_view_passwords is false'],
        'warning'
    );
    json_error('You do not have permission to view passwords.', 403);
}

// ── Input validation ──────────────────────────────────────────
$type = post('type');
$id   = param_int('id', 0, $_POST);

if (!in_array($type, ['manager', 'coverage', 'coverage_investor'], true)) {
    json_error('Invalid credential type.', 400);
}

if ($id <= 0) {
    json_error('Invalid credential ID.', 400);
}

// ── Load the credential record ────────────────────────────────
if ($type === 'manager') {
    $credential = DB::row(
        "SELECT ma.id, ma.label, ma.login_number, ma.encrypted_password, ma.password_salt,
                ma.key_version, ma.server_id, s.name AS server_name
         FROM manager_accounts ma
         JOIN servers s ON s.id = ma.server_id
         WHERE ma.id = ? AND ma.is_active = 1",
        [$id]
    );
    $coverageType = null;
} else {
    // Both 'coverage' and 'coverage_investor' use coverage_accounts
    $credential = DB::row(
        "SELECT ca.id, ca.label, ca.login_number, ca.encrypted_password, ca.password_salt,
                ca.key_version, ca.server_id, ca.manager_account_id,
                ca.encrypted_investor_password, ca.investor_password_salt,
                s.name AS server_name
         FROM coverage_accounts ca
         JOIN servers s ON s.id = ca.server_id
         WHERE ca.id = ? AND ca.is_active = 1",
        [$id]
    );
    $coverageType = $type; // 'coverage' or 'coverage_investor'
}

if (!$credential) {
    json_error('Credential not found.', 404);
}

// ── Access gate ───────────────────────────────────────────────
$accessGranted = $type === 'manager'
    ? RBAC::canAccessManager((int)$id)
    : RBAC::canAccessManager((int)$credential['manager_account_id']);

if (!$accessGranted) {
    Audit::log(
        (int)$user['id'],
        'password_reveal_denied',
        $type . '_account',
        $id,
        ['reason' => 'No manager/server access', 'server_id' => $credential['server_id']],
        'warning'
    );
    json_error('Permission denied.', 403);
}

// ── Investor password check ───────────────────────────────────
if ($type === 'coverage_investor') {
    if (empty($credential['encrypted_investor_password'])) {
        json_error('No investor password set for this account.', 404);
    }
    try {
        $plaintext = Encryption::decryptCredential(
            $credential['encrypted_investor_password'],
            $credential['investor_password_salt']
        );
    } catch (RuntimeException $e) {
        Audit::log((int)$user['id'], 'decryption_failed', 'coverage_account', $id,
            ['error' => $e->getMessage(), 'field' => 'investor_password'], 'critical');
        json_error('Decryption failed. This event has been logged.', 500);
    }

    Audit::logReveal((int)$user['id'], 'coverage_investor', $id, $credential['label']);
    $revealTimeout = (int)setting('password_reveal_timeout_seconds', 30);
    json_success([
        'password'       => $plaintext,
        'label'          => $credential['label'],
        'login_number'   => $credential['login_number'],
        'reveal_timeout' => $revealTimeout,
    ], 'Investor password retrieved successfully.');
}

// ── Decrypt the main password ─────────────────────────────────
try {
    $plaintext = Encryption::decryptCredential(
        $credential['encrypted_password'],
        $credential['password_salt']
    );
} catch (RuntimeException $e) {
    Audit::log(
        (int)$user['id'],
        'decryption_failed',
        $type . '_account',
        $id,
        ['error' => $e->getMessage()],
        'critical'
    );
    app_log('critical', 'Decryption failed for credential', [
        'type' => $type,
        'id'   => $id,
        'user' => $user['id'],
        'err'  => $e->getMessage(),
    ]);
    json_error('Decryption failed. This event has been logged.', 500);
}

// ── Write audit entry BEFORE returning to caller ─────────────
Audit::logReveal(
    (int)$user['id'],
    $type,
    $id,
    $credential['label']
);

// ── Return the decrypted password ─────────────────────────────
$revealTimeout = (int)setting('password_reveal_timeout_seconds', 30);

json_success([
    'password'       => $plaintext,
    'label'          => $credential['label'],
    'login_number'   => $credential['login_number'],
    'reveal_timeout' => $revealTimeout,
], 'Password retrieved successfully.');
