<?php
/**
 * VaultFX — Authentication Middleware
 * =====================================
 * Handles:
 *  • Login / logout flow
 *  • 2FA verification step
 *  • Session validation on every protected request
 *  • IP whitelist enforcement
 *  • Maintenance mode gate
 *  • User loading and caching
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class Auth
{
    private static ?array $user = null;

    // ── Middleware ────────────────────────────────────────────

    /**
     * Enforces authentication on protected pages.
     * Redirects to login if not authenticated.
     * If 2FA is pending, redirects to 2FA verification.
     */
    public static function require(): void
    {
        // IP whitelist gate — checked before auth
        self::enforceIpWhitelist();

        // Maintenance mode gate
        self::enforceMaintenanceMode();

        if (!Session::validate()) {
            flash('info', 'Your session has expired. Please log in again.');
            redirect('?page=login');
        }

        // 2FA pending — user authenticated with password but not TOTP yet
        if (Session::is2FAPending()) {
            $currentPage = $_GET['page'] ?? '';
            if ($currentPage !== '2fa-verify') {
                redirect('?page=2fa-verify');
            }
            return;
        }

        // Load the user record
        $user = self::user();
        if (!$user) {
            Session::destroy('User not found');
            redirect('?page=login');
        }

        // Check user is still active
        if (!$user['is_active']) {
            Session::destroy('Account deactivated');
            flash('error', 'Your account has been deactivated.');
            redirect('?page=login');
        }

        // 2FA enforcement for Admin+ roles
        if (in_array($user['role'], ['super_admin', 'admin']) && !$user['totp_enabled']) {
            $currentPage = $_GET['page'] ?? '';
            if (!in_array($currentPage, ['2fa-setup', 'my-account', 'logout'])) {
                flash('warning', '2FA is required for your role. Please set it up.');
                redirect('?page=2fa-setup');
            }
        }

        // Force password change if required
        if ($user['force_password_change']) {
            $currentPage = $_GET['page'] ?? '';
            if (!in_array($currentPage, ['my-account', 'logout'])) {
                flash('warning', 'You must change your password before continuing.');
                redirect('?page=my-account&tab=security');
            }
        }

        no_cache_headers();
    }

    /**
     * Checks authentication without redirecting (for API endpoints).
     * Returns false if not authenticated; sends JSON error.
     */
    public static function requireApi(): void
    {
        self::enforceIpWhitelist();

        if (!Session::validate() || Session::is2FAPending()) {
            json_error('Authentication required.', 401);
        }

        $user = self::user();
        if (!$user || !$user['is_active']) {
            json_error('Authentication required.', 401);
        }

        // CSRF validation for all API calls
        CSRF::requireValid();

        no_cache_headers();
    }

    // ── Login ─────────────────────────────────────────────────

    /**
     * Attempts to authenticate a user.
     *
     * @param  string $username
     * @param  string $password
     * @return array{
     *   success: bool,
     *   error: string,
     *   needs2FA: bool,
     *   user: array|null,
     *   lockExpiry: string|null
     * }
     */
    public static function attempt(string $username, string $password): array
    {
        $ip = client_ip();

        $result = [
            'success'    => false,
            'error'      => '',
            'needs2FA'   => false,
            'user'       => null,
            'lockExpiry' => null,
        ];

        // Check IP lockout first
        $ipLock = RateLimiter::isIpLocked($ip);
        if ($ipLock) {
            $result['error']      = 'Too many attempts from your IP. Try again in ' . RateLimiter::minutesRemaining($ipLock) . ' minutes.';
            $result['lockExpiry'] = $ipLock;
            Audit::log(null, 'login_failed', 'system', null, ['reason' => 'IP locked', 'username' => $username], 'warning');
            return $result;
        }

        // Check username lockout
        $userLock = RateLimiter::isUsernameLocked($username);
        if ($userLock) {
            $result['error']      = 'Account is locked. Try again in ' . RateLimiter::minutesRemaining($userLock) . ' minutes.';
            $result['lockExpiry'] = $userLock;
            // Record attempt even when locked (for audit)
            RateLimiter::recordAttempt($username, $ip, false);
            Audit::log(null, 'login_failed', 'user', null, ['reason' => 'Account locked', 'username' => $username], 'warning');
            return $result;
        }

        // Load user — ALWAYS call password_verify even if user not found
        // (timing-safe: prevents username enumeration)
        $user = DB::row(
            "SELECT * FROM users WHERE username = ? AND is_active = 1 LIMIT 1",
            [$username]
        );

        // Use a dummy hash if user not found to keep timing consistent
        $hashToVerify = $user ? $user['password_hash'] : '$argon2id$v=19$m=65536,t=4,p=1$dummydummydummy$dummydummydummydummydummydummydumm';

        $passwordValid = password_verify($password, $hashToVerify);

        if (!$user || !$passwordValid) {
            RateLimiter::recordAttempt($username, $ip, false);
            Audit::log(
                $user ? (int)$user['id'] : null,
                'login_failed',
                'user',
                $user ? (int)$user['id'] : null,
                ['reason' => 'Invalid credentials', 'username' => $username],
                'warning'
            );
            $result['error'] = 'Invalid credentials. Please try again.';
            return $result;
        }

        // Rehash if algorithm or cost has changed
        if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID)) {
            $newHash = password_hash($password, PASSWORD_ARGON2ID);
            DB::execute("UPDATE users SET password_hash = ? WHERE id = ?", [$newHash, $user['id']]);
        }

        // Successful password authentication
        RateLimiter::resetUserFailures($username);
        RateLimiter::recordAttempt($username, $ip, true);

        $needs2FA = $user['totp_enabled'] && !empty($user['totp_secret_encrypted']);

        // Init session (2FA pending if enabled)
        Session::initLogin((int)$user['id'], $needs2FA);

        // Update last login info
        DB::execute(
            "UPDATE users SET last_login_at = NOW(), last_login_ip = ? WHERE id = ?",
            [$ip, $user['id']]
        );

        // Log based on whether 2FA is still needed
        $action = $needs2FA ? 'login_2fa_pending' : 'login_success';
        Audit::log((int)$user['id'], $action, 'user', (int)$user['id'], [
            'ip'       => $ip,
            'username' => $username,
        ]);

        // Check if login is from a new IP → flag in audit
        if ($user['last_login_ip'] && $user['last_login_ip'] !== $ip) {
            Audit::log((int)$user['id'], 'login_new_ip', 'user', (int)$user['id'], [
                'previous_ip' => $user['last_login_ip'],
                'new_ip'      => $ip,
            ], 'warning');
        }

        $result['success']  = true;
        $result['needs2FA'] = $needs2FA;
        $result['user']     = $user;

        self::$user = $user;

        return $result;
    }

    // ── 2FA Verification ──────────────────────────────────────

    /**
     * Verifies a TOTP code or backup code for the 2FA step.
     *
     * @param  string $code  6-digit TOTP or 8-char backup code
     * @return bool
     */
    public static function verify2FA(string $code): bool
    {
        $userId = Session::userId();
        if (!$userId || !Session::is2FAPending()) {
            return false;
        }

        $user = self::loadUserById($userId);
        if (!$user || !$user['totp_enabled']) {
            return false;
        }

        $code = trim($code);

        // Try TOTP first
        if (preg_match('/^\d{6}$/', $code)) {
            $secret = Encryption::decryptTotpSecret($user['totp_secret_encrypted'], $userId);
            $totp   = new GoogleAuthenticator();
            if ($totp->verifyCode($secret, $code, 1)) {
                Session::complete2FA();
                Audit::log($userId, 'login_success', 'user', $userId, ['method' => '2FA TOTP']);
                return true;
            }
        }

        // Try backup codes
        if (strlen($code) === 8 && preg_match('/^[A-Z0-9]{8}$/', strtoupper($code))) {
            if (self::verifyBackupCode($user, strtoupper($code))) {
                Session::complete2FA();
                Audit::log($userId, 'login_success', 'user', $userId, ['method' => '2FA backup code']);
                return true;
            }
        }

        Audit::log($userId, 'login_failed', 'user', $userId, ['reason' => 'Invalid 2FA code'], 'warning');
        return false;
    }

    /**
     * Verifies and consumes a backup code.
     */
    private static function verifyBackupCode(array $user, string $code): bool
    {
        $storedHashes = json_decode($user['backup_codes_hash'] ?? '[]', true);
        if (empty($storedHashes)) {
            return false;
        }

        foreach ($storedHashes as $idx => $hash) {
            if (password_verify($code, $hash)) {
                // Consume (remove) the used backup code
                unset($storedHashes[$idx]);
                $newJson = json_encode(array_values($storedHashes));
                DB::execute(
                    "UPDATE users SET backup_codes_hash = ? WHERE id = ?",
                    [$newJson, $user['id']]
                );
                Audit::log((int)$user['id'], '2fa_backup_code_used', 'user', (int)$user['id'], [
                    'remaining_codes' => count($storedHashes),
                ], 'warning');
                return true;
            }
        }

        return false;
    }

    // ── Logout ────────────────────────────────────────────────

    /**
     * Logs out the current user, destroys session, and logs the event.
     */
    public static function logout(): void
    {
        $userId = Session::userId();

        if ($userId) {
            Audit::log($userId, 'logout', 'user', $userId);
        }

        Session::destroy('logout');
        self::$user = null;
    }

    // ── User Loading ──────────────────────────────────────────

    /**
     * Returns the currently authenticated user (cached per request).
     */
    public static function user(): ?array
    {
        if (self::$user !== null) {
            return self::$user;
        }

        $userId = Session::userId();
        if (!$userId) {
            return null;
        }

        self::$user = self::loadUserById($userId);
        return self::$user;
    }

    /**
     * Returns a specific field of the current user.
     */
    public static function userField(string $field, mixed $default = null): mixed
    {
        $user = self::user();
        return $user[$field] ?? $default;
    }

    /**
     * Returns true if the user is logged in and 2FA complete.
     */
    public static function check(): bool
    {
        return Session::validate()
            && !Session::is2FAPending()
            && self::user() !== null;
    }

    /**
     * Loads a user record by ID from the DB.
     */
    private static function loadUserById(int $id): ?array
    {
        return DB::row(
            "SELECT id, username, email, role, can_view_passwords, is_active,
                    totp_secret_encrypted, totp_enabled, backup_codes_hash,
                    force_password_change, password_changed_at,
                    last_login_at, last_login_ip, theme_preference, pinned_credentials,
                    created_at
             FROM users WHERE id = ? LIMIT 1",
            [$id]
        );
    }

    // ── Gates ─────────────────────────────────────────────────

    /**
     * Enforces IP whitelist. Kills the request if IP is not allowed.
     */
    private static function enforceIpWhitelist(): void
    {
        if (!ip_is_whitelisted(client_ip())) {
            http_response_code(403);
            die('Access denied. Your IP address is not authorized.');
        }
    }

    /**
     * Enforces maintenance mode. Only Super Admins can bypass.
     */
    private static function enforceMaintenanceMode(): void
    {
        if (setting('maintenance_mode') !== '1') {
            return;
        }

        // Allow Super Admins to pass through
        $userId = Session::userId();
        if ($userId) {
            $role = DB::scalar("SELECT role FROM users WHERE id = ?", [$userId]);
            if ($role === 'super_admin') {
                return;
            }
        }

        http_response_code(503);
        ?><!DOCTYPE html>
        <html lang="en"><head><title>Maintenance Mode</title>
        <style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0f172a;color:#f8fafc;}
        .card{text-align:center;padding:2rem;max-width:400px;}</style></head>
        <body><div class="card"><h1>&#128274; Maintenance Mode</h1>
        <p>VaultFX is temporarily offline for maintenance. Please try again later.</p></div></body></html>
        <?php
        exit;
    }
}
