<?php
/**
 * VaultFX — Session Hardening & Management
 * ==========================================
 * Implements:
 *  • Hardened session configuration (HTTPOnly, Secure, SameSite=Strict)
 *  • Session binding to IP subnet + user agent hash
 *  • Idle timeout (30 min) + absolute timeout (8 hours)
 *  • One active session per user (concurrent session prevention)
 *  • Clean session destruction on logout
 *
 * Call Session::start() before ANYTHING else in index.php.
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class Session
{
    private const KEY_USER_ID      = '_uid';
    private const KEY_LOGIN_AT     = '_login_at';
    private const KEY_LAST_ACTIVE  = '_last_active';
    private const KEY_IP_SUBNET    = '_ip_subnet';
    private const KEY_UA_HASH      = '_ua_hash';
    private const KEY_2FA_PENDING  = '_2fa_pending';    // Set between pw and 2FA step
    private const KEY_TOTP_DONE    = '_totp_done';

    /**
     * Configures and starts the session.
     * Must be called before any output is sent.
     */
    public static function start(): void
    {
        // Harden session cookie and transport
        ini_set('session.cookie_httponly',      '1');
        ini_set('session.cookie_secure',        defined('APP_ENV') && APP_ENV === 'production' ? '1' : '0');
        ini_set('session.cookie_samesite',      'Strict');
        ini_set('session.use_strict_mode',      '1');
        ini_set('session.use_only_cookies',     '1');
        ini_set('session.use_trans_sid',        '0');
        ini_set('session.gc_maxlifetime',       (string)SESSION_IDLE_TIMEOUT);
        ini_set('session.cookie_lifetime',      '0');
        ini_set('session.sid_length',           '48');
        ini_set('session.sid_bits_per_character', '6');

        session_name(SESSION_NAME);

        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
    }

    /**
     * Validates the active session on every request.
     * Checks IP subnet binding, UA binding, idle timeout, absolute timeout.
     *
     * @return bool  True if session is valid, false if expired/hijacked
     */
    public static function validate(): bool
    {
        if (empty($_SESSION[self::KEY_USER_ID])) {
            return false;
        }

        $ip      = client_ip();
        $subnet  = ip_subnet($ip);
        $uaHash  = ua_hash(client_ua());
        $now     = time();

        // Check IP subnet binding
        if (isset($_SESSION[self::KEY_IP_SUBNET]) &&
            $_SESSION[self::KEY_IP_SUBNET] !== $subnet) {
            self::destroy('IP subnet changed');
            return false;
        }

        // Check user agent binding
        if (isset($_SESSION[self::KEY_UA_HASH]) &&
            !hash_equals($_SESSION[self::KEY_UA_HASH], $uaHash)) {
            self::destroy('User agent changed');
            return false;
        }

        // Check idle timeout
        if (isset($_SESSION[self::KEY_LAST_ACTIVE])) {
            $idleSeconds = $now - $_SESSION[self::KEY_LAST_ACTIVE];
            if ($idleSeconds > SESSION_IDLE_TIMEOUT) {
                self::destroy('Idle timeout');
                return false;
            }
        }

        // Check absolute timeout
        if (isset($_SESSION[self::KEY_LOGIN_AT])) {
            $sessionAge = $now - $_SESSION[self::KEY_LOGIN_AT];
            if ($sessionAge > SESSION_ABSOLUTE_MAX) {
                self::destroy('Absolute timeout');
                return false;
            }
        }

        // Update last activity
        $_SESSION[self::KEY_LAST_ACTIVE] = $now;
        self::syncActivityToDb();

        return true;
    }

    /**
     * Initializes a new authenticated session after successful login.
     *
     * @param  int    $userId    Authenticated user ID
     * @param  bool   $needs2FA  Whether 2FA verification is still pending
     */
    public static function initLogin(int $userId, bool $needs2FA = false): void
    {
        // Destroy any existing session first (concurrent session prevention)
        self::invalidateUserSessions($userId);

        // Regenerate session ID to prevent fixation attacks
        session_regenerate_id(true);

        $ip     = client_ip();
        $subnet = ip_subnet($ip);
        $ua     = client_ua();
        $now    = time();

        $_SESSION[self::KEY_USER_ID]     = $userId;
        $_SESSION[self::KEY_LOGIN_AT]    = $now;
        $_SESSION[self::KEY_LAST_ACTIVE] = $now;
        $_SESSION[self::KEY_IP_SUBNET]   = $subnet;
        $_SESSION[self::KEY_UA_HASH]     = ua_hash($ua);
        $_SESSION[self::KEY_2FA_PENDING] = $needs2FA;
        $_SESSION[self::KEY_TOTP_DONE]   = !$needs2FA;

        // Register session in DB
        self::registerInDb($userId, $ip, $subnet, $ua);
    }

    /**
     * Marks 2FA as completed for the current session.
     */
    public static function complete2FA(): void
    {
        $_SESSION[self::KEY_2FA_PENDING] = false;
        $_SESSION[self::KEY_TOTP_DONE]   = true;
        session_regenerate_id(true);
    }

    /**
     * Returns the current authenticated user ID, or null.
     */
    public static function userId(): ?int
    {
        $id = $_SESSION[self::KEY_USER_ID] ?? null;
        return $id !== null ? (int)$id : null;
    }

    /**
     * Returns whether 2FA verification is pending (user authenticated but not yet 2FA'd).
     */
    public static function is2FAPending(): bool
    {
        return !empty($_SESSION[self::KEY_2FA_PENDING]);
    }

    /**
     * Returns whether 2FA has been completed.
     */
    public static function is2FADone(): bool
    {
        return !empty($_SESSION[self::KEY_TOTP_DONE]);
    }

    /**
     * Returns seconds until idle timeout.
     */
    public static function idleSecondsRemaining(): int
    {
        $lastActive = $_SESSION[self::KEY_LAST_ACTIVE] ?? time();
        return max(0, SESSION_IDLE_TIMEOUT - (time() - $lastActive));
    }

    /**
     * Destroys the current session completely and cleanly.
     *
     * @param  string $reason  Log reason for destruction
     */
    public static function destroy(string $reason = 'logout'): void
    {
        $userId    = self::userId();
        $sessionId = session_id();

        // Remove from DB
        if ($sessionId) {
            DB::execute("DELETE FROM active_sessions WHERE id = ?", [$sessionId]);
        }

        // Clear all session data
        $_SESSION = [];

        // Delete the session cookie
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                [
                    'expires'  => time() - 42000,
                    'path'     => $params['path'],
                    'domain'   => $params['domain'],
                    'secure'   => $params['secure'],
                    'httponly' => $params['httponly'],
                    'samesite' => 'Strict',
                ]
            );
        }

        session_unset();
        session_destroy();

        app_log('info', "Session destroyed: {$reason}", ['user_id' => $userId]);
    }

    /**
     * Pings session to keep it alive (called by session-monitor.js).
     * Returns remaining seconds.
     */
    public static function ping(): int
    {
        if (!self::validate()) {
            return 0;
        }
        return self::idleSecondsRemaining();
    }

    // ── Private Helpers ───────────────────────────────────────

    /**
     * Registers the new session in the active_sessions table.
     * Enforces one session per user by deleting old ones.
     */
    private static function registerInDb(int $userId, string $ip, string $subnet, string $ua): void
    {
        try {
            DB::execute(
                "INSERT INTO active_sessions (id, user_id, ip_address, ip_subnet, user_agent, user_agent_hash, login_at, last_activity)
                 VALUES (?, ?, ?, ?, ?, ?, NOW(), NOW())",
                [session_id(), $userId, $ip, $subnet, $ua, ua_hash($ua)]
            );
        } catch (Exception $e) {
            app_log('error', 'Failed to register session in DB: ' . $e->getMessage());
        }
    }

    /**
     * Updates last_activity in the DB (throttled to once per minute to reduce write load).
     */
    private static function syncActivityToDb(): void
    {
        static $lastSync = 0;
        $now = time();

        if ($now - $lastSync < 60) {
            return;
        }
        $lastSync = $now;

        try {
            DB::execute(
                "UPDATE active_sessions SET last_activity = NOW() WHERE id = ?",
                [session_id()]
            );
        } catch (Exception $e) {
            // Non-fatal — don't disrupt the request
        }
    }

    /**
     * Destroys all active sessions for a given user (concurrent session prevention).
     */
    private static function invalidateUserSessions(int $userId): void
    {
        try {
            DB::execute(
                "DELETE FROM active_sessions WHERE user_id = ?",
                [$userId]
            );
        } catch (Exception $e) {
            app_log('error', 'Failed to invalidate user sessions: ' . $e->getMessage());
        }
    }
}
