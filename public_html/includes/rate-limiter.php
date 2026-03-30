<?php
/**
 * VaultFX — Login Rate Limiter
 * =============================
 * Progressive lockout:
 *  • 5  failures  → lock 15 minutes
 *  • 10 failures  → lock 1 hour
 *  • 20 failures  → lock 24 hours
 *
 * Tracked separately by username AND by IP address.
 * Lockout is stored in the users table (for known users)
 * and enforced via login_attempts table (for unknown users / IP blocks).
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class RateLimiter
{
    // Progressive lockout thresholds (configurable via settings)
    private const TIER1_THRESHOLD = 5;
    private const TIER1_DURATION  = 15;    // minutes

    private const TIER2_THRESHOLD = 10;
    private const TIER2_DURATION  = 60;    // minutes

    private const TIER3_THRESHOLD = 20;
    private const TIER3_DURATION  = 1440;  // minutes (24 hours)

    private const WINDOW_MINUTES  = 30;    // Sliding window for counting failures

    /**
     * Records a login attempt.
     *
     * @param  string $username
     * @param  string $ip
     * @param  bool   $success
     */
    public static function recordAttempt(string $username, string $ip, bool $success): void
    {
        DB::execute(
            "INSERT INTO login_attempts (username, ip_address, user_agent, attempted_at, success)
             VALUES (?, ?, ?, NOW(), ?)",
            [$username, $ip, client_ua(), $success ? 1 : 0]
        );

        if (!$success) {
            // Update the users table lockout if this is a known user
            self::applyUserLockout($username);
        }
    }

    /**
     * Checks if a username is currently locked out.
     * Returns lock expiry time as string or null if not locked.
     */
    public static function isUsernameLocked(string $username): ?string
    {
        $user = DB::row(
            "SELECT locked_until FROM users WHERE username = ? AND is_active = 1",
            [$username]
        );

        if (!$user || empty($user['locked_until'])) {
            return null;
        }

        $lockedUntil = new DateTime($user['locked_until'], new DateTimeZone('UTC'));
        $now         = new DateTime('now', new DateTimeZone('UTC'));

        if ($lockedUntil > $now) {
            return $user['locked_until'];
        }

        // Lock expired — clear it
        DB::execute(
            "UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE username = ?",
            [$username]
        );

        return null;
    }

    /**
     * Checks if an IP is locked out based on recent failed attempts.
     * Returns lock expiry time or null if not locked.
     */
    public static function isIpLocked(string $ip): ?string
    {
        $windowStart = (new DateTime("-" . self::WINDOW_MINUTES . " minutes", new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $failCount = (int)DB::scalar(
            "SELECT COUNT(*) FROM login_attempts
             WHERE ip_address = ? AND success = 0 AND attempted_at >= ?",
            [$ip, $windowStart]
        );

        if ($failCount < self::TIER1_THRESHOLD) {
            return null;
        }

        // Find the last failed attempt time
        $lastFail = DB::scalar(
            "SELECT MAX(attempted_at) FROM login_attempts
             WHERE ip_address = ? AND success = 0 AND attempted_at >= ?",
            [$ip, $windowStart]
        );

        $lockMinutes = self::getLockDuration($failCount);
        $lockExpiry  = (new DateTime($lastFail, new DateTimeZone('UTC')))
            ->modify("+{$lockMinutes} minutes")
            ->format('Y-m-d H:i:s');

        $now = (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        return $lockExpiry > $now ? $lockExpiry : null;
    }

    /**
     * Returns minutes remaining on a lockout, given expiry datetime string.
     */
    public static function minutesRemaining(string $lockedUntil): int
    {
        $expiry = new DateTime($lockedUntil, new DateTimeZone('UTC'));
        $now    = new DateTime('now', new DateTimeZone('UTC'));
        $diff   = $now->diff($expiry);

        return max(1, ($diff->h * 60) + $diff->i + 1);
    }

    /**
     * Resets the failed login count for a user after successful login.
     */
    public static function resetUserFailures(string $username): void
    {
        DB::execute(
            "UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = ?",
            [$username]
        );
    }

    /**
     * Cleans up old login attempt records (can be called periodically).
     */
    public static function cleanup(): void
    {
        DB::execute(
            "DELETE FROM login_attempts WHERE attempted_at < DATE_SUB(NOW(), INTERVAL 24 HOUR)"
        );
    }

    /**
     * Returns the lock duration in minutes for a given failure count.
     */
    private static function getLockDuration(int $failCount): int
    {
        if ($failCount >= self::TIER3_THRESHOLD) {
            return self::TIER3_DURATION;
        }
        if ($failCount >= self::TIER2_THRESHOLD) {
            return self::TIER2_DURATION;
        }
        return self::TIER1_DURATION;
    }

    /**
     * Updates the users table lockout for a known username.
     */
    private static function applyUserLockout(string $username): void
    {
        $windowStart = (new DateTime("-" . self::WINDOW_MINUTES . " minutes", new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $failCount = (int)DB::scalar(
            "SELECT COUNT(*) FROM login_attempts
             WHERE username = ? AND success = 0 AND attempted_at >= ?",
            [$username, $windowStart]
        );

        if ($failCount < self::TIER1_THRESHOLD) {
            // Update the counter but don't lock yet
            DB::execute(
                "UPDATE users SET failed_login_count = ? WHERE username = ?",
                [$failCount, $username]
            );
            return;
        }

        $lockMinutes = self::getLockDuration($failCount);
        $lockedUntil = (new DateTime('now', new DateTimeZone('UTC')))
            ->modify("+{$lockMinutes} minutes")
            ->format('Y-m-d H:i:s');

        DB::execute(
            "UPDATE users SET failed_login_count = ?, locked_until = ? WHERE username = ?",
            [$failCount, $lockedUntil, $username]
        );
    }
}
