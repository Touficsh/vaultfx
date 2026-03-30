<?php
/**
 * VaultFX — Immutable Audit Logging
 * ===================================
 * Every security-relevant event is written here.
 * The audit_log table is NEVER updated or deleted from by the app.
 * Implements suspicious activity detection.
 *
 * Valid action_types:
 *   login_success, login_failed, login_2fa_pending, login_new_ip,
 *   login_locked, logout, session_destroyed,
 *   password_reveal, 2fa_setup, 2fa_disabled, 2fa_backup_code_used,
 *   credential_create, credential_edit, credential_delete,
 *   user_create, user_edit, user_delete, user_role_change,
 *   settings_change, export, import, backup, restore,
 *   ip_whitelist_change, key_rotation, bulk_reveal_flagged,
 *   after_hours_access
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class Audit
{
    // Action type constants
    const LOGIN_SUCCESS     = 'login_success';
    const LOGIN_FAILED      = 'login_failed';
    const LOGOUT            = 'logout';
    const PASSWORD_REVEAL   = 'password_reveal';
    const CREDENTIAL_CREATE = 'credential_create';
    const CREDENTIAL_EDIT   = 'credential_edit';
    const CREDENTIAL_DELETE = 'credential_delete';
    const USER_CREATE       = 'user_create';
    const USER_EDIT         = 'user_edit';
    const USER_DELETE       = 'user_delete';
    const USER_ROLE_CHANGE  = 'user_role_change';
    const SETTINGS_CHANGE   = 'settings_change';
    const EXPORT            = 'export';
    const BACKUP            = 'backup';
    const KEY_ROTATION      = 'key_rotation';
    const IP_WHITELIST_CHG  = 'ip_whitelist_change';
    const BULK_REVEAL_FLAG  = 'bulk_reveal_flagged';
    const AFTER_HOURS       = 'after_hours_access';
    const SESSION_DESTROYED = 'session_destroyed';

    /**
     * Writes an audit log entry.
     *
     * @param  int|null    $userId      Authenticated user (null for unauthenticated events)
     * @param  string      $actionType  One of the action constants above
     * @param  string|null $targetType  'server', 'manager_account', 'coverage_account', 'user', 'system'
     * @param  int|null    $targetId    Primary key of the target record
     * @param  array       $details     Additional context data (stored as JSON)
     * @param  string      $severity    'info', 'warning', 'critical'
     */
    public static function log(
        ?int    $userId,
        string  $actionType,
        ?string $targetType = null,
        ?int    $targetId   = null,
        array   $details    = [],
        string  $severity   = 'info'
    ): void {
        $ip        = client_ip();
        $ua        = client_ua();
        $username  = null;

        // Snapshot username at time of action
        if ($userId) {
            try {
                $username = DB::scalar("SELECT username FROM users WHERE id = ?", [$userId]);
            } catch (Exception $e) {
                // Non-fatal
            }
        }

        // Auto-detect after-hours access
        if ($actionType === self::LOGIN_SUCCESS) {
            self::checkAfterHours($userId);
        }

        try {
            DB::execute(
                "INSERT INTO audit_log
                    (user_id, username, action_type, target_type, target_id, ip_address, user_agent, details, severity)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    $userId,
                    $username,
                    $actionType,
                    $targetType,
                    $targetId,
                    $ip,
                    $ua,
                    empty($details) ? null : json_encode($details),
                    $severity,
                ]
            );
        } catch (Exception $e) {
            // Audit failure is critical — log to file as fallback
            app_log('critical', 'Audit log write failed: ' . $e->getMessage(), [
                'user_id'     => $userId,
                'action_type' => $actionType,
                'details'     => $details,
            ]);
        }
    }

    /**
     * Logs a password reveal event and checks for suspicious bulk reveals.
     *
     * @param  int    $userId
     * @param  string $credentialType  'manager' or 'coverage'
     * @param  int    $credentialId
     * @param  string $label           Label of the credential (for context)
     */
    public static function logReveal(int $userId, string $credentialType, int $credentialId, string $label = ''): void
    {
        $ip = client_ip();

        // Write to password_reveals for quick bulk-detection queries
        DB::execute(
            "INSERT INTO password_reveals (user_id, credential_type, credential_id, ip_address, revealed_at)
             VALUES (?, ?, ?, ?, NOW())",
            [$userId, $credentialType, $credentialId, $ip]
        );

        // Write to audit log
        self::log($userId, self::PASSWORD_REVEAL, $credentialType . '_account', $credentialId, [
            'label'           => $label,
            'credential_type' => $credentialType,
        ]);

        // Check for suspicious bulk reveals
        self::detectBulkReveals($userId, $ip);
    }

    /**
     * Retrieves the last reveal event for a credential.
     *
     * @param  string $type  'manager' or 'coverage'
     * @param  int    $id
     * @return array|null  {username, revealed_at, ip_address}
     */
    public static function lastReveal(string $type, int $id): ?array
    {
        return DB::row(
            "SELECT u.username, pr.revealed_at, pr.ip_address
             FROM password_reveals pr
             JOIN users u ON u.id = pr.user_id
             WHERE pr.credential_type = ? AND pr.credential_id = ?
             ORDER BY pr.revealed_at DESC
             LIMIT 1",
            [$type, $id]
        );
    }

    /**
     * Retrieves the last reveal event for each credential ID in a batch (single query).
     *
     * @param  string $type  'manager' or 'coverage'
     * @param  array  $ids   Array of credential IDs
     * @return array         Map of credential_id → {username, revealed_at, ip_address}
     */
    public static function batchLastReveals(string $type, array $ids): array
    {
        if (empty($ids)) {
            return [];
        }

        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $rows = DB::rows(
            "SELECT pr.credential_id, u.username, pr.revealed_at, pr.ip_address
             FROM password_reveals pr
             JOIN users u ON u.id = pr.user_id
             WHERE pr.credential_type = ? AND pr.credential_id IN ($placeholders)
             ORDER BY pr.revealed_at DESC",
            array_merge([$type], array_map('intval', $ids))
        );

        // Keep only the most recent reveal per credential
        $result = [];
        foreach ($rows as $row) {
            $cid = (int)$row['credential_id'];
            if (!isset($result[$cid])) {
                $result[$cid] = $row;
            }
        }
        return $result;
    }

    /**
     * Fetches paginated audit log entries with optional filters.
     *
     * @param  array $filters  Keys: user_id, action_type, target_type, date_from, date_to, severity, ip
     * @param  int   $page
     * @param  int   $perPage
     * @return array{rows: array, total: int}
     */
    public static function fetch(array $filters = [], int $page = 1, int $perPage = 50): array
    {
        $where  = ['1=1'];
        $params = [];

        // Super admins see all; admins see entries in their server scope
        if (!RBAC::isSuperAdmin()) {
            $serverIds = RBAC::accessibleServerIdsSql();
            // Admins see: their own actions + actions on servers they manage
            $userId = Auth::userField('id');
            $where[] = "(al.user_id = ? OR al.target_id IN
                         (SELECT id FROM manager_accounts WHERE server_id IN {$serverIds})
                         OR al.target_id IN
                         (SELECT id FROM coverage_accounts WHERE server_id IN {$serverIds}))";
            $params[] = (int)$userId;
        }

        if (!empty($filters['user_id'])) {
            $where[]  = 'al.user_id = ?';
            $params[] = (int)$filters['user_id'];
        }

        if (!empty($filters['action_type'])) {
            $where[]  = 'al.action_type = ?';
            $params[] = $filters['action_type'];
        }

        if (!empty($filters['target_type'])) {
            $where[]  = 'al.target_type = ?';
            $params[] = $filters['target_type'];
        }

        if (!empty($filters['severity'])) {
            $where[]  = 'al.severity = ?';
            $params[] = $filters['severity'];
        }

        if (!empty($filters['ip'])) {
            $ipSafe   = str_replace(['%', '_', '\\'], ['\\%', '\\_', '\\\\'], $filters['ip']);
            $where[]  = 'al.ip_address LIKE ?';
            $params[] = '%' . $ipSafe . '%';
        }

        if (!empty($filters['date_from'])) {
            $where[]  = 'al.created_at >= ?';
            $params[] = $filters['date_from'] . ' 00:00:00';
        }

        if (!empty($filters['date_to'])) {
            $where[]  = 'al.created_at <= ?';
            $params[] = $filters['date_to'] . ' 23:59:59';
        }

        $whereStr = implode(' AND ', $where);

        $total = (int)DB::scalar(
            "SELECT COUNT(*) FROM audit_log al WHERE {$whereStr}",
            $params
        );

        $offset = ($page - 1) * $perPage;
        $rows   = DB::rows(
            "SELECT al.*, u.username AS actor_username
             FROM audit_log al
             LEFT JOIN users u ON u.id = al.user_id
             WHERE {$whereStr}
             ORDER BY al.created_at DESC
             LIMIT {$perPage} OFFSET {$offset}",
            $params
        );

        return ['rows' => $rows, 'total' => $total];
    }

    // ── Suspicious Activity Detection ─────────────────────────

    /**
     * Detects if a user has revealed more than N passwords in the past M minutes.
     * If threshold exceeded, flags the event and optionally sends an alert.
     */
    private static function detectBulkReveals(int $userId, string $ip): void
    {
        $threshold = (int)(setting('bulk_reveal_threshold', 3));
        $window    = (int)(setting('bulk_reveal_window_seconds', 300));

        $windowStart = (new DateTime("-{$window} seconds", new DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $count = (int)DB::scalar(
            "SELECT COUNT(*) FROM password_reveals
             WHERE user_id = ? AND revealed_at >= ?",
            [$userId, $windowStart]
        );

        if ($count >= $threshold) {
            // Only flag once per window (check if already flagged recently)
            $alreadyFlagged = DB::scalar(
                "SELECT COUNT(*) FROM audit_log
                 WHERE user_id = ? AND action_type = ? AND created_at >= ?",
                [$userId, self::BULK_REVEAL_FLAG, $windowStart]
            );

            if (!$alreadyFlagged) {
                self::log($userId, self::BULK_REVEAL_FLAG, 'user', $userId, [
                    'reveals_in_window' => $count,
                    'window_seconds'    => $window,
                    'ip'                => $ip,
                ], 'critical');

                send_alert_email(
                    'Bulk Password Reveal Detected',
                    "User ID {$userId} has revealed {$count} passwords within {$window} seconds.\nIP: {$ip}"
                );
            }
        }
    }

    /**
     * Detects and logs after-hours access.
     */
    private static function checkAfterHours(?int $userId): void
    {
        if (!$userId || setting('after_hours_flag_enabled') !== '1') {
            return;
        }

        $start = setting('after_hours_start', '20:00');
        $end   = setting('after_hours_end', '08:00');

        $now  = new DateTime('now', new DateTimeZone('UTC'));
        $hour = (int)$now->format('Hi'); // e.g. 2130

        [$sh, $sm] = explode(':', $start);
        [$eh, $em] = explode(':', $end);
        $startInt = (int)($sh . $sm);
        $endInt   = (int)($eh . $em);

        $isAfterHours = false;
        if ($startInt > $endInt) {
            // Spans midnight (e.g. 20:00 to 08:00)
            $isAfterHours = $hour >= $startInt || $hour < $endInt;
        } else {
            $isAfterHours = $hour >= $startInt && $hour < $endInt;
        }

        if ($isAfterHours) {
            self::log($userId, self::AFTER_HOURS, 'user', $userId, [
                'time_utc' => $now->format('H:i'),
            ], 'warning');
        }
    }

    /**
     * Returns the last N audit entries for quick display on the dashboard.
     */
    public static function recent(int $limit = 10): array
    {
        $serverIdsSql = RBAC::accessibleServerIdsSql();

        if (RBAC::isSuperAdmin()) {
            return DB::rows(
                "SELECT al.*, u.username AS actor_username
                 FROM audit_log al
                 LEFT JOIN users u ON u.id = al.user_id
                 ORDER BY al.created_at DESC
                 LIMIT ?",
                [$limit]
            );
        }

        $userId = (int)Auth::userField('id');
        return DB::rows(
            "SELECT al.*, u.username AS actor_username
             FROM audit_log al
             LEFT JOIN users u ON u.id = al.user_id
             WHERE al.user_id = ?
             ORDER BY al.created_at DESC
             LIMIT ?",
            [$userId, $limit]
        );
    }
}
