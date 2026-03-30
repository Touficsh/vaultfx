<?php
/**
 * VaultFX — Role-Based Access Control (RBAC)
 * ============================================
 * Role hierarchy:
 *   super_admin > admin > viewer > restricted_viewer
 *
 * All permission checks must happen SERVER-SIDE.
 * Never trust client-side checks alone.
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class RBAC
{
    // Role constants
    const SUPER_ADMIN       = 'super_admin';
    const ADMIN             = 'admin';
    const VIEWER            = 'viewer';
    const RESTRICTED_VIEWER = 'restricted_viewer';

    // Role hierarchy (higher = more privileged)
    private const HIERARCHY = [
        self::RESTRICTED_VIEWER => 1,
        self::VIEWER            => 2,
        self::ADMIN             => 3,
        self::SUPER_ADMIN       => 4,
    ];

    // Cache for server access checks (per request)
    private static array $serverAccessCache = [];

    // Cache for manager access checks (per request)
    private static array $managerAccessCache = [];

    // ── Role Checks ───────────────────────────────────────────

    /**
     * Returns the current user's role.
     */
    public static function role(): string
    {
        return Auth::userField('role', self::RESTRICTED_VIEWER);
    }

    /**
     * Returns true if the current user has at least the given role.
     */
    public static function atLeast(string $minimumRole): bool
    {
        $userLevel    = self::HIERARCHY[self::role()] ?? 0;
        $requiredLevel = self::HIERARCHY[$minimumRole] ?? 999;
        return $userLevel >= $requiredLevel;
    }

    /**
     * Returns true if the user IS exactly this role.
     */
    public static function is(string $role): bool
    {
        return self::role() === $role;
    }

    public static function isSuperAdmin(): bool { return self::is(self::SUPER_ADMIN); }
    public static function isAdmin(): bool       { return self::atLeast(self::ADMIN) && !self::isSuperAdmin(); }
    public static function isViewer(): bool      { return self::is(self::VIEWER); }
    public static function isRestricted(): bool  { return self::is(self::RESTRICTED_VIEWER); }

    // ── Permission Checks ─────────────────────────────────────

    /**
     * Can the user view passwords? (Requires explicit grant OR super_admin role)
     */
    public static function canViewPasswords(): bool
    {
        if (self::isSuperAdmin()) {
            return true;
        }
        if (self::isRestricted()) {
            return false; // Never, regardless of flag
        }
        return (bool)Auth::userField('can_view_passwords', false);
    }

    /**
     * Can the user create/edit servers?
     */
    public static function canManageServers(): bool
    {
        return self::atLeast(self::ADMIN);
    }

    /**
     * Can the user create/edit manager accounts?
     */
    public static function canManageManagers(): bool
    {
        if (self::atLeast(self::ADMIN)) return true;
        return (bool)Auth::userField('can_manage_managers', false);
    }

    /**
     * Can the user create/edit coverage accounts?
     */
    public static function canManageCoverage(): bool
    {
        if (self::atLeast(self::ADMIN)) return true;
        return (bool)Auth::userField('can_manage_managers', false);
    }

    /**
     * Can the user delete credentials?
     */
    public static function canDelete(): bool
    {
        return self::atLeast(self::ADMIN);
    }

    /**
     * Can the user manage users?
     */
    public static function canManageUsers(): bool
    {
        return self::isSuperAdmin();
    }

    /**
     * Can the user view the audit log?
     */
    public static function canViewAuditLog(): bool
    {
        return self::atLeast(self::ADMIN);
    }

    /**
     * Can the user view system settings?
     */
    public static function canViewSettings(): bool
    {
        return self::isSuperAdmin();
    }

    /**
     * Can the user export data?
     */
    public static function canExport(): bool
    {
        return self::atLeast(self::ADMIN);
    }

    /**
     * Can the user perform bulk import?
     */
    public static function canImport(): bool
    {
        return self::atLeast(self::ADMIN);
    }

    /**
     * Can the user perform a database backup?
     */
    public static function canBackup(): bool
    {
        return self::isSuperAdmin();
    }

    /**
     * Can the user rotate encryption keys?
     */
    public static function canRotateKeys(): bool
    {
        return self::isSuperAdmin();
    }

    // ── Server-Level Access ───────────────────────────────────

    /**
     * Returns true if the current user has access to a specific server.
     *
     * Super admins always have access.
     * Admins and below require an explicit grant in user_server_access.
     *
     * @param  int  $serverId
     * @return bool
     */
    public static function canAccessServer(int $serverId): bool
    {
        if (self::isSuperAdmin()) {
            return true;
        }

        $userId = Auth::userField('id');
        if (!$userId) {
            return false;
        }

        $cacheKey = "{$userId}:{$serverId}";
        if (isset(self::$serverAccessCache[$cacheKey])) {
            return self::$serverAccessCache[$cacheKey];
        }

        $granted = (bool)DB::scalar(
            "SELECT COUNT(*) FROM user_server_access WHERE user_id = ? AND server_id = ?",
            [(int)$userId, $serverId]
        );

        self::$serverAccessCache[$cacheKey] = $granted;
        return $granted;
    }

    /**
     * Returns all server IDs the current user can access.
     * Super admins get all servers.
     */
    public static function accessibleServerIds(): array
    {
        $userId = Auth::userField('id');

        if (self::isSuperAdmin()) {
            $rows = DB::rows("SELECT id FROM servers WHERE is_active = 1");
            return array_column($rows, 'id');
        }

        $rows = DB::rows(
            "SELECT server_id FROM user_server_access WHERE user_id = ?",
            [(int)$userId]
        );
        return array_column($rows, 'server_id');
    }

    /**
     * Returns an IN clause-safe list of accessible server IDs.
     * Returns "(0)" if no access (prevents SQL errors with empty IN).
     */
    public static function accessibleServerIdsSql(): string
    {
        $ids = self::accessibleServerIds();
        if (empty($ids)) {
            return '(0)';
        }
        return '(' . implode(',', array_map('intval', $ids)) . ')';
    }

    /**
     * Returns all manager account IDs the current user can access.
     *
     * Super admins  → all managers.
     * Admins        → all managers on their accessible servers.
     * Viewer / below → only explicitly granted managers (regardless of server access).
     */
    public static function accessibleManagerIds(): array
    {
        $userId = (int)Auth::userField('id');

        if (self::isSuperAdmin()) {
            $rows = DB::rows("SELECT id FROM manager_accounts WHERE is_active = 1");
            return array_map('intval', array_column($rows, 'id'));
        }

        if (self::atLeast(self::ADMIN)) {
            $serverIdsSql = self::accessibleServerIdsSql();
            $rows = DB::rows(
                "SELECT id FROM manager_accounts WHERE server_id IN $serverIdsSql AND is_active = 1"
            );
            return array_map('intval', array_column($rows, 'id'));
        }

        // Viewer and restricted_viewer: only explicit manager grants
        if (!$userId) {
            return [];
        }
        $rows = DB::rows(
            "SELECT uma.manager_account_id
             FROM user_manager_access uma
             JOIN manager_accounts ma ON ma.id = uma.manager_account_id AND ma.is_active = 1
             WHERE uma.user_id = ?",
            [$userId]
        );
        return array_map(fn($r) => (int)$r['manager_account_id'], $rows);
    }

    /**
     * Returns SQL IN clause for accessible manager IDs.
     */
    public static function accessibleManagerIdsSql(): string
    {
        $ids = self::accessibleManagerIds();
        if (empty($ids)) return '(0)';
        return '(' . implode(',', $ids) . ')';
    }

    /**
     * Checks if user can access a specific manager account.
     *
     * Super admins  → always.
     * Admins        → if they have server-level access to the manager's server.
     * Viewer / below → only if an explicit grant exists in user_manager_access.
     */
    public static function canAccessManager(int $managerId): bool
    {
        if (self::isSuperAdmin()) {
            return true;
        }

        $userId = (int)Auth::userField('id');
        if (!$userId) {
            return false;
        }

        $cacheKey = "{$userId}:{$managerId}";
        if (isset(self::$managerAccessCache[$cacheKey])) {
            return self::$managerAccessCache[$cacheKey];
        }

        $manager = DB::row(
            "SELECT server_id FROM manager_accounts WHERE id = ? AND is_active = 1",
            [$managerId]
        );
        if (!$manager) {
            self::$managerAccessCache[$cacheKey] = false;
            return false;
        }

        if (self::atLeast(self::ADMIN)) {
            // Admins access managers via server-level access
            $granted = self::canAccessServer((int)$manager['server_id']);
            self::$managerAccessCache[$cacheKey] = $granted;
            return $granted;
        }

        // Viewer and restricted_viewer: only explicit grants
        $granted = (bool)DB::scalar(
            "SELECT COUNT(*) FROM user_manager_access WHERE user_id = ? AND manager_account_id = ?",
            [$userId, $managerId]
        );
        self::$managerAccessCache[$cacheKey] = $granted;
        return $granted;
    }

    /**
     * Checks if user can access a coverage account (via manager or server access).
     */
    public static function canAccessCoverage(int $coverageId): bool
    {
        $coverage = DB::row(
            "SELECT manager_account_id FROM coverage_accounts WHERE id = ? AND is_active = 1",
            [$coverageId]
        );
        if (!$coverage) {
            return false;
        }
        return self::canAccessManager((int)$coverage['manager_account_id']);
    }

    // ── Gate Methods (die on failure) ─────────────────────────

    /**
     * Asserts a permission. If not granted, sends 403 and exits.
     *
     * @param  bool   $condition  Result of permission check
     * @param  bool   $isApi      If true, sends JSON error instead of HTML
     */
    public static function assert(bool $condition, bool $isApi = false): void
    {
        if (!$condition) {
            if ($isApi) {
                json_error('Permission denied.', 403);
            }
            http_response_code(403);
            include WEB_ROOT . '/pages/403.php';
            exit;
        }
    }

    /**
     * Asserts server access. Dies with 403 if not authorized.
     */
    public static function assertServerAccess(int $serverId, bool $isApi = false): void
    {
        self::assert(self::canAccessServer($serverId), $isApi);
    }

    /**
     * Asserts at least a minimum role.
     */
    public static function assertRole(string $minimumRole, bool $isApi = false): void
    {
        self::assert(self::atLeast($minimumRole), $isApi);
    }

    /**
     * Asserts the user can view passwords. Sends 403 if not.
     */
    public static function assertCanViewPasswords(bool $isApi = false): void
    {
        self::assert(self::canViewPasswords(), $isApi);
    }

    // ── UI Helpers ────────────────────────────────────────────

    /**
     * Returns a human-readable role label.
     */
    public static function roleLabel(string $role): string
    {
        return match ($role) {
            self::SUPER_ADMIN       => 'Super Admin',
            self::ADMIN             => 'Admin',
            self::VIEWER            => 'Viewer',
            self::RESTRICTED_VIEWER => 'Restricted Viewer',
            default                 => 'Unknown',
        };
    }

    /**
     * Returns a CSS class for a role badge.
     */
    public static function roleBadgeClass(string $role): string
    {
        return match ($role) {
            self::SUPER_ADMIN       => 'badge-super-admin',
            self::ADMIN             => 'badge-admin',
            self::VIEWER            => 'badge-viewer',
            self::RESTRICTED_VIEWER => 'badge-restricted',
            default                 => 'badge-unknown',
        };
    }

    /**
     * Returns all valid roles.
     */
    public static function allRoles(): array
    {
        return [
            self::SUPER_ADMIN,
            self::ADMIN,
            self::VIEWER,
            self::RESTRICTED_VIEWER,
        ];
    }
}
