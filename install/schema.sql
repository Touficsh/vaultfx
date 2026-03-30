-- ============================================================
-- VaultFX — Credential Management System
-- Database Schema v1.1
-- Engine: InnoDB | Charset: utf8mb4_unicode_ci
-- ============================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
SET SQL_MODE = 'STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- ============================================================
-- USERS
-- ============================================================
CREATE TABLE IF NOT EXISTS `users` (
    `id`                    INT UNSIGNED        NOT NULL AUTO_INCREMENT,
    `username`              VARCHAR(50)         NOT NULL,
    `email`                 VARCHAR(255)        NOT NULL,
    `password_hash`         VARCHAR(255)        NOT NULL,
    `role`                  ENUM('super_admin','admin','viewer','restricted_viewer') NOT NULL DEFAULT 'viewer',
    `can_view_passwords`    TINYINT(1)          NOT NULL DEFAULT 0,
    `can_manage_managers`   TINYINT(1)          NOT NULL DEFAULT 0,
    `is_active`             TINYINT(1)          NOT NULL DEFAULT 1,
    `totp_secret_encrypted` VARCHAR(500)        DEFAULT NULL,
    `totp_enabled`          TINYINT(1)          NOT NULL DEFAULT 0,
    `backup_codes_hash`     TEXT                DEFAULT NULL COMMENT 'JSON array of hashed backup codes',
    `force_password_change` TINYINT(1)          NOT NULL DEFAULT 0,
    `password_changed_at`   DATETIME            DEFAULT NULL,
    `last_login_at`         DATETIME            DEFAULT NULL,
    `last_login_ip`         VARCHAR(45)         DEFAULT NULL,
    `failed_login_count`    INT UNSIGNED        NOT NULL DEFAULT 0,
    `locked_until`          DATETIME            DEFAULT NULL,
    `theme_preference`      ENUM('dark','light','system') NOT NULL DEFAULT 'dark',
    `pinned_credentials`    TEXT                DEFAULT NULL COMMENT 'JSON: [{type, id}]',
    `created_by`            INT UNSIGNED        DEFAULT NULL,
    `created_at`            DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`            DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_username` (`username`),
    UNIQUE KEY `uq_email` (`email`),
    INDEX `idx_role` (`role`),
    INDEX `idx_is_active` (`is_active`),
    INDEX `idx_locked_until` (`locked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- SERVERS
-- ============================================================
CREATE TABLE IF NOT EXISTS `servers` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `name`          VARCHAR(255)    NOT NULL,
    `ip_address`    VARCHAR(255)    DEFAULT NULL,
    `platform_type` ENUM('MT4','MT5','cTrader','DXtrade','Other') NOT NULL DEFAULT 'MT4',
    `notes`         TEXT            DEFAULT NULL,
    `tags`          VARCHAR(500)    DEFAULT NULL COMMENT 'Comma-separated tags',
    `is_active`     TINYINT(1)      NOT NULL DEFAULT 1,
    `created_by`    INT UNSIGNED    NOT NULL,
    `created_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_name` (`name`),
    INDEX `idx_platform` (`platform_type`),
    INDEX `idx_active` (`is_active`),
    CONSTRAINT `fk_servers_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- MANAGER ACCOUNTS
-- ============================================================
CREATE TABLE IF NOT EXISTS `manager_accounts` (
    `id`                    INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `server_id`             INT UNSIGNED    NOT NULL,
    `label`                 VARCHAR(100)    NOT NULL,
    `login_number`          VARCHAR(50)     NOT NULL,
    `encrypted_password`    TEXT            NOT NULL COMMENT 'base64(key_version[1] + iv[12] + tag[16] + ciphertext)',
    `password_salt`         VARCHAR(64)     NOT NULL COMMENT 'hex-encoded 32-byte random salt for HKDF',
    `key_version`           TINYINT UNSIGNED NOT NULL DEFAULT 1,
    `password_expires_at`   DATE            DEFAULT NULL,
    `password_last_changed` DATETIME        DEFAULT NULL,
    `notes`                 TEXT            DEFAULT NULL,
    `tags`                  VARCHAR(500)    DEFAULT NULL,
    `is_active`             TINYINT(1)      NOT NULL DEFAULT 1,
    `created_by`            INT UNSIGNED    NOT NULL,
    `created_at`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_server` (`server_id`),
    INDEX `idx_login` (`login_number`),
    INDEX `idx_label` (`label`),
    INDEX `idx_active` (`is_active`),
    CONSTRAINT `fk_managers_server` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_managers_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- COVERAGE ACCOUNTS
-- ============================================================
CREATE TABLE IF NOT EXISTS `coverage_accounts` (
    `id`                            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `manager_account_id`            INT UNSIGNED    NOT NULL,
    `server_id`                     INT UNSIGNED    NOT NULL,
    `label`                         VARCHAR(100)    NOT NULL,
    `login_number`                  VARCHAR(50)     NOT NULL,
    `encrypted_password`            TEXT            NOT NULL COMMENT 'base64(key_version[1] + iv[12] + tag[16] + ciphertext)',
    `password_salt`                 VARCHAR(64)     NOT NULL,
    `encrypted_investor_password`   TEXT            DEFAULT NULL COMMENT 'Optional read-only investor password',
    `investor_password_salt`        VARCHAR(64)     DEFAULT NULL,
    `investor_key_version`          TINYINT UNSIGNED DEFAULT NULL,
    `key_version`                   TINYINT UNSIGNED NOT NULL DEFAULT 1,
    `password_expires_at`           DATE            DEFAULT NULL,
    `password_last_changed`         DATETIME        DEFAULT NULL,
    `notes`                         TEXT            DEFAULT NULL,
    `tags`                          VARCHAR(500)    DEFAULT NULL,
    `is_active`                     TINYINT(1)      NOT NULL DEFAULT 1,
    `created_by`                    INT UNSIGNED    NOT NULL,
    `created_at`                    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at`                    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_manager` (`manager_account_id`),
    INDEX `idx_server` (`server_id`),
    INDEX `idx_login` (`login_number`),
    INDEX `idx_label` (`label`),
    INDEX `idx_active` (`is_active`),
    CONSTRAINT `fk_coverage_manager` FOREIGN KEY (`manager_account_id`) REFERENCES `manager_accounts` (`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_coverage_server` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_coverage_created_by` FOREIGN KEY (`created_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- USER ↔ SERVER ACCESS (Scoped Permissions)
-- ============================================================
CREATE TABLE IF NOT EXISTS `user_server_access` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED    NOT NULL,
    `server_id`     INT UNSIGNED    NOT NULL,
    `granted_by`    INT UNSIGNED    NOT NULL,
    `granted_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_user_server` (`user_id`, `server_id`),
    CONSTRAINT `fk_usa_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_usa_server` FOREIGN KEY (`server_id`) REFERENCES `servers` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_usa_granted_by` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- USER ↔ MANAGER ACCESS (Explicit Manager-Level Grants)
-- Viewers and restricted viewers only see managers listed here.
-- Admins use server-level access instead.
-- ============================================================
CREATE TABLE IF NOT EXISTS `user_manager_access` (
    `id`                    INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `user_id`               INT UNSIGNED    NOT NULL,
    `manager_account_id`    INT UNSIGNED    NOT NULL,
    `granted_by`            INT UNSIGNED    NOT NULL,
    `created_at`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_user_manager` (`user_id`, `manager_account_id`),
    CONSTRAINT `fk_uma_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_uma_manager` FOREIGN KEY (`manager_account_id`) REFERENCES `manager_accounts` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_uma_granted_by` FOREIGN KEY (`granted_by`) REFERENCES `users` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- AUDIT LOG (Immutable — never UPDATE or DELETE rows)
-- ============================================================
CREATE TABLE IF NOT EXISTS `audit_log` (
    `id`            BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED        DEFAULT NULL,
    `username`      VARCHAR(50)         DEFAULT NULL COMMENT 'Snapshot at time of action',
    `action_type`   VARCHAR(50)         NOT NULL,
    `target_type`   VARCHAR(50)         DEFAULT NULL,
    `target_id`     INT UNSIGNED        DEFAULT NULL,
    `ip_address`    VARCHAR(45)         NOT NULL,
    `user_agent`    VARCHAR(500)        DEFAULT NULL,
    `details`       JSON                DEFAULT NULL,
    `severity`      ENUM('info','warning','critical') NOT NULL DEFAULT 'info',
    `created_at`    DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_user` (`user_id`),
    INDEX `idx_action` (`action_type`),
    INDEX `idx_target` (`target_type`, `target_id`),
    INDEX `idx_created` (`created_at`),
    INDEX `idx_ip` (`ip_address`),
    INDEX `idx_severity` (`severity`),
    CONSTRAINT `fk_audit_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- LOGIN ATTEMPTS (Rate Limiting)
-- ============================================================
CREATE TABLE IF NOT EXISTS `login_attempts` (
    `id`            BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `username`      VARCHAR(50)         NOT NULL,
    `ip_address`    VARCHAR(45)         NOT NULL,
    `user_agent`    VARCHAR(500)        DEFAULT NULL,
    `attempted_at`  DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `success`       TINYINT(1)          NOT NULL DEFAULT 0,
    PRIMARY KEY (`id`),
    INDEX `idx_username_time` (`username`, `attempted_at`),
    INDEX `idx_ip_time` (`ip_address`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- ACTIVE SESSIONS (Concurrent Session Control)
-- ============================================================
CREATE TABLE IF NOT EXISTS `active_sessions` (
    `id`              VARCHAR(128)    NOT NULL,
    `user_id`         INT UNSIGNED    NOT NULL,
    `ip_address`      VARCHAR(45)     NOT NULL,
    `ip_subnet`       VARCHAR(45)     NOT NULL COMMENT 'First 3 octets for binding',
    `user_agent`      VARCHAR(500)    DEFAULT NULL,
    `user_agent_hash` VARCHAR(64)     DEFAULT NULL COMMENT 'SHA-256 of user agent for quick compare',
    `login_at`        DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `last_activity`   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_user` (`user_id`),
    INDEX `idx_activity` (`last_activity`),
    CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- SETTINGS
-- ============================================================
CREATE TABLE IF NOT EXISTS `settings` (
    `id`            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `setting_key`   VARCHAR(100)    NOT NULL,
    `setting_value` TEXT            DEFAULT NULL,
    `updated_by`    INT UNSIGNED    DEFAULT NULL,
    `updated_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_setting_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- PASSWORD REVEAL LOG (Separate from audit for quick lookups)
-- ============================================================
CREATE TABLE IF NOT EXISTS `password_reveals` (
    `id`              BIGINT UNSIGNED     NOT NULL AUTO_INCREMENT,
    `user_id`         INT UNSIGNED        NOT NULL,
    `credential_type` VARCHAR(50)         NOT NULL COMMENT 'manager | coverage | coverage_investor',
    `credential_id`   INT UNSIGNED        NOT NULL,
    `ip_address`      VARCHAR(45)         NOT NULL,
    `revealed_at`     DATETIME            NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_user_time` (`user_id`, `revealed_at`),
    INDEX `idx_credential` (`credential_type`, `credential_id`),
    CONSTRAINT `fk_reveals_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- DEFAULT SETTINGS
-- ============================================================
INSERT IGNORE INTO `settings` (`setting_key`, `setting_value`) VALUES
('session_timeout_minutes',         '30'),
('absolute_timeout_hours',          '8'),
('max_failed_logins_lockout',       '5'),
('lockout_duration_minutes',        '15'),
('extended_lockout_threshold',      '10'),
('extended_lockout_minutes',        '60'),
('hard_lockout_threshold',          '20'),
('hard_lockout_hours',              '24'),
('ip_whitelist_enabled',            '0'),
('ip_whitelist',                    '[]'),
('password_reveal_timeout_seconds', '30'),
('require_2fa_admin',               '1'),
('require_2fa_super_admin',         '1'),
('app_name',                        'VaultFX'),
('maintenance_mode',                '0'),
('maintenance_allowed_ips',         '[]'),
('after_hours_start',               '20:00'),
('after_hours_end',                 '08:00'),
('after_hours_flag_enabled',        '0'),
('bulk_reveal_threshold',           '3'),
('bulk_reveal_window_seconds',      '300'),
('backup_encryption_enabled',       '1'),
('csv_export_include_passwords',    '0'),
('alert_email_enabled',             '0'),
('alert_email_to',                  ''),
('alert_email_from',                ''),
('app_version',                     '1.1.0'),
('theme_accent_color',              '#3b82f6');

SET FOREIGN_KEY_CHECKS = 1;
