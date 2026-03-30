<?php
/**
 * VaultFX — CSRF Protection
 * ==========================
 * Per-session CSRF token with:
 *  • 32-byte cryptographically random tokens
 *  • Timing-safe comparison via hash_equals()
 *  • Token rotation after every successful validation
 *  • Support for form hidden fields and custom AJAX headers
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class CSRF
{
    private const SESSION_KEY   = '_csrf_token';
    private const HEADER_NAME   = 'X-CSRF-Token';
    private const FIELD_NAME    = 'csrf_token';

    /**
     * Generates or retrieves the current CSRF token.
     * A new token is generated if none exists in the session.
     */
    public static function token(): string
    {
        if (empty($_SESSION[self::SESSION_KEY])) {
            self::regenerate();
        }
        return $_SESSION[self::SESSION_KEY];
    }

    /**
     * Generates a new CSRF token and stores it in the session.
     */
    public static function regenerate(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION[self::SESSION_KEY] = $token;
        return $token;
    }

    /**
     * Returns an HTML hidden input field containing the CSRF token.
     * Use inside every form.
     */
    public static function field(): string
    {
        return sprintf(
            '<input type="hidden" name="%s" value="%s">',
            self::FIELD_NAME,
            e(self::token())
        );
    }

    /**
     * Validates the CSRF token from a POST request.
     * Checks both the form field and the custom AJAX header.
     *
     * @param  bool $rotate   If true, generates a new token after validation
     * @return bool           True if valid
     */
    public static function validate(bool $rotate = true): bool
    {
        $token = self::token();
        if (empty($token)) {
            return false;
        }

        // Check custom header first (AJAX), then form field
        $submitted = '';
        if (!empty($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $submitted = $_SERVER['HTTP_X_CSRF_TOKEN'];
        } elseif (!empty($_POST[self::FIELD_NAME])) {
            $submitted = $_POST[self::FIELD_NAME];
        }

        if (empty($submitted)) {
            return false;
        }

        $valid = hash_equals($token, $submitted);

        if ($valid && $rotate) {
            self::regenerate();
        }

        return $valid;
    }

    /**
     * Validates CSRF token and dies with 403 if invalid.
     * Use at the top of every POST handler.
     */
    public static function requireValid(): void
    {
        if (!self::validate()) {
            $isAjax = strtolower($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'xmlhttprequest';
            if ($isAjax) {
                json_error('CSRF token validation failed.', 403);
            }
            http_response_code(403);
            include WEB_ROOT . '/pages/403.php';
            exit;
        }
    }

    /**
     * Returns the field name (for JavaScript to read).
     */
    public static function fieldName(): string
    {
        return self::FIELD_NAME;
    }

    /**
     * Returns the header name (for AJAX requests).
     */
    public static function headerName(): string
    {
        return self::HEADER_NAME;
    }
}
