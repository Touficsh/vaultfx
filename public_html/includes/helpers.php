<?php
/**
 * VaultFX — Global Helper Functions
 * ===================================
 * Core utilities: output escaping, flash messages, application logging,
 * JSON responses, common formatting, and security utilities.
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

// ── Output Escaping ───────────────────────────────────────────

/**
 * HTML-escape a string for safe output in HTML context.
 * ALWAYS use this for any user-controlled or database-sourced data.
 *
 * @param  mixed  $value  Value to escape
 * @return string         HTML-safe string
 */
function e(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Escape for use inside a JSON response.
 * Prevents XSS through JSON injection.
 */
function json_safe(array $data): string
{
    return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);
}

// ── API/JSON Responses ────────────────────────────────────────

/**
 * Send a JSON success response and exit.
 */
function json_success(array $data = [], string $message = 'OK', int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    $payload = ['success' => true, 'message' => $message, 'data' => $data];
    // Return rotated CSRF token so JS can stay in sync
    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['_csrf_token'])) {
        $payload['_csrf'] = $_SESSION['_csrf_token'];
    }
    echo json_safe($payload);
    exit;
}

/**
 * Send a JSON error response and exit.
 */
function json_error(string $message, int $code = 400, array $errors = []): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    $payload = ['success' => false, 'message' => $message, 'errors' => $errors];
    if (session_status() === PHP_SESSION_ACTIVE && !empty($_SESSION['_csrf_token'])) {
        $payload['_csrf'] = $_SESSION['_csrf_token'];
    }
    echo json_safe($payload);
    exit;
}

/**
 * Require request to be an AJAX/API call (checks header and method).
 */
function require_ajax(): void
{
    $requestedWith = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
    if (strtolower($requestedWith) !== 'xmlhttprequest') {
        json_error('Invalid request type.', 400);
    }
}

// ── Flash Messages ────────────────────────────────────────────

/**
 * Sets a flash message (displayed once on next page load).
 *
 * @param  string $type     'success' | 'error' | 'warning' | 'info'
 * @param  string $message  Message text (will be HTML-escaped on output)
 */
function flash(string $type, string $message): void
{
    if (!isset($_SESSION)) {
        return;
    }
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

/**
 * Retrieves and clears the current flash message.
 *
 * @return array|null  ['type' => string, 'message' => string] or null
 */
function get_flash(): ?array
{
    if (isset($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

// ── Redirect ──────────────────────────────────────────────────

/**
 * Redirect to a URL (relative paths are relative to APP_URL).
 */
function redirect(string $path, int $code = 302): never
{
    $url = str_starts_with($path, 'http') ? $path : rtrim(APP_URL, '/') . '/' . ltrim($path, '/');
    header('Location: ' . $url, true, $code);
    exit;
}

// ── Input Helpers ─────────────────────────────────────────────

/**
 * Get a POST value, trimmed, or default if not set/empty.
 */
function post(string $key, mixed $default = ''): mixed
{
    return isset($_POST[$key]) ? trim((string)$_POST[$key]) : $default;
}

/**
 * Get a GET value, trimmed.
 */
function get_param(string $key, mixed $default = ''): mixed
{
    return isset($_GET[$key]) ? trim((string)$_GET[$key]) : $default;
}

/**
 * Get an integer from $_POST or $_GET, or default.
 */
function param_int(string $key, int $default = 0, ?array $source = null): int
{
    $source = $source ?? ($_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET);
    $val = filter_var($source[$key] ?? $default, FILTER_VALIDATE_INT);
    return $val === false ? $default : (int)$val;
}

// ── Logging ───────────────────────────────────────────────────

/**
 * Writes a message to the application log file.
 *
 * @param  string $level    'debug' | 'info' | 'warning' | 'error' | 'critical'
 * @param  string $message  Log message
 * @param  array  $context  Optional context data
 */
function app_log(string $level, string $message, array $context = []): void
{
    $logFile = defined('APP_LOG') ? APP_LOG : '/tmp/vaultfx_app.log';
    $line    = sprintf(
        "[%s] [%s] %s %s\n",
        gmdate('Y-m-d H:i:s'),
        strtoupper($level),
        $message,
        empty($context) ? '' : json_encode($context)
    );

    @file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

// ── Security Utilities ────────────────────────────────────────

/**
 * Returns the real client IP address, preferring the most reliable source.
 * On shared hosting with a proxy/CDN, adjust accordingly.
 */
function client_ip(): string
{
    // Prefer REMOTE_ADDR — it's not spoofable
    // Only use forwarded headers if you're behind a trusted proxy
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Returns the first 3 octets of an IPv4 address for subnet binding.
 * Returns the full IP for IPv6 (which has different structure).
 */
function ip_subnet(string $ip): string
{
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $parts = explode('.', $ip);
        return implode('.', array_slice($parts, 0, 3));
    }
    return $ip; // IPv6: use full address
}

/**
 * Returns a SHA-256 hash of the user agent string.
 */
function ua_hash(string $ua): string
{
    return hash('sha256', $ua);
}

/**
 * Returns the user agent string (truncated to 500 chars).
 */
function client_ua(): string
{
    return substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 500);
}

/**
 * Checks if an IP address is in a CIDR range.
 *
 * @param  string $ip    IP to test
 * @param  string $cidr  CIDR range (e.g. "192.168.1.0/24" or "192.168.1.5")
 * @return bool
 */
function ip_in_cidr(string $ip, string $cidr): bool
{
    if (!str_contains($cidr, '/')) {
        return $ip === $cidr;
    }

    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int)$bits;

    if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ||
        !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return false;
    }

    $mask    = -1 << (32 - $bits);
    $ipLong  = ip2long($ip);
    $subLong = ip2long($subnet);

    return ($ipLong & $mask) === ($subLong & $mask);
}

/**
 * Checks IP against the configured whitelist.
 * Returns true if access should be allowed.
 */
function ip_is_whitelisted(string $ip): bool
{
    // Fetch whitelist setting from DB (cached per request)
    static $cache = null;
    if ($cache === null) {
        try {
            $enabled = DB::scalar("SELECT setting_value FROM settings WHERE setting_key = 'ip_whitelist_enabled'");
            if ($enabled !== '1') {
                $cache = ['enabled' => false, 'list' => []];
            } else {
                $list   = DB::scalar("SELECT setting_value FROM settings WHERE setting_key = 'ip_whitelist'");
                $cache  = ['enabled' => true, 'list' => json_decode($list ?? '[]', true) ?: []];
            }
        } catch (Exception $e) {
            $cache = ['enabled' => false, 'list' => []];
        }
    }

    if (!$cache['enabled']) {
        return true; // Whitelist not enabled — all IPs allowed
    }

    foreach ($cache['list'] as $range) {
        if (ip_in_cidr($ip, $range)) {
            return true;
        }
    }

    return false;
}

// ── Formatting ────────────────────────────────────────────────

/**
 * Formats a datetime string for display in the UI.
 */
function format_datetime(?string $datetime, string $format = 'M j, Y H:i'): string
{
    if (empty($datetime)) {
        return '—';
    }
    try {
        $dt = new DateTime($datetime, new DateTimeZone('UTC'));
        return $dt->format($format);
    } catch (Exception $e) {
        return '—';
    }
}

/**
 * Returns a human-readable "time ago" string.
 */
function time_ago(?string $datetime): string
{
    if (empty($datetime)) {
        return 'Never';
    }

    $now  = new DateTime('now', new DateTimeZone('UTC'));
    $past = new DateTime($datetime, new DateTimeZone('UTC'));
    $diff = $now->diff($past);

    if ($diff->y > 0)  return $diff->y . ' year' . ($diff->y > 1 ? 's' : '') . ' ago';
    if ($diff->m > 0)  return $diff->m . ' month' . ($diff->m > 1 ? 's' : '') . ' ago';
    if ($diff->d > 0)  return $diff->d . ' day' . ($diff->d > 1 ? 's' : '') . ' ago';
    if ($diff->h > 0)  return $diff->h . ' hour' . ($diff->h > 1 ? 's' : '') . ' ago';
    if ($diff->i > 0)  return $diff->i . ' minute' . ($diff->i > 1 ? 's' : '') . ' ago';
    return 'Just now';
}

/**
 * Returns password expiry status: 'expired', 'critical', 'warning', 'ok', 'none'
 */
function expiry_status(?string $expiresAt): string
{
    if (empty($expiresAt)) {
        return 'none';
    }

    $now    = new DateTime('now', new DateTimeZone('UTC'));
    $expiry = new DateTime($expiresAt, new DateTimeZone('UTC'));
    $diff   = $now->diff($expiry);
    $days   = (int)$diff->format('%r%a'); // negative = past

    if ($days < 0)   return 'expired';
    if ($days <= 7)  return 'critical';
    if ($days <= 14) return 'warning';
    if ($days <= 30) return 'caution';
    return 'ok';
}

/**
 * Returns a CSS class name for an expiry status.
 */
function expiry_badge_class(string $status): string
{
    return match ($status) {
        'expired'  => 'badge-expired',
        'critical' => 'badge-critical',
        'warning'  => 'badge-warning',
        'caution'  => 'badge-caution',
        'ok'       => 'badge-ok',
        default    => 'badge-none',
    };
}

/**
 * Parses comma-separated tags into an array.
 */
function parse_tags(?string $tags): array
{
    if (empty($tags)) {
        return [];
    }
    return array_filter(array_map('trim', explode(',', $tags)));
}

/**
 * Truncates a string to a max length with ellipsis.
 */
function truncate(string $str, int $max = 50): string
{
    if (mb_strlen($str) <= $max) {
        return $str;
    }
    return mb_substr($str, 0, $max - 3) . '…';
}

/**
 * Returns platform badge color class.
 */
function platform_badge_class(string $platform): string
{
    return match ($platform) {
        'MT4'     => 'badge-mt4',
        'MT5'     => 'badge-mt5',
        'cTrader' => 'badge-ctrader',
        'DXtrade' => 'badge-dxtrade',
        default   => 'badge-other',
    };
}

/**
 * Gets a cached setting value from the DB.
 */
function setting(string $key, mixed $default = null): mixed
{
    static $cache = [];
    if (!isset($cache[$key])) {
        try {
            $val = DB::scalar("SELECT setting_value FROM settings WHERE setting_key = ?", [$key]);
            $cache[$key] = $val ?? $default;
        } catch (Exception $e) {
            return $default;
        }
    }
    return $cache[$key];
}

/**
 * Generates a unique nonce for CSP (can be used with inline scripts if needed).
 */
function csp_nonce(): string
{
    static $nonce = null;
    if ($nonce === null) {
        $nonce = base64_encode(random_bytes(16));
    }
    return $nonce;
}

/**
 * Sets no-cache headers — required for all credential pages.
 */
function no_cache_headers(): void
{
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
}

/**
 * Sends an email alert to the admin (if configured).
 */
function send_alert_email(string $subject, string $body): void
{
    $enabled = setting('alert_email_enabled', '0');
    if ($enabled !== '1') {
        return;
    }

    $to   = setting('alert_email_to', '');
    $from = setting('alert_email_from', 'noreply@vaultfx.local');

    if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return;
    }

    $headers  = 'From: ' . $from . "\r\n";
    $headers .= 'X-Mailer: VaultFX' . "\r\n";
    $headers .= 'Content-Type: text/plain; charset=UTF-8' . "\r\n";

    @mail($to, '[VaultFX Alert] ' . $subject, $body, $headers);
}
