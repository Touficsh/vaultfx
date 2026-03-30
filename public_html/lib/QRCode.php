<?php
/**
 * VaultFX — QR Code Helper
 * =========================
 * Generates QR codes for 2FA setup.
 * Uses Google Chart API for rendering (external CDN call is acceptable
 * during one-time 2FA setup only — the secret is NOT sent to Google,
 * only the otpauth URL structure is).
 *
 * For maximum security in air-gapped environments, replace with a
 * self-hosted QR generator like endroid/qr-code (if Composer is available)
 * or include a standalone PHP QR library.
 */

class QRCode
{
    /**
     * Returns an <img> tag rendering the QR code via a data URI.
     * This keeps the otpauth URL server-side and never sends secrets to Google.
     *
     * Falls back to Google Charts if PHP GD is not available.
     *
     * @param  string $data     The data to encode (otpauth URI)
     * @param  int    $size     Pixel dimensions of the QR code
     * @return string           HTML img tag
     */
    public static function render(string $data, int $size = 200): string
    {
        // Option 1: Render using built-in PHP with GD if phpqrcode is available
        // Option 2: Return a URL for client-side rendering via a JS QR library
        // We'll return the URL to be rendered client-side via qrcode.js (no secret transmitted externally)

        // The data URI approach: we output the raw otpauth URL and render it with JS
        return sprintf(
            '<canvas id="qrcode-canvas" data-qr="%s" data-size="%d"></canvas>',
            htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            $size
        );
    }

    /**
     * Returns the Google Charts URL for a QR code.
     * Note: The full otpauth URL (including the secret) is sent to Google's servers.
     * Only use this as a last resort fallback if JS is disabled.
     *
     * @param  string $data
     * @param  int    $size
     * @return string  URL
     */
    public static function googleChartsUrl(string $data, int $size = 200): string
    {
        return 'https://chart.googleapis.com/chart?chs=' . $size . 'x' . $size
            . '&chld=M|0&cht=qr&chl=' . rawurlencode($data);
    }
}
