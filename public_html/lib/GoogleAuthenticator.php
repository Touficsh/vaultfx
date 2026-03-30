<?php
/**
 * PHP Google Authenticator — TOTP/HOTP Implementation
 * =====================================================
 * Standalone TOTP library compatible with Google Authenticator, Authy, etc.
 * Based on RFC 6238 (TOTP) and RFC 4226 (HOTP).
 *
 * No Composer required — single self-contained file.
 *
 * Original concept by PHPGangsta, heavily revised for security and PHP 8 compatibility.
 */

class GoogleAuthenticator
{
    private const CODE_LENGTH   = 6;
    private const KEY_REGEN_AT  = 60;   // Regenerate secret after N chars
    private const BASE32_CHARS  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generates a new Base32-encoded secret key.
     * Uses cryptographically secure random bytes.
     *
     * @param  int $length  Number of base32 characters (default 32 = 160 bits)
     * @return string       Base32-encoded secret
     */
    public function createSecret(int $length = 32): string
    {
        // Each base32 char encodes 5 bits; we need $length * 5 bits = $length * 5 / 8 bytes
        $bytes  = (int)ceil($length * 5 / 8);
        $random = random_bytes($bytes);
        $result = '';
        $i      = 0;

        $buffer     = 0;
        $bufferBits = 0;

        foreach (str_split($random) as $byte) {
            $buffer     = ($buffer << 8) | ord($byte);
            $bufferBits += 8;

            while ($bufferBits >= 5) {
                $bufferBits -= 5;
                $result     .= self::BASE32_CHARS[($buffer >> $bufferBits) & 0x1F];
            }
        }

        return substr($result, 0, $length);
    }

    /**
     * Gets the TOTP code for the current (or given) time step.
     *
     * @param  string $secret      Base32-encoded secret
     * @param  int|null $timeSlice Unix timestamp / 30 (defaults to now)
     * @return string              6-digit code
     */
    public function getCode(string $secret, ?int $timeSlice = null): string
    {
        if ($timeSlice === null) {
            $timeSlice = (int)floor(time() / 30);
        }

        $secretKey = $this->base32Decode($secret);

        // Pack time as big-endian 64-bit integer
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);

        // HMAC-SHA1
        $hmac     = hash_hmac('SHA1', $time, $secretKey, true);
        $offset   = ord(substr($hmac, -1)) & 0x0F;
        $hash     = substr($hmac, $offset, 4);
        $value    = unpack('N', $hash)[1] & 0x7FFFFFFF;

        return str_pad((string)($value % (10 ** self::CODE_LENGTH)), self::CODE_LENGTH, '0', STR_PAD_LEFT);
    }

    /**
     * Verifies a submitted TOTP code.
     *
     * @param  string $secret     Base32-encoded secret
     * @param  string $code       6-digit code to verify
     * @param  int    $discrepancy  Number of time steps to allow (1 = ±30s, recommended)
     * @return bool
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1): bool
    {
        $code = trim($code);
        if (!preg_match('/^\d{6}$/', $code)) {
            return false;
        }

        $currentTimeSlice = (int)floor(time() / 30);

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Returns the otpauth:// URI for QR code generation.
     *
     * @param  string $secret    Base32-encoded secret
     * @param  string $name      Account name/email (URL-encoded)
     * @param  string $issuer    App name (e.g. "VaultFX")
     * @return string            otpauth URI
     */
    public function getQRCodeUrl(string $secret, string $name, string $issuer = 'VaultFX'): string
    {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($issuer),
            rawurlencode($name),
            $secret,
            rawurlencode($issuer)
        );
    }

    /**
     * Generates 8 one-time backup codes (8 alphanumeric chars each).
     * Returns plain codes (caller must hash them before storing).
     *
     * @return array  8 plain-text backup codes
     */
    public function generateBackupCodes(): array
    {
        $codes   = [];
        $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $len     = strlen($charset);

        for ($i = 0; $i < 8; $i++) {
            $code = '';
            for ($j = 0; $j < 8; $j++) {
                $code .= $charset[random_int(0, $len - 1)];
            }
            $codes[] = $code;
        }

        return $codes;
    }

    /**
     * Decodes a Base32 string to raw bytes.
     *
     * @param  string $input  Base32-encoded string
     * @return string         Raw binary
     */
    private function base32Decode(string $input): string
    {
        $input   = strtoupper(trim($input));
        $output  = '';
        $buffer  = 0;
        $bits    = 0;

        foreach (str_split($input) as $char) {
            $pos = strpos(self::BASE32_CHARS, $char);
            if ($pos === false) {
                continue; // Skip padding and unknown characters
            }
            $buffer = ($buffer << 5) | $pos;
            $bits  += 5;
            if ($bits >= 8) {
                $bits   -= 8;
                $output .= chr(($buffer >> $bits) & 0xFF);
            }
        }

        return $output;
    }
}
