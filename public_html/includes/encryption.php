<?php
/**
 * VaultFX — AES-256-GCM Encryption Layer
 * ========================================
 * Implements:
 *  • AES-256-GCM authenticated encryption (confidentiality + integrity)
 *  • Envelope encryption: per-record derived keys via HKDF-SHA256
 *  • Unique random IV per encryption operation (12 bytes / 96 bits for GCM)
 *  • GCM authentication tag storage (16 bytes) for tamper detection
 *  • Key versioning for seamless key rotation
 *
 * Storage format (base64-encoded blob):
 *   [ key_version(1 byte) | iv(12 bytes) | tag(16 bytes) | ciphertext(variable) ]
 *
 * Security guarantees:
 *   - Same plaintext encrypted twice produces different ciphertext (IVs are random)
 *   - Tag verification on decrypt detects any tampering
 *   - Per-record HKDF derivation limits blast radius if one key is exposed
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class Encryption
{
    private const CIPHER      = 'aes-256-gcm';
    private const IV_LENGTH   = 12;    // 96 bits — NIST recommended for GCM
    private const TAG_LENGTH  = 16;    // 128 bits — maximum GCM tag
    private const KEY_BYTES   = 32;    // 256 bits
    private const SALT_BYTES  = 32;    // 256-bit HKDF salt
    private const HKDF_INFO   = 'vaultfx-credential-v1';

    // ── Encryption ────────────────────────────────────────────

    /**
     * Encrypts a plaintext credential password.
     *
     * @param  string $plaintext    The password to encrypt
     * @return array{
     *   encrypted_blob: string,   base64-encoded storage blob
     *   salt: string,             hex-encoded 32-byte HKDF salt
     *   key_version: int          Master key version used
     * }
     * @throws RuntimeException on failure
     */
    public static function encryptCredential(string $plaintext): array
    {
        if (strlen($plaintext) === 0) {
            throw new InvalidArgumentException('Cannot encrypt empty plaintext.');
        }

        // Reject null bytes
        if (str_contains($plaintext, "\0")) {
            throw new InvalidArgumentException('Plaintext contains null bytes.');
        }

        // Get current master key version
        $keyVersion = vaultfx_current_key_version();
        $masterKey  = vaultfx_get_encryption_key($keyVersion);

        // Generate a unique random salt for HKDF derivation
        $salt = random_bytes(self::SALT_BYTES);

        // Derive a per-record encryption key
        $recordKey = self::deriveKey($masterKey, $salt);

        // Generate a unique random IV for this encryption
        $iv = random_bytes(self::IV_LENGTH);

        // Encrypt with AES-256-GCM
        $tag        = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $recordKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',             // No additional authenticated data
            self::TAG_LENGTH
        );

        if ($ciphertext === false || strlen($tag) !== self::TAG_LENGTH) {
            throw new RuntimeException('Encryption failed.');
        }

        // Pack: key_version(1) + iv(12) + tag(16) + ciphertext
        $blob = pack('C', $keyVersion) . $iv . $tag . $ciphertext;

        // Zero out sensitive intermediates
        sodium_memzero($recordKey);

        return [
            'encrypted_blob' => base64_encode($blob),
            'salt'           => bin2hex($salt),
            'key_version'    => $keyVersion,
        ];
    }

    /**
     * Decrypts a stored credential blob.
     *
     * @param  string $encryptedBlob  base64-encoded blob from DB
     * @param  string $saltHex        hex-encoded HKDF salt from DB
     * @return string                 Decrypted plaintext
     * @throws RuntimeException on failure or tamper detection
     */
    public static function decryptCredential(string $encryptedBlob, string $saltHex): string
    {
        $blob = base64_decode($encryptedBlob, true);
        if ($blob === false) {
            throw new RuntimeException('Invalid encrypted blob encoding.');
        }

        // Minimum size: 1 + 12 + 16 = 29 bytes
        $minLen = 1 + self::IV_LENGTH + self::TAG_LENGTH;
        if (strlen($blob) < $minLen + 1) {
            throw new RuntimeException('Encrypted blob too short — possible corruption.');
        }

        // Unpack components
        $keyVersion = unpack('C', substr($blob, 0, 1))[1];
        $iv         = substr($blob, 1, self::IV_LENGTH);
        $tag        = substr($blob, 1 + self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($blob, 1 + self::IV_LENGTH + self::TAG_LENGTH);

        if (strlen($ciphertext) === 0) {
            throw new RuntimeException('Empty ciphertext in blob.');
        }

        // Load the master key for the stored version
        $masterKey = vaultfx_get_encryption_key($keyVersion);

        // Reconstruct the salt
        $salt = hex2bin($saltHex);
        if ($salt === false || strlen($salt) !== self::SALT_BYTES) {
            throw new RuntimeException('Invalid HKDF salt.');
        }

        // Re-derive the per-record key
        $recordKey = self::deriveKey($masterKey, $salt);

        // Decrypt with AES-256-GCM — tag verification is automatic
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $recordKey,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        sodium_memzero($recordKey);

        if ($plaintext === false) {
            // GCM tag mismatch = tamper detected or wrong key
            throw new RuntimeException('Decryption failed — authentication tag mismatch. Possible tampering detected.');
        }

        return $plaintext;
    }

    /**
     * Encrypts the TOTP secret for a user (uses user ID as HKDF info context).
     */
    public static function encryptTotpSecret(string $secret, int $userId): string
    {
        $result = self::encryptWithContext($secret, 'vaultfx-totp-' . $userId);
        return $result['blob'] . ':' . $result['salt'];
    }

    /**
     * Decrypts a stored TOTP secret.
     */
    public static function decryptTotpSecret(string $stored, int $userId): string
    {
        [$blob, $salt] = explode(':', $stored, 2);
        return self::decryptWithContext($blob, $salt, 'vaultfx-totp-' . $userId);
    }

    // ── Key Rotation ──────────────────────────────────────────

    /**
     * Re-encrypts a credential blob with the current (latest) key version.
     * Used during key rotation.
     *
     * @param  string $encryptedBlob  Current blob
     * @param  string $saltHex        Current salt
     * @return array                  New blob, salt, version
     */
    public static function rotateCredential(string $encryptedBlob, string $saltHex): array
    {
        // Decrypt with old key
        $plaintext = self::decryptCredential($encryptedBlob, $saltHex);

        // Re-encrypt with current key
        $result = self::encryptCredential($plaintext);

        // Zero out plaintext ASAP
        sodium_memzero($plaintext);

        return $result;
    }

    // ── Helpers ───────────────────────────────────────────────

    /**
     * Derives a 32-byte record-specific key using HKDF-SHA256.
     */
    private static function deriveKey(string $masterKey, string $salt): string
    {
        return hash_hkdf('sha256', $masterKey, self::KEY_BYTES, self::HKDF_INFO, $salt);
    }

    /**
     * Generic encrypt with a custom HKDF context string (for TOTP etc.)
     */
    private static function encryptWithContext(string $plaintext, string $context): array
    {
        $keyVersion = vaultfx_current_key_version();
        $masterKey  = vaultfx_get_encryption_key($keyVersion);
        $salt       = random_bytes(self::SALT_BYTES);
        $recordKey  = hash_hkdf('sha256', $masterKey, self::KEY_BYTES, $context, $salt);
        $iv         = random_bytes(self::IV_LENGTH);

        $tag        = '';
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $recordKey, OPENSSL_RAW_DATA, $iv, $tag, '', self::TAG_LENGTH);

        if ($ciphertext === false) {
            throw new RuntimeException('TOTP encryption failed.');
        }

        $blob = base64_encode(pack('C', $keyVersion) . $iv . $tag . $ciphertext);
        sodium_memzero($recordKey);

        return ['blob' => $blob, 'salt' => bin2hex($salt)];
    }

    /**
     * Generic decrypt with a custom HKDF context string.
     */
    private static function decryptWithContext(string $blob, string $saltHex, string $context): string
    {
        $raw        = base64_decode($blob, true);
        $keyVersion = unpack('C', substr($raw, 0, 1))[1];
        $iv         = substr($raw, 1, self::IV_LENGTH);
        $tag        = substr($raw, 1 + self::IV_LENGTH, self::TAG_LENGTH);
        $ciphertext = substr($raw, 1 + self::IV_LENGTH + self::TAG_LENGTH);

        $masterKey  = vaultfx_get_encryption_key($keyVersion);
        $salt       = hex2bin($saltHex);
        $recordKey  = hash_hkdf('sha256', $masterKey, self::KEY_BYTES, $context, $salt);

        $plaintext  = openssl_decrypt($ciphertext, self::CIPHER, $recordKey, OPENSSL_RAW_DATA, $iv, $tag);
        sodium_memzero($recordKey);

        if ($plaintext === false) {
            throw new RuntimeException('Decryption failed.');
        }

        return $plaintext;
    }

    /**
     * Generates a cryptographically random password.
     *
     * @param  int    $length       Password length (8–64)
     * @param  bool   $upper        Include uppercase
     * @param  bool   $lower        Include lowercase
     * @param  bool   $digits       Include digits
     * @param  bool   $special      Include special characters
     * @return string               Generated password
     */
    public static function generatePassword(
        int $length = 20,
        bool $upper = true,
        bool $lower = true,
        bool $digits = true,
        bool $special = true
    ): string {
        $length  = max(8, min(64, $length));
        $charset = '';
        $required = [];

        if ($upper)   { $charset .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; $required[] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'; }
        if ($lower)   { $charset .= 'abcdefghijklmnopqrstuvwxyz'; $required[] = 'abcdefghijklmnopqrstuvwxyz'; }
        if ($digits)  { $charset .= '0123456789'; $required[] = '0123456789'; }
        if ($special) { $charset .= '!@#$%^&*()_+-=[]{}|;:,.<>?'; $required[] = '!@#$%^&*()_+-=[]{}|;:,.<>?'; }

        if (empty($charset)) {
            throw new InvalidArgumentException('At least one character set must be selected.');
        }

        $password = '';
        $charLen  = strlen($charset);

        // Ensure at least one character from each required set
        foreach ($required as $chars) {
            $password .= $chars[random_int(0, strlen($chars) - 1)];
        }

        // Fill the rest randomly
        while (strlen($password) < $length) {
            $password .= $charset[random_int(0, $charLen - 1)];
        }

        // Fisher-Yates shuffle using random_int (cryptographically secure)
        $arr = str_split($password);
        for ($i = count($arr) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$arr[$i], $arr[$j]] = [$arr[$j], $arr[$i]];
        }

        return implode('', $arr);
    }

    // Prevent instantiation
    private function __construct() {}
}
