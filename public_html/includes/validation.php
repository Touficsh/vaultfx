<?php
/**
 * VaultFX — Input Validation
 * ===========================
 * Server-side validation for all input types.
 * Returns structured error arrays for clean form handling.
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

class Validation
{
    private array $errors = [];

    // ── Field-Level Validators ────────────────────────────────

    public function required(string $field, mixed $value, string $label): static
    {
        if ($value === null || $value === '' || (is_array($value) && empty($value))) {
            $this->errors[$field] = "{$label} is required.";
        }
        return $this;
    }

    public function minLength(string $field, string $value, int $min, string $label): static
    {
        if (!isset($this->errors[$field]) && mb_strlen($value) < $min) {
            $this->errors[$field] = "{$label} must be at least {$min} characters.";
        }
        return $this;
    }

    public function maxLength(string $field, string $value, int $max, string $label): static
    {
        if (!isset($this->errors[$field]) && mb_strlen($value) > $max) {
            $this->errors[$field] = "{$label} must not exceed {$max} characters.";
        }
        return $this;
    }

    public function email(string $field, string $value, string $label = 'Email'): static
    {
        if (!isset($this->errors[$field]) && !filter_var($value, FILTER_VALIDATE_EMAIL)) {
            $this->errors[$field] = "{$label} must be a valid email address.";
        }
        return $this;
    }

    public function integer(string $field, mixed $value, string $label): static
    {
        if (!isset($this->errors[$field]) && filter_var($value, FILTER_VALIDATE_INT) === false) {
            $this->errors[$field] = "{$label} must be a valid integer.";
        }
        return $this;
    }

    public function ipAddress(string $field, string $value, string $label = 'IP Address'): static
    {
        if (!isset($this->errors[$field]) && !empty($value) &&
            !filter_var($value, FILTER_VALIDATE_IP) &&
            !self::isValidHostname($value)) {
            $this->errors[$field] = "{$label} must be a valid IP address or hostname.";
        }
        return $this;
    }

    public function alphanumericDash(string $field, string $value, string $label): static
    {
        if (!isset($this->errors[$field]) && !preg_match('/^[a-zA-Z0-9\-_. ]+$/', $value)) {
            $this->errors[$field] = "{$label} may only contain letters, numbers, hyphens, underscores, dots, and spaces.";
        }
        return $this;
    }

    public function username(string $field, string $value): static
    {
        if (!isset($this->errors[$field]) && !preg_match('/^[a-zA-Z0-9_\-\.]{3,50}$/', $value)) {
            $this->errors[$field] = "Username must be 3–50 characters and may only contain letters, numbers, underscores, hyphens, and dots.";
        }
        return $this;
    }

    public function noNullBytes(string $field, string $value, string $label): static
    {
        if (!isset($this->errors[$field]) && str_contains($value, "\0")) {
            $this->errors[$field] = "{$label} contains invalid characters.";
        }
        return $this;
    }

    public function inEnum(string $field, mixed $value, array $allowed, string $label): static
    {
        if (!isset($this->errors[$field]) && !in_array($value, $allowed, true)) {
            $this->errors[$field] = "{$label} has an invalid value.";
        }
        return $this;
    }

    public function date(string $field, string $value, string $label): static
    {
        if (!isset($this->errors[$field]) && !empty($value)) {
            $d = DateTime::createFromFormat('Y-m-d', $value);
            if (!$d || $d->format('Y-m-d') !== $value) {
                $this->errors[$field] = "{$label} must be a valid date (YYYY-MM-DD).";
            }
        }
        return $this;
    }

    public function loginNumber(string $field, string $value, string $label = 'Login number'): static
    {
        if (!isset($this->errors[$field])) {
            // Login numbers can be numeric strings (MT4/MT5 account numbers)
            if (!preg_match('/^\d{1,20}$/', $value)) {
                $this->errors[$field] = "{$label} must be a numeric account number (up to 20 digits).";
            }
        }
        return $this;
    }

    public function tags(string $field, string $value, string $label = 'Tags'): static
    {
        if (!isset($this->errors[$field]) && !empty($value)) {
            if (mb_strlen($value) > 500) {
                $this->errors[$field] = "{$label} exceed maximum length.";
            }
            $tags = parse_tags($value);
            foreach ($tags as $tag) {
                if (!preg_match('/^[a-zA-Z0-9\-_ ]{1,50}$/', $tag)) {
                    $this->errors[$field] = "Tag '{$tag}' contains invalid characters. Use letters, numbers, hyphens, underscores, and spaces.";
                    break;
                }
            }
        }
        return $this;
    }

    // ── User Password Strength Validation ─────────────────────

    /**
     * Validates a user account password meets security requirements.
     * Does NOT validate credential passwords (those can be anything the user wants).
     */
    public function strongPassword(string $field, string $value, string $label = 'Password'): static
    {
        if (isset($this->errors[$field])) {
            return $this;
        }

        $errors = self::checkPasswordStrength($value);

        if (!empty($errors)) {
            $this->errors[$field] = $errors[0]; // Show first failing rule
        }

        return $this;
    }

    /**
     * Returns all password strength failures.
     *
     * @param  string $password
     * @return array  Empty if strong
     */
    public static function checkPasswordStrength(string $password): array
    {
        $errors = [];

        if (strlen($password) < MIN_PASSWORD_LENGTH) {
            $errors[] = 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one digit.';
        }
        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character.';
        }

        // Check against common breached passwords list
        if (self::isBreachedPassword($password)) {
            $errors[] = 'This password appears in known data breaches. Please choose a different password.';
        }

        return $errors;
    }

    /**
     * Checks if password is in the common breached list.
     * Uses a subset of the top breached passwords.
     */
    public static function isBreachedPassword(string $password): bool
    {
        // Top commonly breached passwords — extend this list
        $breached = [
            'password','123456','12345678','qwerty','abc123','monkey','1234567',
            'letmein','trustno1','dragon','master','111111','baseball','iloveyou',
            'sunshine','princess','welcome','shadow','superman','michael','soccer',
            'batman','pass','123456789','hockey','ranger','daniel','starwars',
            'klaster','112233','george','computer','michelle','jessica','pepper',
            'password1','zxcvbn','hello','whatever','donald','password123',
            'qwerty123','qwertyuiop','iloveyou1','admin','admin123','root',
            'toor','pass123','Password1','Password1!','P@ssword1','Welcome1',
            'Welcome1!','Summer2023','Summer2024','Summer2025','Winter2024',
            'Spring2024','Football1','Baseball1','Monkey123','Shadow123',
        ];

        // Case-insensitive check
        $lower = strtolower($password);
        foreach ($breached as $b) {
            if ($lower === strtolower($b)) {
                return true;
            }
        }

        return false;
    }

    // ── Result Accessors ──────────────────────────────────────

    public function fails(): bool
    {
        return !empty($this->errors);
    }

    public function passes(): bool
    {
        return empty($this->errors);
    }

    public function errors(): array
    {
        return $this->errors;
    }

    public function firstError(): string
    {
        return reset($this->errors) ?: '';
    }

    // ── Static Helpers ────────────────────────────────────────

    /**
     * Strips tags and limits string length.
     */
    public static function sanitizeText(string $input, int $maxLen = 255): string
    {
        $clean = strip_tags(trim($input));
        return mb_substr($clean, 0, $maxLen);
    }

    /**
     * Rejects null bytes in any value.
     */
    public static function hasNullByte(string $value): bool
    {
        return str_contains($value, "\0");
    }

    /**
     * Validates a simple hostname.
     */
    private static function isValidHostname(string $host): bool
    {
        return (bool)preg_match('/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})*$/', $host);
    }

    /**
     * Validates a CIDR notation string.
     */
    public static function isValidCidr(string $cidr): bool
    {
        if (!str_contains($cidr, '/')) {
            return (bool)filter_var($cidr, FILTER_VALIDATE_IP);
        }
        [$ip, $prefix] = explode('/', $cidr, 2);
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        $prefix = (int)$prefix;
        return $prefix >= 0 && $prefix <= 32;
    }
}
