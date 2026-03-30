# VaultFX — Local Development Setup

## Prerequisites

- **PHP 8.1+** with extensions: `pdo_mysql`, `openssl`, `sodium`, `mbstring`, `json`
- **MySQL 8.0+** (or MariaDB 10.6+)
- A terminal

---

## 1. Create the Database

```sql
CREATE DATABASE vaultfx CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'vaultfx'@'localhost' IDENTIFIED BY 'your_db_password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, INDEX, ALTER ON vaultfx.* TO 'vaultfx'@'localhost';
-- Deny UPDATE/DELETE on audit_log for security
REVOKE UPDATE, DELETE ON vaultfx.audit_log FROM 'vaultfx'@'localhost';
FLUSH PRIVILEGES;
```

> You can also just use `root` locally for simplicity — the REVOKE step is a production hardening measure.

---

## 2. Configure the App

Copy the sample config and fill in your values:

```bash
cp config/config.sample.php config/config.php
```

Edit `config/config.php` and set:

```php
define('DB_HOST',   'localhost');
define('DB_PORT',   '3306');
define('DB_NAME',   'vaultfx');
define('DB_USER',   'vaultfx');
define('DB_PASS',   'your_db_password');
define('APP_URL',   'http://localhost:8000');
```

> **Note:** If `config/config.sample.php` doesn't exist yet, copy the installed `config/config.php` from the installer output (step 4 below runs the installer which writes it for you).

---

## 3. Start the PHP Built-in Server

```bash
cd /path/to/vaultfx/public_html
php -S localhost:8000 index.php
```

> The built-in server routes all requests through `index.php`, matching the `.htaccess` rewrite rules used in production.

---

## 4. Run the Installer

Open your browser and go to:

```
http://localhost:8000/../install/install.php
```

Or navigate directly:

```
http://localhost:8000
```

Since `install.lock` doesn't exist yet, you'll be redirected to the installer automatically.

**The installer will:**
1. Check PHP requirements (sodium, pdo_mysql, openssl, etc.)
2. Create all database tables from `install/schema.sql`
3. Generate an AES-256 encryption key in `config/encryption-key.php`
4. Write `config/config.php` with your DB credentials
5. Create the Super Admin account
6. Write `install/install.lock` to disable the installer permanently

---

## 5. Set Up 2FA (Required for Super Admin)

After logging in, you'll be prompted to set up 2FA. Use any TOTP app:
- **Google Authenticator** (iOS/Android)
- **Authy**
- **1Password** / **Bitwarden** (built-in TOTP)

The QR code is rendered **client-side** — the secret never leaves your browser.

---

## 6. Directory Structure

```
vaultfx/
├── config/                  ← Outside web root (never publicly accessible)
│   ├── config.php           ← DB credentials, app constants
│   └── encryption-key.php   ← AES master key (chmod 600 in production)
│
├── install/
│   ├── install.php          ← One-time setup wizard
│   ├── install.lock         ← Created after install (blocks re-running)
│   └── schema.sql           ← Full database schema
│
├── logs/                    ← App logs (created by installer)
│
└── public_html/             ← Web root (point your server here)
    ├── index.php            ← Single entry point / front controller
    ├── .htaccess            ← Security headers, rewrites, PHP hardening
    ├── includes/            ← Core PHP classes (DB, Auth, Session, etc.)
    ├── pages/               ← Page templates (included by index.php)
    ├── api/                 ← AJAX/API endpoints
    ├── assets/              ← CSS, JS, fonts
    └── lib/                 ← Third-party libraries (GoogleAuthenticator)
```

---

## 7. Common Issues

### "Application not configured"
The `config/config.php` file is missing. Run the installer or create it manually.

### "sodium_memzero() not found"
The `sodium` PHP extension is not enabled. On macOS with Homebrew:
```bash
brew install php
# sodium is bundled with PHP 7.2+, check php.ini
php -m | grep sodium
```
On Ubuntu/Debian:
```bash
sudo apt install php8.x-sodium
```

### "PDO MySQL driver not found"
```bash
# macOS
brew install php   # includes pdo_mysql

# Ubuntu/Debian
sudo apt install php8.x-mysql
```

### Installer redirects to blank page
Check PHP errors:
```bash
php -S localhost:8000 index.php 2>&1
```

### QR code not rendering
The 2FA setup page loads `qrcode.js` from `unpkg.com`. Make sure you have internet access during setup, or host the file locally in `assets/js/qrcode.min.js` and update the `<script>` tag in `pages/2fa-setup.php`.

---

## 8. Production Deployment (Hostinger)

1. Upload all files via FTP/FileManager
2. Point web root to `public_html/`
3. Ensure `config/` is **above** `public_html/` (outside web root)
4. Run `chmod 600 config/encryption-key.php` via SSH or a PHP script
5. Create the DB and run the installer at `yourdomain.com/../install/install.php`
6. Verify `.htaccess` is processed (LiteSpeed supports it on Hostinger Business)
7. Set `APP_URL` to your live domain in `config/config.php`

---

## 9. Test Accounts (Created by Installer)

| Role        | Username   | Set During Install |
|-------------|------------|--------------------|
| Super Admin | (you set)  | Step 3 of installer |

Additional users are created via **Users** → **Add User** in the UI.

---

## 10. Key Security Notes

- `config/encryption-key.php` contains your master AES key — **back it up securely**. If lost, all encrypted credentials are unrecoverable.
- The audit log is append-only. The DB user has no UPDATE/DELETE on `audit_log`.
- Password reveals are logged before the password is returned to the client.
- All sessions are tied to IP subnet + User-Agent hash.
