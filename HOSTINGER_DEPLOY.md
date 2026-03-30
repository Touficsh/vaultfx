# VaultFX — Hostinger Deployment Guide

> **Estimated time:** 15–20 minutes
> **Tested on:** Hostinger Business / Cloud hosting (LiteSpeed, PHP 8.1+)

---

## Prerequisites

- Hostinger Business or higher plan (needs SSH access for chmod)
- PHP 8.1+ with extensions: `pdo_mysql`, `openssl`, `sodium`, `mbstring`, `json`
- MySQL database created in hPanel
- Domain/subdomain pointed to your hosting

---

## Step 1 — Create the Database

In **hPanel → Databases → MySQL Databases**:

1. Create a new database, e.g. `u123456_vaultfx`
2. Create a new DB user, e.g. `u123456_vaultfx`, and set a strong password
3. Assign the user to the database with **All Privileges**
4. Note down:
   - Host: `localhost`
   - Database name: `u123456_vaultfx`
   - Username: `u123456_vaultfx`
   - Password: (what you just set)

---

## Step 2 — Upload Files

Your local VaultFX project has this structure:

```
vaultfx/
├── config/          ← goes to /home/username/config/
├── install/         ← goes to /home/username/install/
├── logs/            ← goes to /home/username/logs/
└── public_html/     ← goes to /home/username/public_html/
```

**Option A — File Manager (no SSH)**

1. In hPanel → **File Manager**, navigate to `/home/username/` (your root, one level above `public_html/`)
2. Create folders: `config`, `install`, `logs`, `logs/audit_export`
3. Upload `config/config.example.php` → rename it to `config.php` after uploading
4. Upload `install/schema.sql` and `install/install.php`
5. Upload the entire `public_html/` folder contents into your existing Hostinger `public_html/`

**Option B — FTP (FileZilla)**

1. Connect using your Hostinger FTP credentials (hPanel → FTP Accounts)
2. Upload the entire project root (`vaultfx/`) to `/home/username/` so paths align
3. The remote path for web files becomes `/home/username/public_html/`

**Option C — Git (SSH)**

```bash
ssh username@yourserver.hostinger.com
cd /home/username
git clone https://github.com/Touficsh/vaultfx.git
```

> Skip Step 2 if using Git — the repo is already cloned.

---

## Step 3 — Configure the App

**Via File Manager:**

1. Open `config/config.php` (you uploaded `config.example.php` and renamed it)
2. Edit these values:

```php
define('DB_HOST',    'localhost');
define('DB_NAME',    'u123456_vaultfx');   // your DB name
define('DB_USER',    'u123456_vaultfx');   // your DB user
define('DB_PASS',    'YourStrongPass123!');
define('APP_URL',    'https://yourdomain.com');  // your domain, no trailing slash
define('APP_ENV',    'production');
```

3. Save the file.

---

## Step 4 — Set File Permissions

**Via SSH:**

```bash
ssh username@yourserver.hostinger.com

# Secure the config directory
chmod 700 /home/username/config/
chmod 600 /home/username/config/config.php

# Logs directory must be writable by PHP
chmod 755 /home/username/logs/
chmod 755 /home/username/logs/audit_export/

# public_html permissions
find /home/username/public_html/ -type f -exec chmod 644 {} \;
find /home/username/public_html/ -type d -exec chmod 755 {} \;
```

> **No SSH?** Skip for now — the installer will warn you if permissions are wrong. Fix after install.

---

## Step 5 — Run the Installer

1. Open your browser and navigate to:
   ```
   https://yourdomain.com/install/install.php
   ```
   > If you see a 404, make sure `install/install.php` was uploaded to the correct location.

2. The installer will:
   - ✅ Check PHP extensions
   - ✅ Test database connectivity
   - ✅ Create all database tables from `schema.sql`
   - ✅ Generate `config/encryption-key.php` (AES-256 master key)
   - ✅ Insert default system settings
   - ✅ Create your Super Admin account
   - ✅ Write `config/install.lock` (prevents re-running the installer)

3. Fill in the installer form and complete setup.

4. **After install completes** — lock down the encryption key:
   ```bash
   chmod 600 /home/username/config/encryption-key.php
   ```

---

## Step 6 — Verify .htaccess is Active

VaultFX uses `.htaccess` for URL routing and security headers. On Hostinger:

- **LiteSpeed** (Business/Cloud): `.htaccess` is fully supported ✅
- **Apache**: Fully supported ✅
- If the app shows a blank page or 500 error: check `logs/php_errors.log`

---

## Step 7 — Configure Domain / SSL

1. In hPanel → **SSL** → enable Let's Encrypt for your domain
2. In `config/config.php` make sure `APP_URL` uses `https://`
3. If you're using a subdomain (e.g. `vault.yourdomain.com`), point it to `public_html/`

---

## Step 8 — First Login & 2FA Setup

1. Log in at `https://yourdomain.com` with the Super Admin credentials you set in the installer
2. You'll be prompted to set up 2FA (required for Super Admin)
3. Scan the QR code with Google Authenticator, Authy, or 1Password
4. Save your backup codes securely

---

## Step 9 — Post-Deploy Checklist

- [ ] `APP_ENV` is set to `production` in config.php
- [ ] `APP_URL` matches your live domain (https)
- [ ] `config/config.php` permissions are 600
- [ ] `config/encryption-key.php` permissions are 600
- [ ] SSL certificate is active
- [ ] You can log in and see the dashboard
- [ ] 2FA is configured for Super Admin
- [ ] Settings → Security → 2FA is enabled for Admins
- [ ] Installer is disabled (config/install.lock exists)

---

## Directory Structure on Hostinger

```
/home/username/                     ← your Hostinger home
├── public_html/                    ← WEB ROOT (publicly accessible)
│   ├── index.php                   ← Front controller
│   ├── .htaccess                   ← Routing + security headers
│   ├── assets/                     ← CSS, JS, images
│   ├── includes/                   ← PHP core classes
│   ├── pages/                      ← Page templates
│   ├── api/                        ← AJAX endpoints
│   └── lib/                        ← Third-party libs
│
├── config/                         ← NOT in web root (safe)
│   ├── config.php                  ← DB credentials (chmod 600)
│   └── encryption-key.php          ← AES master key (chmod 600)
│
├── install/                        ← NOT in web root
│   ├── install.php                 ← One-time installer
│   └── schema.sql                  ← DB schema
│
└── logs/                           ← PHP + app logs (writable by PHP)
    ├── php_errors.log
    ├── app.log
    └── audit_export/
```

---

## Troubleshooting

### "Application not configured"
→ `config/config.php` is missing or in the wrong location. It should be at `/home/username/config/config.php`.

### Installer 404
→ `install/install.php` was not uploaded, or it ended up inside `public_html/install/` instead of `/home/username/install/`.

### White screen / 500 error
→ Check `/home/username/logs/php_errors.log` via File Manager. Common causes:
- Wrong `APP_ROOT` path
- Missing PHP extension (`sodium`, `pdo_mysql`)
- File permissions too restrictive

### Passwords/2FA not working after moving
→ The `config/encryption-key.php` **must** be the exact same file as when the data was encrypted. Keep a secure backup of it.

### Session errors
→ Hostinger may use a shared session path. The app uses database-backed sessions, so this should not be an issue.

---

## Security Notes

- **Back up `config/encryption-key.php` immediately** — if lost, all encrypted credentials are permanently unrecoverable
- The DB user should NOT have `DROP` or `TRUNCATE` privileges in production
- Enable IP Whitelist in **Settings → IP Whitelist** if accessing from a fixed IP
- Enable 2FA for all Admin accounts via **Settings → Security**
- Audit all reveals via **Audit Log** regularly
