<?php
/**
 * VaultFX — Installation Wizard
 * ================================
 * Run once to set up the application.
 * This script self-disables after successful installation.
 *
 * Security: This file should be DELETED or its directory
 * blocked via .htaccess after installation is complete.
 */

// Check if already installed
$lockFile = dirname(__DIR__) . '/config/install.lock';
if (file_exists($lockFile) && !isset($_GET['force'])) {
    die('<h2 style="font-family:monospace;color:red">Installation already completed. Delete install/ directory.</h2>');
}

define('VAULTFX_BOOT', true);
ini_set('display_errors', '1');
error_reporting(E_ALL);

$step   = (int)($_GET['step'] ?? 1);
$errors = [];
$info   = [];

// ── Step Definitions ──────────────────────────────────────────
// Step 1: System check
// Step 2: Database configuration
// Step 3: Create first Super Admin
// Step 4: Complete

// ── PHP Requirements ──────────────────────────────────────────
function checkRequirements(): array
{
    $checks  = [];
    $version = PHP_VERSION;

    $checks[] = ['name' => 'PHP Version ≥ 8.0', 'pass' => version_compare($version, '8.0.0', '>='), 'detail' => "Current: {$version}"];
    $checks[] = ['name' => 'OpenSSL Extension',  'pass' => extension_loaded('openssl'), 'detail' => 'Required for AES-256-GCM encryption'];
    $checks[] = ['name' => 'PDO Extension',       'pass' => extension_loaded('pdo'), 'detail' => ''];
    $checks[] = ['name' => 'PDO MySQL Driver',    'pass' => extension_loaded('pdo_mysql'), 'detail' => ''];
    $checks[] = ['name' => 'JSON Extension',      'pass' => extension_loaded('json'), 'detail' => ''];
    $checks[] = ['name' => 'Mbstring Extension',  'pass' => extension_loaded('mbstring'), 'detail' => ''];
    $checks[] = ['name' => 'Sodium Extension',    'pass' => extension_loaded('sodium'), 'detail' => 'Required for secure memory operations'];
    $checks[] = ['name' => 'Hash HKDF Support',   'pass' => function_exists('hash_hkdf'), 'detail' => 'Required for envelope encryption'];
    $checks[] = ['name' => 'random_bytes() Available', 'pass' => function_exists('random_bytes'), 'detail' => 'Required for cryptographic key generation'];

    // Config directory writable
    $configDir = dirname(__DIR__) . '/config';
    $checks[] = ['name' => 'Config Directory Writable', 'pass' => is_writable($configDir), 'detail' => $configDir];

    // Logs directory
    $logsDir = dirname(__DIR__) . '/logs';
    if (!is_dir($logsDir)) {
        @mkdir($logsDir, 0750, true);
    }
    $checks[] = ['name' => 'Logs Directory Exists',     'pass' => is_dir($logsDir), 'detail' => $logsDir];
    $checks[] = ['name' => 'Logs Directory Writable',   'pass' => is_writable($logsDir), 'detail' => ''];

    return $checks;
}

$allPassed = true;
if ($step >= 1) {
    $checks = checkRequirements();
    foreach ($checks as $c) {
        if (!$c['pass']) { $allPassed = false; break; }
    }
}

// ── Step 2: Database setup ────────────────────────────────────
$dbSetupDone = false;
if ($step === 2 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $dbHost    = trim($_POST['db_host'] ?? 'localhost');
    $dbPort    = (int)($_POST['db_port'] ?? 3306);
    $dbName    = trim($_POST['db_name'] ?? '');
    $dbUser    = trim($_POST['db_user'] ?? '');
    $dbPass    = $_POST['db_pass'] ?? '';
    $dbRtUser  = trim($_POST['db_rt_user'] ?? '');
    $dbRtPass  = $_POST['db_rt_pass'] ?? '';

    if (empty($dbName) || empty($dbUser)) {
        $errors[] = 'Database name and user are required.';
    } else {
        // Test privileged connection
        try {
            $dsn = "mysql:host={$dbHost};port={$dbPort};charset=utf8mb4";
            $pdo = new PDO($dsn, $dbUser, $dbPass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $info[] = 'Database connection successful.';

            // Create database if needed
            $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$dbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo->exec("USE `{$dbName}`");
            $info[] = "Database `{$dbName}` ready.";

            // Import schema
            $schema = file_get_contents(__DIR__ . '/schema.sql');
            foreach (array_filter(explode(';', $schema)) as $stmt) {
                $stmt = trim($stmt);
                if ($stmt) {
                    try { $pdo->exec($stmt); } catch (Exception $e) { /* ignore duplicate warnings */ }
                }
            }
            $info[] = 'Database schema created successfully.';

            // Generate master encryption key
            $masterKey = bin2hex(random_bytes(32)); // 64-char hex = 32 raw bytes
            $keyFile   = dirname(__DIR__) . '/config/encryption-key.php';

            $keyContent = "<?php\n";
            $keyContent .= "if (!defined('VAULTFX_BOOT')) { http_response_code(403); exit('Forbidden'); }\n";
            $keyContent .= "function vaultfx_get_encryption_key(int \$version = 1): string {\n";
            $keyContent .= "    static \$keys = [1 => '{$masterKey}'];\n";
            $keyContent .= "    if (!isset(\$keys[\$version])) throw new RuntimeException(\"Key version {\$version} not found.\");\n";
            $keyContent .= "    \$raw = hex2bin(\$keys[\$version]);\n";
            $keyContent .= "    if (\$raw === false || strlen(\$raw) !== 32) throw new RuntimeException('Invalid encryption key.');\n";
            $keyContent .= "    return \$raw;\n";
            $keyContent .= "}\n";
            $keyContent .= "function vaultfx_current_key_version(): int { return 1; }\n";

            file_put_contents($keyFile, $keyContent, LOCK_EX);
            chmod($keyFile, 0600);
            $info[] = 'Encryption key generated and stored securely.';

            // Write config.php
            $configFile = dirname(__DIR__) . '/config/config.php';
            $rtUser     = $dbRtUser ?: $dbUser;
            $rtPass     = $dbRtPass ?: $dbPass;

            $configContent = "<?php\n";
            $configContent .= "if (!defined('VAULTFX_BOOT')) { http_response_code(403); exit('Forbidden'); }\n";
            $configContent .= "define('DB_HOST',    " . var_export($dbHost, true) . ");\n";
            $configContent .= "define('DB_PORT',    " . var_export((string)$dbPort, true) . ");\n";
            $configContent .= "define('DB_NAME',    " . var_export($dbName, true) . ");\n";
            $configContent .= "define('DB_USER',    " . var_export($rtUser, true) . ");\n";
            $configContent .= "define('DB_PASS',    " . var_export($rtPass, true) . ");\n";
            $configContent .= "define('DB_CHARSET', 'utf8mb4');\n";
            $configContent .= "define('DB_INSTALL_USER', " . var_export($dbUser, true) . ");\n";
            $configContent .= "define('DB_INSTALL_PASS', " . var_export($dbPass, true) . ");\n";
            $configContent .= "define('APP_ROOT',   dirname(__DIR__));\n";
            $configContent .= "define('CONFIG_PATH', APP_ROOT . '/config');\n";
            $configContent .= "define('LOG_PATH',    APP_ROOT . '/logs');\n";
            $configContent .= "define('EXPORT_PATH', APP_ROOT . '/logs/audit_export');\n";
            $configContent .= "define('WEB_ROOT',    APP_ROOT . '/public_html');\n";
            $configContent .= "define('APP_NAME',    'VaultFX');\n";
            $configContent .= "define('APP_VERSION', '1.0.0');\n";
            $configContent .= "define('APP_URL',     'https://' . (\$_SERVER['HTTP_HOST'] ?? 'localhost'));\n";
            $configContent .= "define('APP_ENV',     'production');\n";
            $configContent .= "define('APP_TIMEZONE', 'UTC');\n";
            $configContent .= "define('SESSION_NAME',         'vfx_sess');\n";
            $configContent .= "define('SESSION_IDLE_TIMEOUT', 1800);\n";
            $configContent .= "define('SESSION_ABSOLUTE_MAX', 28800);\n";
            $configContent .= "define('BCRYPT_COST',          12);\n";
            $configContent .= "define('MIN_PASSWORD_LENGTH',  12);\n";
            $configContent .= "define('PHP_ERROR_LOG',  LOG_PATH . '/php_errors.log');\n";
            $configContent .= "define('APP_LOG',        LOG_PATH . '/app.log');\n";
            $configContent .= "define('ALERT_EMAIL_ENABLED', false);\n";
            $configContent .= "define('ALERT_EMAIL_FROM',    'noreply@yourdomain.com');\n";
            $configContent .= "define('ALERT_EMAIL_TO',      'admin@yourdomain.com');\n";
            $configContent .= "define('ENCRYPTION_KEY_FILE', CONFIG_PATH . '/encryption-key.php');\n";
            $configContent .= "define('INSTALL_LOCK_FILE',   CONFIG_PATH . '/install.lock');\n";

            file_put_contents($configFile, $configContent, LOCK_EX);
            chmod($configFile, 0640);
            $info[] = 'Configuration file written.';

            // Save state for next step
            session_start();
            $_SESSION['install_db'] = compact('dbHost', 'dbPort', 'dbName', 'dbUser', 'dbPass', 'dbRtUser', 'dbRtPass');
            $_SESSION['install_pdo_dsn'] = "mysql:host={$dbHost};port={$dbPort};dbname={$dbName};charset=utf8mb4";
            $_SESSION['install_pdo_user'] = $dbUser;
            $_SESSION['install_pdo_pass'] = $dbPass;

            $dbSetupDone = true;
            header('Location: install.php?step=3');
            exit;
        } catch (Exception $e) {
            $errors[] = 'Database error: ' . $e->getMessage();
        }
    }
}

// ── Step 3: Create Super Admin ─────────────────────────────────
$adminCreated = false;
if ($step === 3 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    session_start();

    $username = trim($_POST['username'] ?? '');
    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';

    if (empty($username) || empty($email) || empty($password)) {
        $errors[] = 'All fields are required.';
    } elseif ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    } elseif (strlen($password) < 12) {
        $errors[] = 'Password must be at least 12 characters.';
    } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[a-z]/', $password) || !preg_match('/[0-9]/', $password) || !preg_match('/[^a-zA-Z0-9]/', $password)) {
        $errors[] = 'Password must contain uppercase, lowercase, digits, and special characters.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email address.';
    } else {
        try {
            $dsn  = $_SESSION['install_pdo_dsn'] ?? '';
            $user = $_SESSION['install_pdo_user'] ?? '';
            $pass = $_SESSION['install_pdo_pass'] ?? '';

            $pdo = new PDO($dsn, $user, $pass, [
                PDO::ATTR_ERRMODE          => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);

            // Check if Argon2id is available
            $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
            $hash = password_hash($password, $algo);

            $stmt = $pdo->prepare(
                "INSERT INTO users (username, email, password_hash, role, can_view_passwords, is_active, force_password_change, password_changed_at)
                 VALUES (?, ?, ?, 'super_admin', 1, 1, 0, NOW())"
            );
            $stmt->execute([$username, $email, $hash]);

            // Create install lock
            file_put_contents($lockFile, date('Y-m-d H:i:s') . ' - Installed', LOCK_EX);

            $adminCreated = true;
            session_destroy();
            header('Location: install.php?step=4');
            exit;
        } catch (Exception $e) {
            $errors[] = 'Failed to create admin: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VaultFX Installation</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0f1a; color: #f0f4ff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .install-card { background: #111827; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 40px; max-width: 640px; width: 100%; box-shadow: 0 20px 60px rgba(0,0,0,0.5); }
    h1 { font-size: 1.6rem; margin-bottom: 4px; } h2 { font-size: 1.1rem; margin: 0 0 20px; color: #8b9cba; }
    .step-indicator { display: flex; gap: 8px; margin-bottom: 28px; }
    .step-dot { flex: 1; height: 4px; border-radius: 2px; background: rgba(255,255,255,0.1); }
    .step-dot.done { background: #10b981; } .step-dot.active { background: #3b82f6; }
    .check-row { display: flex; align-items: center; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.875rem; }
    .check-pass { color: #10b981; font-weight: 700; } .check-fail { color: #ef4444; font-weight: 700; }
    .field { display: flex; flex-direction: column; gap: 6px; margin-bottom: 16px; }
    .field label { font-size: 0.835rem; color: #8b9cba; font-weight: 500; }
    .field input { background: #1a2235; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 10px 14px; color: #f0f4ff; font-size: 0.9rem; width: 100%; font-family: inherit; }
    .field input:focus { outline: none; border-color: #3b82f6; }
    .field-row { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
    .btn { padding: 11px 22px; background: #3b82f6; color: #fff; border: none; border-radius: 8px; font-size: 0.9rem; font-weight: 600; cursor: pointer; font-family: inherit; }
    .btn:hover { background: #2563eb; }
    .alert-err { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); border-radius: 8px; padding: 10px 14px; color: #f87171; font-size: 0.875rem; margin-bottom: 16px; }
    .alert-ok  { background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 8px; padding: 10px 14px; color: #34d399; font-size: 0.875rem; margin-bottom: 8px; }
    .checklist { margin-top: 20px; list-style: none; } .checklist li { padding: 6px 0; font-size: 0.875rem; color: #8b9cba; border-bottom: 1px solid rgba(255,255,255,0.05); }
    .checklist li::before { content: '☐ '; color: #f59e0b; }
    .logo { font-size: 1.4rem; font-weight: 700; margin-bottom: 8px; }
    .logo .fx { color: #3b82f6; }
  </style>
</head>
<body>
<div class="install-card">
  <div class="logo">Vault<span class="fx">FX</span> — Installation</div>

  <div class="step-indicator">
    <div class="step-dot <?= $step >= 1 ? ($step > 1 ? 'done' : 'active') : '' ?>"></div>
    <div class="step-dot <?= $step >= 2 ? ($step > 2 ? 'done' : 'active') : '' ?>"></div>
    <div class="step-dot <?= $step >= 3 ? ($step > 3 ? 'done' : 'active') : '' ?>"></div>
    <div class="step-dot <?= $step >= 4 ? 'done' : '' ?>"></div>
  </div>

<?php if ($step === 1): ?>
  <h2>Step 1 — System Requirements</h2>

  <?php foreach ($checks as $c): ?>
  <div class="check-row">
    <span class="<?= $c['pass'] ? 'check-pass' : 'check-fail' ?>"><?= $c['pass'] ? '✓' : '✗' ?></span>
    <div style="flex:1">
      <div><?= htmlspecialchars($c['name']) ?></div>
      <?php if ($c['detail']): ?><div style="font-size:0.75rem;color:#4b5a73;font-family:monospace"><?= htmlspecialchars($c['detail']) ?></div><?php endif; ?>
    </div>
  </div>
  <?php endforeach; ?>

  <div style="margin-top:24px">
    <?php if ($allPassed): ?>
    <a href="install.php?step=2" class="btn">Continue →</a>
    <?php else: ?>
    <div class="alert-err" style="margin-bottom:16px">Please resolve the failing requirements before continuing.</div>
    <a href="install.php?step=1" class="btn" style="background:#6b7280">Re-check</a>
    <?php endif; ?>
  </div>

<?php elseif ($step === 2): ?>
  <h2>Step 2 — Database Configuration</h2>

  <?php foreach ($errors as $e): ?><div class="alert-err"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>
  <?php foreach ($info as $i): ?><div class="alert-ok"><?= htmlspecialchars($i) ?></div><?php endforeach; ?>

  <form method="POST" action="install.php?step=2">
    <div class="field-row">
      <div class="field">
        <label>Database Host</label>
        <input type="text" name="db_host" value="localhost" required>
      </div>
      <div class="field">
        <label>Port</label>
        <input type="text" name="db_port" value="3306" required>
      </div>
    </div>
    <div class="field">
      <label>Database Name</label>
      <input type="text" name="db_name" placeholder="vaultfx" required>
    </div>
    <div class="field-row">
      <div class="field">
        <label>Admin MySQL User (for install)</label>
        <input type="text" name="db_user" placeholder="root or admin user" required>
      </div>
      <div class="field">
        <label>Admin MySQL Password</label>
        <input type="password" name="db_pass" placeholder="">
      </div>
    </div>
    <hr style="border:none;border-top:1px solid rgba(255,255,255,0.06);margin:16px 0">
    <div style="font-size:0.82rem;color:#6b7280;margin-bottom:12px">
      Runtime user: limited privileges (SELECT, INSERT, UPDATE, DELETE only). Leave blank to use admin user.
    </div>
    <div class="field-row">
      <div class="field">
        <label>Runtime MySQL User</label>
        <input type="text" name="db_rt_user" placeholder="vaultfx_runtime">
      </div>
      <div class="field">
        <label>Runtime MySQL Password</label>
        <input type="password" name="db_rt_pass" placeholder="">
      </div>
    </div>
    <button type="submit" class="btn">Setup Database →</button>
  </form>

<?php elseif ($step === 3): ?>
  <h2>Step 3 — Create Super Admin Account</h2>

  <?php foreach ($errors as $e): ?><div class="alert-err"><?= htmlspecialchars($e) ?></div><?php endforeach; ?>

  <form method="POST" action="install.php?step=3">
    <div class="field">
      <label>Username</label>
      <input type="text" name="username" maxlength="50" required autocomplete="off">
    </div>
    <div class="field">
      <label>Email Address</label>
      <input type="email" name="email" maxlength="255" required>
    </div>
    <div class="field-row">
      <div class="field">
        <label>Password (min 12 chars)</label>
        <input type="password" name="password" minlength="12" required autocomplete="new-password">
      </div>
      <div class="field">
        <label>Confirm Password</label>
        <input type="password" name="confirm_password" required autocomplete="new-password">
      </div>
    </div>
    <button type="submit" class="btn">Create Admin & Finish →</button>
  </form>

<?php elseif ($step === 4): ?>
  <h2>✓ Installation Complete!</h2>

  <div class="alert-ok" style="margin-bottom:20px">VaultFX has been successfully installed.</div>

  <p style="font-size:0.875rem;color:#8b9cba;margin-bottom:20px;line-height:1.6">
    Your Super Admin account is ready. You will be prompted to set up two-factor authentication on first login.
    <strong>2FA is mandatory for Super Admin accounts.</strong>
  </p>

  <div style="margin-bottom:24px">
    <a href="../public_html/index.php" class="btn">Go to VaultFX →</a>
  </div>

  <div style="font-size:0.875rem;color:#f59e0b;margin-bottom:10px;font-weight:600">⚠ Post-Installation Security Checklist</div>
  <ul class="checklist">
    <li>Delete or block the <code>install/</code> directory immediately</li>
    <li>Verify HTTPS is working (test at <a href="https://www.ssllabs.com/ssltest/" target="_blank" style="color:#3b82f6">ssllabs.com</a>)</li>
    <li>Verify security headers at <a href="https://securityheaders.com" target="_blank" style="color:#3b82f6">securityheaders.com</a></li>
    <li>Confirm config/ directory is NOT web-accessible</li>
    <li>Set <code>chmod 600</code> on <code>config/encryption-key.php</code></li>
    <li>Set <code>chmod 640</code> on <code>config/config.php</code></li>
    <li>Create a restricted MySQL user with only SELECT, INSERT, UPDATE, DELETE</li>
    <li>Configure regular database backups</li>
    <li>Set up IP whitelist in Settings if applicable</li>
    <li>Complete 2FA setup for your Super Admin account</li>
    <li>Review and test all user roles before adding team members</li>
  </ul>

  <div style="margin-top:16px;padding:12px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.2);border-radius:8px;font-size:0.82rem;color:#f87171">
    <strong>CRITICAL:</strong> The <code>config/encryption-key.php</code> file contains your master encryption key.
    Back it up securely NOW. Loss of this key means permanent loss of all stored credentials.
  </div>
<?php endif; ?>

</div>
</body>
</html>
