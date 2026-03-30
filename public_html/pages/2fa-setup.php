<?php
/**
 * VaultFX — 2FA Setup / Enrollment Page
 * Generates TOTP secret, shows QR code, verifies a code, saves.
 */

$pageTitle = '2FA Setup';
$user      = Auth::user();
$userId    = (int)$user['id'];
$totp      = new GoogleAuthenticator();

$step   = (int)($_GET['step'] ?? 1);
$error  = '';
$secret = '';

// Step 1: generate a fresh secret and show QR
if ($step === 1) {
    // Only generate a new secret if one isn't already pending
    if (empty($_SESSION['totp_pending_secret'])) {
        $_SESSION['totp_pending_secret'] = $totp->createSecret(32);
    }
    $secret = $_SESSION['totp_pending_secret'];
    $otpUrl = $totp->getQRCodeUrl($secret, $user['email'], setting('app_name', 'VaultFX'));
}

// Step 2: verify code + save
if ($step === 2 && $_SERVER['REQUEST_METHOD'] === 'POST') {
    CSRF::requireValid();

    $code   = trim(post('code'));
    $secret = $_SESSION['totp_pending_secret'] ?? '';

    if (empty($secret)) {
        $error = 'Session expired. Please restart 2FA setup.';
        $step  = 1;
    } elseif (!$totp->verifyCode($secret, $code, 2)) {
        $error = 'Invalid code. Please try again with the current code from your authenticator app.';
        // Show QR again with same secret
        $otpUrl = $totp->getQRCodeUrl($secret, $user['email'], setting('app_name', 'VaultFX'));
    } else {
        // Generate backup codes
        $backupCodes = $totp->generateBackupCodes(); // 8 plain codes
        $hashedCodes = array_map(fn($c) => password_hash($c, PASSWORD_BCRYPT, ['cost' => 10]), $backupCodes);

        // Encrypt TOTP secret
        $encryptedSecret = Encryption::encryptTotpSecret($secret, $userId);

        DB::execute(
            "UPDATE users SET totp_secret_encrypted = ?, totp_enabled = 1, backup_codes_hash = ? WHERE id = ?",
            [$encryptedSecret, json_encode($hashedCodes), $userId]
        );

        Audit::log($userId, '2fa_setup', 'user', $userId);

        unset($_SESSION['totp_pending_secret']);
        Session::complete2FA();

        // Store backup codes briefly for display
        $_SESSION['backup_codes_display'] = $backupCodes;

        $step = 3; // Show backup codes
    }
}

// Step 3: show backup codes (then clear from session)
$backupCodesDisplay = [];
if ($step === 3 && isset($_SESSION['backup_codes_display'])) {
    $backupCodesDisplay = $_SESSION['backup_codes_display'];
    unset($_SESSION['backup_codes_display']);
}

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">Two-Factor Authentication Setup</h1>
    <p class="page-subtitle">
      <?php if ($step === 1): ?>Scan the QR code with your authenticator app<?php
      elseif ($step === 2): ?>Verify your authenticator is working<?php
      else: ?>Save your backup codes<?php endif; ?>
    </p>
  </div>
</div>

<div style="max-width:560px">

<?php if ($step === 1 || ($step === 2 && !empty($error) && !empty($secret))): ?>
<!-- Step 1 & 2 (with error): Show QR code -->

<?php if (!empty($error)): ?>
<div class="alert alert-error mb-6"><?= e($error) ?></div>
<?php endif; ?>

<div class="card mb-6">
  <div class="card-header">
    <span class="card-title">Step 1 — Scan QR Code</span>
  </div>
  <div class="card-body" style="text-align:center">
    <p class="text-sm text-muted mb-4" style="text-align:left">
      Open <strong>Google Authenticator</strong>, <strong>Authy</strong>, or any TOTP-compatible app and scan the QR code below.
    </p>

    <!-- QR code rendered client-side via qrcode.js (secret never sent to third party) -->
    <div id="qr-container" style="display:inline-block;padding:16px;background:#fff;border-radius:12px;margin-bottom:16px">
      <canvas id="qr-canvas"></canvas>
    </div>

    <p class="text-sm text-muted mb-2">Can't scan? Enter this secret manually:</p>
    <div style="font-family:monospace;font-size:1rem;background:var(--bg-raised);border:1px solid var(--border);border-radius:8px;padding:10px 14px;letter-spacing:0.2em;word-break:break-all;margin-bottom:8px">
      <?= e($secret ?? $_SESSION['totp_pending_secret'] ?? '') ?>
    </div>
    <p class="text-xs text-muted">Algorithm: SHA1 · Digits: 6 · Period: 30s</p>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <span class="card-title">Step 2 — Verify</span>
  </div>
  <div class="card-body">
    <p class="text-sm text-muted mb-4">Enter the 6-digit code from your authenticator app to confirm setup:</p>
    <form method="POST" action="?page=2fa-setup&step=2" autocomplete="off">
      <?= CSRF::field() ?>
      <div style="display:flex;gap:10px;align-items:flex-end">
        <div class="form-group" style="flex:1">
          <label class="form-label">Verification Code</label>
          <input type="text" name="code" class="form-control font-mono" maxlength="6" inputmode="numeric"
            pattern="[0-9]{6}" placeholder="000000" autocomplete="one-time-code" required autofocus
            style="font-size:1.2rem;letter-spacing:0.2em;text-align:center">
        </div>
        <button type="submit" class="btn btn-primary" style="height:40px">Verify & Enable</button>
      </div>
    </form>
  </div>
</div>

<?php elseif ($step === 3): ?>
<!-- Step 3: Backup codes -->
<div class="alert alert-success mb-6">
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0;margin-top:2px"><polyline points="20 6 9 17 4 12"></polyline></svg>
  Two-factor authentication is now enabled on your account.
</div>

<div class="card">
  <div class="card-header">
    <span class="card-title">Backup Codes</span>
    <span class="badge badge-warning" style="margin-left:auto">Save these now</span>
  </div>
  <div class="card-body">
    <p class="text-sm text-muted mb-4" style="line-height:1.6">
      These 8 one-time backup codes can be used to sign in if you lose access to your authenticator app.
      <strong style="color:var(--danger)">Save them somewhere secure — they will only be shown once.</strong>
    </p>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px">
      <?php foreach ($backupCodesDisplay as $code): ?>
      <div style="font-family:monospace;font-size:1rem;background:var(--bg-raised);border:1px solid var(--border);border-radius:8px;padding:10px 14px;text-align:center;letter-spacing:0.1em">
        <?= e($code) ?>
      </div>
      <?php endforeach; ?>
    </div>

    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn btn-outline" onclick="printCodes()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
        Print
      </button>
      <button class="btn btn-outline" onclick="copyCodes()">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        Copy All
      </button>
      <a href="?page=dashboard" class="btn btn-primary" style="margin-left:auto">
        I've saved them — Go to Dashboard
      </a>
    </div>
  </div>
</div>

<script>
const codes = <?= json_encode($backupCodesDisplay) ?>;

function printCodes() {
  const w = window.open('', '_blank');
  w.document.write('<pre style="font-family:monospace;font-size:14px;line-height:2">' +
    'VaultFX — 2FA Backup Codes\n' +
    'Generated: ' + new Date().toISOString() + '\n\n' +
    codes.join('\n') + '\n\nKEEP THESE SAFE — ONE USE EACH</pre>');
  w.document.close();
  w.print();
}

async function copyCodes() {
  await navigator.clipboard.writeText(codes.join('\n'));
  VaultFX.toast('success', 'Backup codes copied to clipboard.');
}
</script>

<?php endif; ?>

</div>

<?php if ($step === 1 || ($step === 2 && !empty($error))): ?>
<!-- Load qrcode.js for client-side QR rendering -->
<script src="assets/js/qrcode.min.js"></script>
<script>
const OTP_URL = <?= json_encode($otpUrl ?? '') ?>;
if (OTP_URL && window.QRCode) {
  QRCode.toCanvas(document.getElementById('qr-canvas'), OTP_URL, { width: 200, margin: 1 }, (err) => {
    if (err) console.error('QR error:', err);
  });
}
// Auto-focus code input when present
document.querySelector('input[name="code"]')?.focus();
</script>
<?php endif; ?>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
