<?php
/**
 * VaultFX — 2FA Verification Page
 * Step 2 of login: TOTP or backup code
 */

if (!Session::is2FAPending()) {
    redirect('?page=dashboard');
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::validate()) {
        $error = 'Security token expired. Please try again.';
    } else {
        $code = post('totp_code');
        if (empty($code)) {
            $error = 'Please enter your verification code.';
        } elseif (!Auth::verify2FA($code)) {
            $error = 'Invalid verification code. Please try again.';
        } else {
            redirect('?page=dashboard');
        }
    }
}

$csrfToken = CSRF::token();
no_cache_headers();
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="<?= e($csrfToken) ?>">
  <meta name="robots" content="noindex, nofollow">
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
  <title>Two-Factor Authentication — <?= e(setting('app_name', 'VaultFX')) ?></title>
  <link rel="stylesheet" href="assets/css/login.css">
</head>
<body>

<div class="login-wrapper">
  <div class="login-card">

    <div class="login-logo">
      <div class="login-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
      </div>
      <div class="login-app-name"><span class="vault">Vault</span><span class="fx">FX</span></div>
    </div>

    <?php if ($error): ?>
    <div class="login-error">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <?= e($error) ?>
    </div>
    <?php endif; ?>

    <div class="login-step-title">Two-Factor Authentication</div>
    <div class="login-step-desc">Enter the 6-digit code from your authenticator app, or use a backup code.</div>

    <form method="POST" action="?page=2fa-verify" id="totp-form" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">

      <!-- TOTP digit inputs -->
      <div class="totp-input-group" id="totp-digits">
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="0">
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="1">
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="2">
        <span class="totp-separator">—</span>
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="3">
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="4">
        <input type="text" class="totp-digit" maxlength="1" inputmode="numeric" pattern="[0-9]" data-idx="5">
      </div>

      <input type="hidden" name="totp_code" id="totp-hidden">

      <button type="submit" class="login-btn" id="totp-submit" disabled>
        Verify Code
      </button>
    </form>

    <!-- Backup code option -->
    <span class="backup-code-link" onclick="toggleBackupInput()">
      Use a backup code instead
    </span>

    <div class="backup-code-input-wrap" id="backup-wrap">
      <form method="POST" action="?page=2fa-verify" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">
        <div class="login-form-group">
          <label class="login-label" for="backup-code">8-character backup code</label>
          <input
            type="text"
            id="backup-code"
            name="totp_code"
            class="login-input"
            maxlength="8"
            style="font-family:monospace;letter-spacing:0.15em;text-transform:uppercase"
            placeholder="XXXXXXXX"
            autocomplete="off"
            spellcheck="false">
        </div>
        <button type="submit" class="login-btn" style="margin-top:0">Use Backup Code</button>
      </form>
    </div>

    <div style="margin-top:20px;padding-top:14px;border-top:1px solid rgba(255,255,255,0.06);text-align:center">
      <a href="?page=logout" style="font-size:0.8rem;color:#4b5a73">Cancel and log out</a>
    </div>

  </div>
</div>

<script>
const digits = document.querySelectorAll('.totp-digit');
const hidden = document.getElementById('totp-hidden');
const submit = document.getElementById('totp-submit');

function updateHidden() {
  const code = Array.from(digits).map(d => d.value).join('');
  hidden.value = code;
  submit.disabled = code.length !== 6;
}

digits.forEach((digit, idx) => {
  digit.addEventListener('input', (e) => {
    // Only allow digits
    digit.value = digit.value.replace(/[^0-9]/g, '').slice(-1);

    if (digit.value && idx < 5) {
      digits[idx + 1].focus();
    }
    updateHidden();
  });

  digit.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && !digit.value && idx > 0) {
      digits[idx - 1].focus();
      digits[idx - 1].value = '';
      updateHidden();
    }
    if (e.key === 'ArrowLeft' && idx > 0) digits[idx - 1].focus();
    if (e.key === 'ArrowRight' && idx < 5) digits[idx + 1].focus();
  });

  // Handle paste (e.g. from password manager)
  digit.addEventListener('paste', (e) => {
    e.preventDefault();
    const pasted = (e.clipboardData || window.clipboardData).getData('text').replace(/\D/g, '').slice(0, 6);
    pasted.split('').forEach((char, i) => {
      if (digits[i]) digits[i].value = char;
    });
    updateHidden();
    const next = Math.min(pasted.length, 5);
    digits[next].focus();
  });
});

// Auto-focus first digit
digits[0].focus();

function toggleBackupInput() {
  const wrap = document.getElementById('backup-wrap');
  wrap.classList.toggle('visible');
  if (wrap.classList.contains('visible')) {
    document.getElementById('backup-code').focus();
  }
}

// Backup code: uppercase transform
document.getElementById('backup-code')?.addEventListener('input', function() {
  this.value = this.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
});
</script>
</body>
</html>
