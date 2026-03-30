<?php
/**
 * VaultFX — Login Page
 * Step 1: Username + Password
 * Step 2: 2FA code (shown after successful password verification)
 */

// If already fully authenticated, go to dashboard
if (Session::validate() && !Session::is2FAPending()) {
    redirect('?page=dashboard');
}

// If 2FA is pending, show the 2FA step
if (Session::is2FAPending()) {
    redirect('?page=2fa-verify');
}

// ── Handle POST ────────────────────────────────────────────────
$error      = '';
$lockExpiry = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['username'])) {
    if (!CSRF::validate()) {
        $error = 'Security token expired. Please try again.';
    } else {
        $username = post('username');
        $password = post('password');

        if (empty($username) || empty($password)) {
            $error = 'Please enter your username and password.';
        } else {
            $result = Auth::attempt($username, $password);

            if ($result['success']) {
                if ($result['needs2FA']) {
                    redirect('?page=2fa-verify');
                } else {
                    redirect('?page=dashboard');
                }
            } else {
                $error      = $result['error'];
                $lockExpiry = $result['lockExpiry'];
            }
        }
    }
}

$csrfToken = CSRF::token();
$flash     = get_flash();
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
  <title>Login — <?= e(setting('app_name', 'VaultFX')) ?></title>
  <link rel="stylesheet" href="assets/css/login.css">
</head>
<body>

<div class="login-wrapper">
  <div class="login-card">

    <!-- Logo -->
    <div class="login-logo">
      <div class="login-logo-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
      </div>
      <div class="login-app-name"><span class="vault">Vault</span><span class="fx">FX</span></div>
      <div class="login-subtitle">Credential Management System</div>
    </div>

    <?php if ($flash): ?>
    <div class="login-error" style="<?= $flash['type'] === 'success' ? 'background:rgba(16,185,129,0.1);border-color:rgba(16,185,129,0.2);color:#34d399' : '' ?>">
      <?= e($flash['message']) ?>
    </div>
    <?php endif; ?>

    <?php if ($lockExpiry): ?>
    <div class="login-lockout">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
        <line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>
      </svg>
      <div>
        <div style="font-weight:600">Account Locked</div>
        <div><?= e($error) ?></div>
      </div>
    </div>
    <?php elseif ($error): ?>
    <div class="login-error">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:1px">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <?= e($error) ?>
    </div>
    <?php endif; ?>

    <div class="login-step-title">Sign in to VaultFX</div>
    <div class="login-step-desc">Enter your credentials to access the vault</div>

    <form method="POST" action="?page=login" id="login-form" autocomplete="off" novalidate>
      <input type="hidden" name="csrf_token" value="<?= e($csrfToken) ?>">

      <div class="login-form-group">
        <label class="login-label" for="username">Username</label>
        <input
          type="text"
          id="username"
          name="username"
          class="login-input"
          autocomplete="username"
          autocapitalize="none"
          spellcheck="false"
          maxlength="50"
          required
          value="<?= e(post('username')) ?>">
      </div>

      <div class="login-form-group">
        <label class="login-label" for="password">Password</label>
        <div class="password-wrap">
          <input
            type="password"
            id="password"
            name="password"
            class="login-input"
            autocomplete="current-password"
            maxlength="255"
            required>
          <button type="button" class="pw-toggle" onclick="togglePassword('password')" tabindex="-1" aria-label="Toggle password visibility">
            <svg id="pw-eye-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
          </button>
        </div>
      </div>

      <button type="submit" class="login-btn" id="login-submit">
        <span>Sign In</span>
      </button>
    </form>

    <div class="security-badge">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
      </svg>
      AES-256-GCM Encrypted · TLS Secured
    </div>

  </div>
</div>

<script>
function togglePassword(fieldId) {
  const input = document.getElementById(fieldId);
  const icon  = document.getElementById('pw-eye-icon');
  if (!input) return;
  if (input.type === 'password') {
    input.type = 'text';
    icon.innerHTML = `
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
      <line x1="1" y1="1" x2="23" y2="23"></line>
    `;
  } else {
    input.type = 'password';
    icon.innerHTML = `
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
      <circle cx="12" cy="12" r="3"></circle>
    `;
  }
}

// Show loading state on submit
document.getElementById('login-form').addEventListener('submit', function() {
  const btn = document.getElementById('login-submit');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div><span>Signing in…</span>';
  setTimeout(() => { btn.disabled = false; btn.innerHTML = '<span>Sign In</span>'; }, 8000);
});
</script>
</body>
</html>
