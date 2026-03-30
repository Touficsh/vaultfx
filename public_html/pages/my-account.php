<?php
/**
 * VaultFX — My Account Page
 * Profile, password change, 2FA management, theme preference
 */

$pageTitle  = 'My Account';
$user       = Auth::user();
$userId     = (int)$user['id'];
$activeTab  = $_GET['tab'] ?? 'profile';
$error      = '';
$successMsg = '';

// ── Handle password change ─────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && post('action') === 'change_password') {
    CSRF::requireValid();

    $current = post('current_password');
    $new     = post('new_password');
    $confirm = post('confirm_password');

    if (!password_verify($current, DB::scalar("SELECT password_hash FROM users WHERE id = ?", [$userId]))) {
        $error = 'Current password is incorrect.';
    } elseif ($new !== $confirm) {
        $error = 'New passwords do not match.';
    } else {
        $pwErrors = Validation::checkPasswordStrength($new);
        if (!empty($pwErrors)) {
            $error = $pwErrors[0];
        } else {
            $hash = password_hash($new, PASSWORD_ARGON2ID);
            DB::execute(
                "UPDATE users SET password_hash = ?, password_changed_at = NOW(), force_password_change = 0 WHERE id = ?",
                [$hash, $userId]
            );
            Audit::log($userId, 'password_change', 'user', $userId);
            $successMsg = 'Password changed successfully.';
            // Reload user
            $user = Auth::user();
        }
    }
    $activeTab = 'security';
}

// ── Handle theme change ────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && post('action') === 'change_theme') {
    CSRF::requireValid();
    $theme = post('theme');
    if (in_array($theme, ['dark', 'light', 'system'])) {
        DB::execute("UPDATE users SET theme_preference = ? WHERE id = ?", [$theme, $userId]);
        redirect('?page=my-account&tab=profile&saved=1');
    }
}

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">My Account</h1>
    <p class="page-subtitle"><?= e($user['username']) ?> · <?= e(RBAC::roleLabel($user['role'])) ?></p>
  </div>
</div>

<?php if (!empty($_GET['saved'])): ?>
<div class="alert alert-success mb-6">Settings saved.</div>
<?php endif; ?>

<?php if (!empty($successMsg)): ?>
<div class="alert alert-success mb-6"><?= e($successMsg) ?></div>
<?php endif; ?>

<?php if (!empty($error)): ?>
<div class="alert alert-error mb-6"><?= e($error) ?></div>
<?php endif; ?>

<div data-tabs style="max-width:680px">
  <div class="tabs">
    <button class="tab-btn <?= $activeTab === 'profile' ? 'active' : '' ?>" data-tab="profile">Profile</button>
    <button class="tab-btn <?= $activeTab === 'security' ? 'active' : '' ?>" data-tab="security">Security</button>
    <button class="tab-btn <?= $activeTab === '2fa' ? 'active' : '' ?>" data-tab="2fa">Two-Factor Auth</button>
  </div>

  <!-- Profile Tab -->
  <div class="tab-panel <?= $activeTab === 'profile' ? 'active' : '' ?>" id="tab-profile">
    <div class="card">
      <div class="card-header"><span class="card-title">Profile Information</span></div>
      <div class="card-body">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
          <div style="width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,var(--accent),#7c3aed);display:flex;align-items:center;justify-content:center;font-size:1.4rem;font-weight:700;color:#fff">
            <?= e(strtoupper(substr($user['username'], 0, 2))) ?>
          </div>
          <div>
            <div style="font-size:1.1rem;font-weight:700"><?= e($user['username']) ?></div>
            <div class="text-muted text-sm"><?= e($user['email']) ?></div>
            <span class="badge <?= e(RBAC::roleBadgeClass($user['role'])) ?>" style="margin-top:4px"><?= e(RBAC::roleLabel($user['role'])) ?></span>
          </div>
        </div>

        <div class="divider"></div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:16px">
          <div>
            <div class="text-xs text-muted" style="margin-bottom:4px">Member Since</div>
            <div class="text-sm"><?= e(format_datetime($user['created_at'], 'M j, Y')) ?></div>
          </div>
          <div>
            <div class="text-xs text-muted" style="margin-bottom:4px">Last Login</div>
            <div class="text-sm"><?= e(format_datetime($user['last_login_at'])) ?></div>
          </div>
          <div>
            <div class="text-xs text-muted" style="margin-bottom:4px">Last Login IP</div>
            <div class="text-sm font-mono"><?= e($user['last_login_ip'] ?? '—') ?></div>
          </div>
          <div>
            <div class="text-xs text-muted" style="margin-bottom:4px">Password Last Changed</div>
            <div class="text-sm"><?= e(format_datetime($user['password_changed_at'])) ?></div>
          </div>
        </div>

        <div class="divider"></div>

        <form method="POST" action="?page=my-account">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="change_theme">
          <div class="form-group">
            <label class="form-label">Theme Preference</label>
            <select name="theme" class="form-control" style="max-width:200px" onchange="this.form.submit()">
              <option value="dark"   <?= $user['theme_preference'] === 'dark'   ? 'selected' : '' ?>>Dark</option>
              <option value="light"  <?= $user['theme_preference'] === 'light'  ? 'selected' : '' ?>>Light</option>
              <option value="system" <?= $user['theme_preference'] === 'system' ? 'selected' : '' ?>>System</option>
            </select>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Security Tab -->
  <div class="tab-panel <?= $activeTab === 'security' ? 'active' : '' ?>" id="tab-security">
    <div class="card">
      <div class="card-header"><span class="card-title">Change Password</span></div>
      <div class="card-body">
        <?php if ($user['force_password_change']): ?>
        <div class="alert alert-warning mb-4">
          An administrator has required you to change your password.
        </div>
        <?php endif; ?>
        <form method="POST" action="?page=my-account&tab=security" autocomplete="off">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="change_password">
          <div class="form-group mb-4">
            <label class="form-label">Current Password <span class="required">*</span></label>
            <div class="password-field">
              <input type="password" name="current_password" class="form-control" autocomplete="current-password" required maxlength="255">
              <button type="button" class="password-toggle" onclick="togglePw(this)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
              </button>
            </div>
          </div>
          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">New Password <span class="required">*</span></label>
              <div class="password-field">
                <input type="password" name="new_password" id="new-pw" class="form-control" autocomplete="new-password" required minlength="12" maxlength="255">
                <button type="button" class="password-toggle" onclick="togglePw(this)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
              </div>
              <div class="pw-strength mt-2" id="pw-strength-meter" data-strength="0">
                <div class="pw-strength-bar"></div>
                <div class="pw-strength-bar"></div>
                <div class="pw-strength-bar"></div>
                <div class="pw-strength-bar"></div>
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Confirm New Password <span class="required">*</span></label>
              <div class="password-field">
                <input type="password" name="confirm_password" class="form-control" autocomplete="new-password" required minlength="12" maxlength="255">
                <button type="button" class="password-toggle" onclick="togglePw(this)">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                </button>
              </div>
            </div>
          </div>
          <div class="form-hint mt-2">Min 12 characters with uppercase, lowercase, digit, and special character.</div>
          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Change Password</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- 2FA Tab -->
  <div class="tab-panel <?= $activeTab === '2fa' ? 'active' : '' ?>" id="tab-2fa">
    <div class="card">
      <div class="card-header">
        <span class="card-title">Two-Factor Authentication</span>
        <?php if ($user['totp_enabled']): ?>
        <span class="badge badge-active" style="margin-left:auto">Enabled</span>
        <?php else: ?>
        <span class="badge badge-inactive" style="margin-left:auto">Disabled</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <?php if ($user['totp_enabled']): ?>
        <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:20px">
          <div style="width:40px;height:40px;border-radius:10px;background:var(--success-soft);display:flex;align-items:center;justify-content:center;flex-shrink:0">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="2.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
          </div>
          <div>
            <div style="font-weight:600;margin-bottom:4px">2FA is active on your account</div>
            <div class="text-sm text-muted">Your account is protected with time-based one-time passwords (TOTP).</div>
          </div>
        </div>
        <p class="text-sm text-muted mb-4">
          To reconfigure 2FA (e.g. if you got a new phone), you can reset it here.
          You will need to re-scan the QR code after resetting.
        </p>
        <a href="?page=2fa-setup&step=1" class="btn btn-outline">Reconfigure 2FA</a>
        <?php else: ?>
        <?php if (in_array($user['role'], ['super_admin', 'admin'])): ?>
        <div class="alert alert-warning mb-4">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          2FA is <strong>mandatory</strong> for your role. Please set it up now.
        </div>
        <?php endif; ?>
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          Two-factor authentication adds a second layer of security by requiring a 6-digit code
          from your authenticator app in addition to your password.
        </p>
        <a href="?page=2fa-setup&step=1" class="btn btn-primary">Set Up 2FA</a>
        <?php endif; ?>
      </div>
    </div>
  </div>

</div><!-- /.tabs wrapper -->

<?php
$inlineJs = <<<'JS'
function togglePw(btn) {
  const input = btn.previousElementSibling;
  if (input) input.type = input.type === 'password' ? 'text' : 'password';
}

// Password strength meter
initPasswordStrength('new-pw', 'pw-strength-meter');
JS;
include WEB_ROOT . '/includes/footer.php';
?>
