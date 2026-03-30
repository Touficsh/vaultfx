<?php
/**
 * VaultFX — System Settings Page
 * Super Admin only — manage app-wide configuration.
 */

$pageTitle = 'Settings';
RBAC::assertRole(RBAC::SUPER_ADMIN);

$activeTab  = $_GET['tab'] ?? 'general';
$error      = '';
$successMsg = '';

// ── Helper: save a batch of settings ──────────────────────────
function saveSetting(string $key, ?string $value, int $userId): void
{
    DB::execute(
        "INSERT INTO settings (setting_key, setting_value, updated_by)
         VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_by = VALUES(updated_by)",
        [$key, $value, $userId]
    );
}

// ── Load current settings ──────────────────────────────────────
$settings = [];
$rows = DB::rows("SELECT setting_key, setting_value FROM settings");
foreach ($rows as $r) {
    $settings[$r['setting_key']] = $r['setting_value'];
}

function cfg(string $key, mixed $default = ''): mixed {
    global $settings;
    return $settings[$key] ?? $default;
}

// ── Handle POST ────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CSRF::requireValid();
    $postAction = post('action');
    $userId     = (int)Auth::userField('id');

    if ($postAction === 'save_general') {
        $appName        = trim(post('app_name'));
        $sessionTimeout = (int)post('session_timeout_minutes');
        $absoluteMax    = (int)post('absolute_timeout_hours');

        if (empty($appName) || strlen($appName) > 60) {
            $error = 'App name must be 1–60 characters.';
        } elseif ($sessionTimeout < 5 || $sessionTimeout > 480) {
            $error = 'Session timeout must be between 5 and 480 minutes.';
        } elseif ($absoluteMax < 1 || $absoluteMax > 72) {
            $error = 'Absolute max session must be between 1 and 72 hours.';
        } else {
            saveSetting('app_name', $appName, $userId);
            saveSetting('session_timeout_minutes', (string)$sessionTimeout, $userId);
            saveSetting('absolute_timeout_hours', (string)$absoluteMax, $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'general']);
            $successMsg = 'General settings saved.';
            // Refresh
            $settings['app_name'] = $appName;
            $settings['session_timeout_minutes'] = (string)$sessionTimeout;
            $settings['absolute_timeout_hours'] = (string)$absoluteMax;
        }
        $activeTab = 'general';
    }

    elseif ($postAction === 'save_security') {
        $require2faAdmin  = post('require_2fa_admin')       === '1' ? '1' : '0';
        $require2faSA     = post('require_2fa_super_admin') === '1' ? '1' : '0';
        $revealTimeout    = (int)post('password_reveal_timeout_seconds');
        $bulkThreshold    = (int)post('bulk_reveal_threshold');
        $bulkWindow       = (int)post('bulk_reveal_window_seconds');
        $lockoutFails     = (int)post('max_failed_logins_lockout');
        $lockoutMins      = (int)post('lockout_duration_minutes');
        $extThreshold     = (int)post('extended_lockout_threshold');
        $extMins          = (int)post('extended_lockout_minutes');
        $hardThreshold    = (int)post('hard_lockout_threshold');
        $hardHours        = (int)post('hard_lockout_hours');

        if ($revealTimeout < 10 || $revealTimeout > 300) {
            $error = 'Reveal timeout must be between 10 and 300 seconds.';
        } elseif ($bulkThreshold < 1 || $bulkThreshold > 50) {
            $error = 'Bulk reveal threshold must be 1–50.';
        } elseif ($bulkWindow < 30 || $bulkWindow > 3600) {
            $error = 'Bulk reveal window must be 30–3600 seconds.';
        } elseif ($lockoutFails < 3 || $lockoutFails > 20) {
            $error = 'Failed logins threshold must be 3–20.';
        } else {
            saveSetting('require_2fa_admin',              $require2faAdmin, $userId);
            saveSetting('require_2fa_super_admin',        $require2faSA,    $userId);
            saveSetting('password_reveal_timeout_seconds', (string)$revealTimeout, $userId);
            saveSetting('bulk_reveal_threshold',          (string)$bulkThreshold,  $userId);
            saveSetting('bulk_reveal_window_seconds',     (string)$bulkWindow,     $userId);
            saveSetting('max_failed_logins_lockout',      (string)$lockoutFails,   $userId);
            saveSetting('lockout_duration_minutes',       (string)$lockoutMins,    $userId);
            saveSetting('extended_lockout_threshold',     (string)$extThreshold,   $userId);
            saveSetting('extended_lockout_minutes',       (string)$extMins,        $userId);
            saveSetting('hard_lockout_threshold',         (string)$hardThreshold,  $userId);
            saveSetting('hard_lockout_hours',             (string)$hardHours,      $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'security'], 'warning');
            $successMsg = 'Security settings saved.';
            // Refresh local cache
            foreach ([
                'require_2fa_admin' => $require2faAdmin,
                'require_2fa_super_admin' => $require2faSA,
                'password_reveal_timeout_seconds' => $revealTimeout,
                'bulk_reveal_threshold' => $bulkThreshold,
                'bulk_reveal_window_seconds' => $bulkWindow,
                'max_failed_logins_lockout' => $lockoutFails,
                'lockout_duration_minutes' => $lockoutMins,
                'extended_lockout_threshold' => $extThreshold,
                'extended_lockout_minutes' => $extMins,
                'hard_lockout_threshold' => $hardThreshold,
                'hard_lockout_hours' => $hardHours,
            ] as $k => $v) {
                $settings[$k] = (string)$v;
            }
        }
        $activeTab = 'security';
    }

    elseif ($postAction === 'save_ip_whitelist') {
        $enabled   = post('ip_whitelist_enabled') === '1' ? '1' : '0';
        $rawList   = post('ip_whitelist_raw');
        $ipLines   = array_filter(array_map('trim', explode("\n", $rawList)));
        $ipErrors  = [];

        foreach ($ipLines as $entry) {
            if (!filter_var(explode('/', $entry)[0], FILTER_VALIDATE_IP)) {
                $ipErrors[] = $entry;
            }
        }

        if (!empty($ipErrors)) {
            $error = 'Invalid IP entries: ' . implode(', ', array_map('htmlspecialchars', $ipErrors));
        } else {
            saveSetting('ip_whitelist_enabled', $enabled, $userId);
            saveSetting('ip_whitelist', json_encode(array_values($ipLines)), $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'ip_whitelist', 'enabled' => $enabled], 'warning');
            $successMsg = 'IP whitelist saved.';
            $settings['ip_whitelist_enabled'] = $enabled;
            $settings['ip_whitelist'] = json_encode(array_values($ipLines));
        }
        $activeTab = 'ip-whitelist';
    }

    elseif ($postAction === 'save_maintenance') {
        $maintMode    = post('maintenance_mode') === '1' ? '1' : '0';
        $rawAllowed   = post('maintenance_allowed_ips_raw');
        $allowedLines = array_filter(array_map('trim', explode("\n", $rawAllowed)));
        $ipErrors     = [];

        foreach ($allowedLines as $entry) {
            if (!filter_var(explode('/', $entry)[0], FILTER_VALIDATE_IP)) {
                $ipErrors[] = $entry;
            }
        }

        if (!empty($ipErrors)) {
            $error = 'Invalid IP entries: ' . implode(', ', array_map('htmlspecialchars', $ipErrors));
        } else {
            saveSetting('maintenance_mode', $maintMode, $userId);
            saveSetting('maintenance_allowed_ips', json_encode(array_values($allowedLines)), $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'maintenance', 'mode' => $maintMode], 'warning');
            $successMsg = 'Maintenance settings saved.';
            $settings['maintenance_mode'] = $maintMode;
            $settings['maintenance_allowed_ips'] = json_encode(array_values($allowedLines));
        }
        $activeTab = 'maintenance';
    }

    elseif ($postAction === 'save_after_hours') {
        $enabled = post('after_hours_flag_enabled') === '1' ? '1' : '0';
        $start   = post('after_hours_start');
        $end     = post('after_hours_end');

        if (!preg_match('/^\d{2}:\d{2}$/', $start) || !preg_match('/^\d{2}:\d{2}$/', $end)) {
            $error = 'Invalid time format. Use HH:MM.';
        } else {
            saveSetting('after_hours_flag_enabled', $enabled, $userId);
            saveSetting('after_hours_start', $start, $userId);
            saveSetting('after_hours_end', $end, $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'after_hours']);
            $successMsg = 'After-hours settings saved.';
            $settings['after_hours_flag_enabled'] = $enabled;
            $settings['after_hours_start'] = $start;
            $settings['after_hours_end'] = $end;
        }
        $activeTab = 'after-hours';
    }

    elseif ($postAction === 'save_appearance') {
        $accentRaw = trim(post('theme_accent_color'));
        if (!preg_match('/^#[0-9a-fA-F]{6}$/', $accentRaw)) {
            $error = 'Invalid colour — please pick a valid hex colour (e.g. #3b82f6).';
        } else {
            saveSetting('theme_accent_color', $accentRaw, $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'appearance', 'accent' => $accentRaw]);
            $successMsg = 'Appearance settings saved.';
            $settings['theme_accent_color'] = $accentRaw;
        }
        $activeTab = 'appearance';
    }

    elseif ($postAction === 'save_alerts') {
        $alertEnabled = post('alert_email_enabled') === '1' ? '1' : '0';
        $alertTo      = trim(post('alert_email_to'));
        $alertFrom    = trim(post('alert_email_from'));

        $v = new Validation();
        if ($alertEnabled === '1') {
            $v->required('alert_email_to', $alertTo, 'Alert recipient email')
              ->email('alert_email_to', $alertTo, 'Alert recipient email')
              ->required('alert_email_from', $alertFrom, 'Alert sender email')
              ->email('alert_email_from', $alertFrom, 'Alert sender email');
        }

        if ($v->fails()) {
            $error = array_values($v->errors())[0];
        } else {
            saveSetting('alert_email_enabled', $alertEnabled, $userId);
            saveSetting('alert_email_to',      $alertTo,      $userId);
            saveSetting('alert_email_from',    $alertFrom,    $userId);
            Audit::log($userId, 'settings_change', 'system', null, ['section' => 'alerts']);
            $successMsg = 'Alert settings saved.';
            $settings['alert_email_enabled'] = $alertEnabled;
            $settings['alert_email_to']      = $alertTo;
            $settings['alert_email_from']    = $alertFrom;
        }
        $activeTab = 'alerts';
    }
}

// Build IP whitelist textarea value
$ipWhitelistRaw = implode("\n", json_decode(cfg('ip_whitelist', '[]'), true) ?: []);
$maintAllowedRaw = implode("\n", json_decode(cfg('maintenance_allowed_ips', '[]'), true) ?: []);

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">System Settings</h1>
    <p class="page-subtitle">Super admin configuration</p>
  </div>
</div>

<?php if (!empty($successMsg)): ?>
<div class="alert alert-success mb-6"><?= e($successMsg) ?></div>
<?php endif; ?>

<?php if (!empty($error)): ?>
<div class="alert alert-error mb-6"><?= e($error) ?></div>
<?php endif; ?>

<div data-tabs style="max-width:760px">
  <div class="tabs">
    <button class="tab-btn <?= $activeTab === 'general'     ? 'active' : '' ?>" data-tab="general">General</button>
    <button class="tab-btn <?= $activeTab === 'appearance'  ? 'active' : '' ?>" data-tab="appearance">Appearance</button>
    <button class="tab-btn <?= $activeTab === 'security'    ? 'active' : '' ?>" data-tab="security">Security</button>
    <button class="tab-btn <?= $activeTab === 'ip-whitelist'? 'active' : '' ?>" data-tab="ip-whitelist">IP Whitelist</button>
    <button class="tab-btn <?= $activeTab === 'maintenance' ? 'active' : '' ?>" data-tab="maintenance">Maintenance</button>
    <button class="tab-btn <?= $activeTab === 'after-hours' ? 'active' : '' ?>" data-tab="after-hours">After Hours</button>
    <button class="tab-btn <?= $activeTab === 'alerts'      ? 'active' : '' ?>" data-tab="alerts">Alerts</button>
    <button class="tab-btn <?= $activeTab === 'tools'       ? 'active' : '' ?>" data-tab="tools">Tools</button>
  </div>

  <!-- General Tab -->
  <div class="tab-panel <?= $activeTab === 'general' ? 'active' : '' ?>" id="tab-general">
    <div class="card">
      <div class="card-header"><span class="card-title">General Settings</span></div>
      <div class="card-body">
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_general">

          <div class="form-group mb-4">
            <label class="form-label">Application Name <span class="required">*</span></label>
            <input type="text" name="app_name" class="form-control" style="max-width:320px"
              value="<?= e(cfg('app_name', 'VaultFX')) ?>" maxlength="60" required>
            <div class="form-hint">Displayed in the header and 2FA QR code issuer.</div>
          </div>

          <div class="divider"></div>
          <div style="font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:12px">Session Timeouts</div>

          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Idle Timeout (minutes) <span class="required">*</span></label>
              <input type="number" name="session_timeout_minutes" class="form-control"
                value="<?= e(cfg('session_timeout_minutes', '30')) ?>" min="5" max="480" required>
              <div class="form-hint">Time before an inactive session is terminated. Default: 30.</div>
            </div>
            <div class="form-group">
              <label class="form-label">Absolute Max Session (hours) <span class="required">*</span></label>
              <input type="number" name="absolute_timeout_hours" class="form-control"
                value="<?= e(cfg('absolute_timeout_hours', '8')) ?>" min="1" max="72" required>
              <div class="form-hint">Hard limit regardless of activity. Default: 8.</div>
            </div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save General Settings</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Appearance Tab -->
  <div class="tab-panel <?= $activeTab === 'appearance' ? 'active' : '' ?>" id="tab-appearance">
    <div class="card">
      <div class="card-header"><span class="card-title">Appearance</span></div>
      <div class="card-body">
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_appearance">

          <div class="form-group mb-6">
            <label class="form-label">Theme Accent Colour</label>
            <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-top:4px">
              <input type="color" name="theme_accent_color" id="accentColorPicker"
                value="<?= e(cfg('theme_accent_color', '#3b82f6')) ?>"
                style="width:48px;height:48px;border:2px solid var(--border-strong);border-radius:10px;
                       background:transparent;cursor:pointer;padding:2px;">
              <input type="text" id="accentColorHex" class="form-control font-mono"
                style="max-width:120px"
                value="<?= e(cfg('theme_accent_color', '#3b82f6')) ?>"
                maxlength="7" placeholder="#3b82f6"
                oninput="syncColorPicker(this.value)">
              <div style="display:flex;gap:8px;flex-wrap:wrap" id="accentPresets">
                <?php
                $presets = [
                    ['#3b82f6','Blue (default)'],['#8b5cf6','Violet'],['#ec4899','Pink'],
                    ['#10b981','Emerald'],['#f59e0b','Amber'],['#ef4444','Red'],
                    ['#06b6d4','Cyan'],['#f97316','Orange'],['#64748b','Slate'],
                ];
                foreach ($presets as [$hex, $label]):
                ?>
                <button type="button" onclick="applyPreset('<?= e($hex) ?>')"
                  title="<?= e($label) ?>"
                  style="width:28px;height:28px;border-radius:50%;background:<?= e($hex) ?>;
                         border:2px solid transparent;cursor:pointer;transition:transform 0.15s,border-color 0.15s"
                  onmouseover="this.style.transform='scale(1.2)'" onmouseout="this.style.transform='scale(1)'">
                </button>
                <?php endforeach; ?>
              </div>
            </div>
            <div class="form-hint" style="margin-top:8px">
              Controls buttons, links, active states and the sidebar logo.
              Changes apply site-wide on next page load.
            </div>
          </div>

          <!-- Live preview strip -->
          <div style="border:1px solid var(--border);border-radius:var(--radius);padding:16px;background:var(--bg-raised);margin-bottom:20px">
            <div style="font-size:0.78rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:10px">Preview</div>
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
              <button type="button" id="previewBtn"
                style="padding:8px 18px;border-radius:6px;border:none;cursor:pointer;
                       background:#3b82f6;color:#fff;font-size:0.88rem;font-weight:600">
                Primary Button
              </button>
              <span id="previewLink" style="color:#3b82f6;font-size:0.88rem;cursor:pointer">Link text</span>
              <div id="previewBadge"
                style="padding:3px 10px;border-radius:20px;font-size:0.78rem;font-weight:600;
                       background:rgba(59,130,246,0.12);color:#3b82f6">
                Badge
              </div>
              <div id="previewLogo"
                style="width:32px;height:32px;border-radius:7px;
                       background:linear-gradient(135deg,#3b82f6,#1d4ed8);
                       display:flex;align-items:center;justify-content:center">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
                  <rect x="3" y="11" width="18" height="11" rx="2"></rect>
                  <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                </svg>
              </div>
            </div>
          </div>

          <button type="submit" class="btn btn-primary">Save Appearance</button>
        </form>
      </div>
    </div>
  </div>

  <!-- Security Tab -->
  <div class="tab-panel <?= $activeTab === 'security' ? 'active' : '' ?>" id="tab-security">

    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Two-Factor Authentication</span></div>
      <div class="card-body">
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_security">

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('require_2fa_admin', '1') === '1' ? 'on' : '' ?>" id="toggle-2fa-admin"
                onclick="this.classList.toggle('on');document.getElementById('require_2fa_admin').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Require 2FA for Admins</span>
            </label>
            <input type="hidden" name="require_2fa_admin" id="require_2fa_admin"
              value="<?= e(cfg('require_2fa_admin', '1')) ?>">
            <div class="form-hint" style="margin-top:4px">Admins must complete 2FA setup before accessing the system.</div>
          </div>

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('require_2fa_super_admin', '1') === '1' ? 'on' : '' ?>" id="toggle-2fa-sa"
                onclick="this.classList.toggle('on');document.getElementById('require_2fa_super_admin').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Require 2FA for Super Admins</span>
            </label>
            <input type="hidden" name="require_2fa_super_admin" id="require_2fa_super_admin"
              value="<?= e(cfg('require_2fa_super_admin', '1')) ?>">
          </div>

          <div class="divider"></div>
          <div style="font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:12px">Password Reveal</div>

          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Reveal Timeout (seconds)</label>
              <input type="number" name="password_reveal_timeout_seconds" class="form-control"
                value="<?= e(cfg('password_reveal_timeout_seconds', '30')) ?>" min="10" max="300" required>
              <div class="form-hint">How long a revealed password stays visible. Default: 30.</div>
            </div>
            <div class="form-group">
              <label class="form-label">Bulk Reveal Threshold</label>
              <input type="number" name="bulk_reveal_threshold" class="form-control"
                value="<?= e(cfg('bulk_reveal_threshold', '3')) ?>" min="1" max="50" required>
              <div class="form-hint">Reveals within the window that triggers an alert.</div>
            </div>
            <div class="form-group">
              <label class="form-label">Bulk Reveal Window (seconds)</label>
              <input type="number" name="bulk_reveal_window_seconds" class="form-control"
                value="<?= e(cfg('bulk_reveal_window_seconds', '300')) ?>" min="30" max="3600" required>
              <div class="form-hint">Time window for bulk reveal detection. Default: 300 (5 min).</div>
            </div>
          </div>

          <div class="divider"></div>
          <div style="font-size:0.85rem;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;color:var(--text-muted);margin-bottom:12px">Rate Limiting</div>

          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Tier 1 — Failed Login Threshold</label>
              <input type="number" name="max_failed_logins_lockout" class="form-control"
                value="<?= e(cfg('max_failed_logins_lockout', '5')) ?>" min="3" max="20" required>
            </div>
            <div class="form-group">
              <label class="form-label">Tier 1 — Lockout (minutes)</label>
              <input type="number" name="lockout_duration_minutes" class="form-control"
                value="<?= e(cfg('lockout_duration_minutes', '15')) ?>" min="1" max="60" required>
            </div>
            <div class="form-group">
              <label class="form-label">Tier 2 — Extended Threshold</label>
              <input type="number" name="extended_lockout_threshold" class="form-control"
                value="<?= e(cfg('extended_lockout_threshold', '10')) ?>" min="5" max="50" required>
            </div>
            <div class="form-group">
              <label class="form-label">Tier 2 — Extended Lockout (minutes)</label>
              <input type="number" name="extended_lockout_minutes" class="form-control"
                value="<?= e(cfg('extended_lockout_minutes', '60')) ?>" min="15" max="480" required>
            </div>
            <div class="form-group">
              <label class="form-label">Tier 3 — Hard Lockout Threshold</label>
              <input type="number" name="hard_lockout_threshold" class="form-control"
                value="<?= e(cfg('hard_lockout_threshold', '20')) ?>" min="10" max="100" required>
            </div>
            <div class="form-group">
              <label class="form-label">Tier 3 — Hard Lockout (hours)</label>
              <input type="number" name="hard_lockout_hours" class="form-control"
                value="<?= e(cfg('hard_lockout_hours', '24')) ?>" min="1" max="168" required>
            </div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save Security Settings</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- IP Whitelist Tab -->
  <div class="tab-panel <?= $activeTab === 'ip-whitelist' ? 'active' : '' ?>" id="tab-ip-whitelist">
    <div class="card">
      <div class="card-header"><span class="card-title">IP Whitelist</span>
        <?php if (cfg('ip_whitelist_enabled') === '1'): ?>
        <span class="badge badge-active" style="margin-left:auto">Enabled</span>
        <?php else: ?>
        <span class="badge badge-inactive" style="margin-left:auto">Disabled</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <?php if (cfg('ip_whitelist_enabled') !== '1'): ?>
        <div class="alert alert-warning mb-4">
          IP whitelisting is currently <strong>disabled</strong>. When enabled, only the listed IPs/CIDRs can access the system.
          <strong>Ensure your current IP is in the list before enabling.</strong>
        </div>
        <?php endif; ?>
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_ip_whitelist">

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('ip_whitelist_enabled') === '1' ? 'on' : '' ?>" id="toggle-ipwl"
                onclick="this.classList.toggle('on');document.getElementById('ip_whitelist_enabled').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Enable IP Whitelist</span>
            </label>
            <input type="hidden" name="ip_whitelist_enabled" id="ip_whitelist_enabled"
              value="<?= e(cfg('ip_whitelist_enabled', '0')) ?>">
          </div>

          <div class="form-group">
            <label class="form-label">Allowed IPs / CIDR Ranges</label>
            <textarea name="ip_whitelist_raw" class="form-control font-mono"
              rows="8" placeholder="192.168.1.0/24&#10;10.0.0.5&#10;203.0.113.42"
              style="resize:vertical"><?= e($ipWhitelistRaw) ?></textarea>
            <div class="form-hint">One entry per line. Supports IPv4 addresses and CIDR notation (e.g. 192.168.1.0/24). Your current IP: <strong class="font-mono"><?= e(client_ip()) ?></strong></div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save IP Whitelist</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Maintenance Tab -->
  <div class="tab-panel <?= $activeTab === 'maintenance' ? 'active' : '' ?>" id="tab-maintenance">
    <div class="card">
      <div class="card-header"><span class="card-title">Maintenance Mode</span>
        <?php if (cfg('maintenance_mode') === '1'): ?>
        <span class="badge badge-warning" style="margin-left:auto">Active</span>
        <?php else: ?>
        <span class="badge badge-inactive" style="margin-left:auto">Off</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <div class="alert alert-warning mb-4">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
          When maintenance mode is on, only IPs in the allowed list can log in. All other users will see a maintenance page.
          <strong>Ensure your IP is in the list before enabling.</strong>
        </div>
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_maintenance">

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('maintenance_mode') === '1' ? 'on' : '' ?>" id="toggle-maint"
                onclick="this.classList.toggle('on');document.getElementById('maintenance_mode').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Enable Maintenance Mode</span>
            </label>
            <input type="hidden" name="maintenance_mode" id="maintenance_mode"
              value="<?= e(cfg('maintenance_mode', '0')) ?>">
          </div>

          <div class="form-group">
            <label class="form-label">IPs Allowed During Maintenance</label>
            <textarea name="maintenance_allowed_ips_raw" class="form-control font-mono"
              rows="6" placeholder="192.168.1.5&#10;203.0.113.10"
              style="resize:vertical"><?= e($maintAllowedRaw) ?></textarea>
            <div class="form-hint">One IP per line. Your current IP: <strong class="font-mono"><?= e(client_ip()) ?></strong></div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save Maintenance Settings</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- After Hours Tab -->
  <div class="tab-panel <?= $activeTab === 'after-hours' ? 'active' : '' ?>" id="tab-after-hours">
    <div class="card">
      <div class="card-header"><span class="card-title">After-Hours Monitoring</span>
        <?php if (cfg('after_hours_flag_enabled') === '1'): ?>
        <span class="badge badge-warning" style="margin-left:auto">Enabled</span>
        <?php else: ?>
        <span class="badge badge-inactive" style="margin-left:auto">Disabled</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          When enabled, any password reveal or sensitive action performed outside of business hours
          is flagged in the audit log with a <code>warning</code> severity for review.
          Times are in <strong>UTC</strong>.
        </p>
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_after_hours">

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('after_hours_flag_enabled') === '1' ? 'on' : '' ?>" id="toggle-ah"
                onclick="this.classList.toggle('on');document.getElementById('after_hours_flag_enabled').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Enable After-Hours Flagging</span>
            </label>
            <input type="hidden" name="after_hours_flag_enabled" id="after_hours_flag_enabled"
              value="<?= e(cfg('after_hours_flag_enabled', '0')) ?>">
          </div>

          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">After Hours Start (UTC)</label>
              <input type="time" name="after_hours_start" class="form-control"
                value="<?= e(cfg('after_hours_start', '20:00')) ?>" required>
              <div class="form-hint">Outside business hours begin at this time.</div>
            </div>
            <div class="form-group">
              <label class="form-label">After Hours End (UTC)</label>
              <input type="time" name="after_hours_end" class="form-control"
                value="<?= e(cfg('after_hours_end', '08:00')) ?>" required>
              <div class="form-hint">Business hours resume at this time.</div>
            </div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save After-Hours Settings</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Alerts Tab -->
  <div class="tab-panel <?= $activeTab === 'alerts' ? 'active' : '' ?>" id="tab-alerts">
    <div class="card">
      <div class="card-header"><span class="card-title">Email Alerts</span>
        <?php if (cfg('alert_email_enabled') === '1'): ?>
        <span class="badge badge-active" style="margin-left:auto">Enabled</span>
        <?php else: ?>
        <span class="badge badge-inactive" style="margin-left:auto">Disabled</span>
        <?php endif; ?>
      </div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          When enabled, security alerts (bulk password reveals, after-hours access) are sent via email
          using your server's PHP <code>mail()</code> function. Ensure your hosting provider has outbound
          mail configured.
        </p>
        <form method="POST" action="?page=settings">
          <?= CSRF::field() ?>
          <input type="hidden" name="action" value="save_alerts">

          <div class="form-group mb-4">
            <label style="display:flex;align-items:center;gap:10px;cursor:pointer">
              <div class="toggle <?= cfg('alert_email_enabled') === '1' ? 'on' : '' ?>" id="toggle-alerts"
                onclick="this.classList.toggle('on');document.getElementById('alert_email_enabled').value=this.classList.contains('on')?'1':'0'">
                <div class="toggle-knob"></div>
              </div>
              <span class="form-label" style="margin:0">Enable Email Alerts</span>
            </label>
            <input type="hidden" name="alert_email_enabled" id="alert_email_enabled"
              value="<?= e(cfg('alert_email_enabled', '0')) ?>">
          </div>

          <div class="form-grid">
            <div class="form-group">
              <label class="form-label">Send Alerts To <span class="required">*</span></label>
              <input type="email" name="alert_email_to" class="form-control"
                value="<?= e(cfg('alert_email_to', '')) ?>"
                placeholder="admin@yourdomain.com">
              <div class="form-hint">The email address that receives security alerts.</div>
            </div>
            <div class="form-group">
              <label class="form-label">Send Alerts From <span class="required">*</span></label>
              <input type="email" name="alert_email_from" class="form-control"
                value="<?= e(cfg('alert_email_from', '')) ?>"
                placeholder="noreply@yourdomain.com">
              <div class="form-hint">The sender address shown in alert emails.</div>
            </div>
          </div>

          <div class="mt-4">
            <button type="submit" class="btn btn-primary">Save Alert Settings</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <!-- Tools Tab -->
  <div class="tab-panel <?= $activeTab === 'tools' ? 'active' : '' ?>" id="tab-tools">

    <!-- Export -->
    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Export Credentials</span></div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          Download all accessible credentials as a CSV file. Optionally include plaintext passwords
          (requires your account to have password view permission). Exports are recorded in the audit log.
        </p>
        <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
          <a href="api/export.php?format=csv&include_passwords=0" class="btn btn-outline">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            Export CSV (no passwords)
          </a>
          <?php if (RBAC::canViewPasswords()): ?>
          <a href="api/export.php?format=csv&include_passwords=1"
             onclick="return confirm('This export will include plaintext passwords. Are you sure?')"
             class="btn btn-outline" style="color:var(--warning);border-color:var(--warning)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
            Export CSV (with passwords)
          </a>
          <?php endif; ?>
        </div>
      </div>
    </div>

    <!-- Import -->
    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Import Credentials</span></div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          Upload a CSV to bulk-import managers and coverage accounts. Required columns:
          <code>Type</code>, <code>Server</code>, <code>Name</code>, <code>Login</code>, <code>Password</code>.
          For coverage rows, also include <code>Manager Login</code>.
          Duplicate logins on the same server are skipped.
        </p>
        <div id="import-area">
          <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
            <input type="file" id="import-file" accept=".csv" style="font-size:0.875rem">
            <button class="btn btn-outline" onclick="previewImport()">Preview</button>
            <button class="btn btn-primary" id="import-commit-btn" style="display:none" onclick="commitImport()">
              Confirm Import
            </button>
          </div>
          <div id="import-status" class="text-sm text-muted mt-3"></div>
          <div id="import-preview" style="margin-top:12px"></div>
        </div>
      </div>
    </div>

    <!-- Backup -->
    <div class="card mb-4">
      <div class="card-header"><span class="card-title">Database Backup</span></div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          Download a full SQL dump of all VaultFX tables. Encrypted credentials remain encrypted in the
          backup — no plaintext passwords are included. Backups are recorded in the audit log.
        </p>
        <a href="api/backup.php" class="btn btn-outline"
           onclick="return confirm('Download a full database backup? This action will be logged.')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
          Download Backup (.sql)
        </a>
      </div>
    </div>

    <!-- Key Rotation -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">Key Rotation</span>
        <span id="rotation-status-badge" class="badge badge-inactive" style="margin-left:auto">Checking…</span>
      </div>
      <div class="card-body">
        <p class="text-sm text-muted mb-4" style="line-height:1.6">
          Re-encrypts all credentials using the current master key version. Run this after adding a new
          encryption key to <code>keys/encryption.key.php</code>. All credentials remain encrypted at all
          times — there is no window where plaintext is written to disk.
        </p>
        <div id="rotation-details" class="text-sm text-muted mb-4"></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn btn-outline" onclick="checkKeyStatus()">Check Status</button>
          <button class="btn btn-danger" id="rotate-btn" style="display:none"
            onclick="runKeyRotation()">Rotate Keys Now</button>
        </div>
        <div id="rotation-result" class="mt-4"></div>
      </div>
    </div>

  </div>

</div><!-- /.tabs wrapper -->

<script>
// ── Import ────────────────────────────────────────────────────
async function previewImport() {
  const file = document.getElementById('import-file').files[0];
  if (!file) { VaultFX.toast('error', 'Select a CSV file first.'); return; }

  const fd = new FormData();
  fd.append('csv_file', file);

  document.getElementById('import-status').textContent = 'Parsing…';
  document.getElementById('import-preview').innerHTML = '';
  document.getElementById('import-commit-btn').style.display = 'none';

  const res = await VaultFX.postForm('api/import.php?action=preview', fd);
  if (!res.ok || !res.data.success) {
    document.getElementById('import-status').textContent = res.data.message || 'Preview failed.';
    return;
  }

  const { preview, errors, total } = res.data.data;
  let html = '';

  if (errors.length) {
    html += '<div class="alert alert-error mb-3" style="font-size:0.8rem">'
          + errors.map(e => VaultFX.escapeHtml(e)).join('<br>')
          + '</div>';
  }

  if (total > 0) {
    html += `<p class="text-sm mb-2">${total} rows ready to import:</p>`;
    html += '<div style="max-height:260px;overflow-y:auto;border:1px solid var(--border);border-radius:6px">'
          + '<table style="width:100%;font-size:0.8rem"><thead><tr>'
          + '<th style="padding:6px 10px;text-align:left">Type</th><th style="padding:6px 10px;text-align:left">Server</th>'
          + '<th style="padding:6px 10px;text-align:left">Name</th><th style="padding:6px 10px;text-align:left">Login</th>'
          + '<th style="padding:6px 10px;text-align:left">Password</th></tr></thead><tbody>';
    preview.forEach(r => {
      html += `<tr><td style="padding:5px 10px">${VaultFX.escapeHtml(r.type)}</td>`
            + `<td style="padding:5px 10px">${VaultFX.escapeHtml(r.server_name)}</td>`
            + `<td style="padding:5px 10px">${VaultFX.escapeHtml(r.name)}</td>`
            + `<td style="padding:5px 10px font-family:monospace">${VaultFX.escapeHtml(r.login)}</td>`
            + `<td style="padding:5px 10px">${r.has_password ? '••••••••' : '<span style="color:var(--danger)">missing</span>'}</td></tr>`;
    });
    html += '</tbody></table></div>';
    document.getElementById('import-commit-btn').style.display = '';
  }

  document.getElementById('import-status').textContent = '';
  document.getElementById('import-preview').innerHTML = html;
}

async function commitImport() {
  const file = document.getElementById('import-file').files[0];
  if (!file) return;

  const ok = await VaultFX.confirm({
    title: 'Confirm Import',
    message: 'This will create credentials in the database. Proceed?',
    confirmText: 'Import',
    confirmClass: 'btn-primary',
  });
  if (!ok) return;

  const fd = new FormData();
  fd.append('csv_file', file);

  document.getElementById('import-status').textContent = 'Importing…';
  const res = await VaultFX.postForm('api/import.php?action=commit', fd);

  if (res.ok && res.data.success) {
    VaultFX.toast('success', res.data.message);
    document.getElementById('import-status').textContent = res.data.message;
    document.getElementById('import-preview').innerHTML = '';
    document.getElementById('import-commit-btn').style.display = 'none';
    document.getElementById('import-file').value = '';
  } else {
    VaultFX.toast('error', res.data.message || 'Import failed.');
    document.getElementById('import-status').textContent = res.data.message || 'Import failed.';
  }
}

// ── Key Rotation ───────────────────────────────────────────────
async function checkKeyStatus() {
  document.getElementById('rotation-status-badge').textContent = 'Checking…';
  const res = await VaultFX.fetch('api/keys.php?action=status');
  if (!res.ok || !res.data.success) {
    VaultFX.toast('error', 'Failed to fetch key status.');
    return;
  }
  const d = res.data.data;
  const badge = document.getElementById('rotation-status-badge');
  const details = document.getElementById('rotation-details');
  const rotateBtn = document.getElementById('rotate-btn');

  if (d.outdated_total === 0) {
    badge.textContent = 'Up to date';
    badge.className = 'badge badge-active';
    rotateBtn.style.display = 'none';
    details.textContent = `All credentials are on key version ${d.current_key_version}.`;
  } else {
    badge.textContent = `${d.outdated_total} outdated`;
    badge.className = 'badge badge-critical';
    rotateBtn.style.display = '';
    details.innerHTML = `Current key version: <strong>${d.current_key_version}</strong><br>`
      + `Outdated manager passwords: <strong>${d.outdated_managers}</strong><br>`
      + `Outdated coverage passwords: <strong>${d.outdated_coverage}</strong><br>`
      + `Outdated investor passwords: <strong>${d.outdated_investor}</strong>`;
  }
}

async function runKeyRotation() {
  const ok = await VaultFX.confirm({
    title: 'Run Key Rotation',
    message: 'This will re-encrypt all outdated credentials with the current master key. This may take a moment. Proceed?',
    confirmText: 'Rotate Keys',
    confirmClass: 'btn-danger',
  });
  if (!ok) return;

  document.getElementById('rotation-result').textContent = 'Rotating keys…';
  const res = await VaultFX.postForm('api/keys.php?action=rotate', new FormData());

  if (res.ok && res.data.success) {
    VaultFX.toast('success', res.data.message);
    document.getElementById('rotation-result').innerHTML =
      `<div class="alert alert-success">${VaultFX.escapeHtml(res.data.message)}</div>`;
    checkKeyStatus();
  } else {
    VaultFX.toast('error', res.data.message || 'Key rotation failed.');
    document.getElementById('rotation-result').innerHTML =
      `<div class="alert alert-error">${VaultFX.escapeHtml(res.data.message || 'Rotation failed.')}</div>`;
  }
}

// Auto-check key status when Tools tab is active
document.addEventListener('DOMContentLoaded', function() {
  const toolsBtn = document.querySelector('[data-tab="tools"]');
  if (toolsBtn) {
    toolsBtn.addEventListener('click', function() {
      setTimeout(checkKeyStatus, 100);
    });
  }
  // If already on tools tab on load
  if (document.getElementById('tab-tools')?.classList.contains('active')) {
    checkKeyStatus();
  }
});

// ── Appearance / Theme Colour ─────────────────────────────────
function hexIsValid(hex) {
  return /^#[0-9a-fA-F]{6}$/.test(hex);
}

function applyPreset(hex) {
  document.getElementById('accentColorPicker').value = hex;
  document.getElementById('accentColorHex').value    = hex;
  updatePreview(hex);
}

function syncColorPicker(val) {
  if (hexIsValid(val)) {
    document.getElementById('accentColorPicker').value = val;
    updatePreview(val);
  }
}

function updatePreview(hex) {
  if (!hexIsValid(hex)) return;
  const r = parseInt(hex.slice(1,3),16),
        g = parseInt(hex.slice(3,5),16),
        b = parseInt(hex.slice(5,7),16);
  const soft = `rgba(${r},${g},${b},0.12)`;
  const darker = `rgb(${Math.round(r*0.82)},${Math.round(g*0.82)},${Math.round(b*0.82)})`;

  const btn   = document.getElementById('previewBtn');
  const link  = document.getElementById('previewLink');
  const badge = document.getElementById('previewBadge');
  const logo  = document.getElementById('previewLogo');

  if (btn)   btn.style.background   = hex;
  if (link)  link.style.color       = hex;
  if (badge) { badge.style.background = soft; badge.style.color = hex; }
  if (logo)  logo.style.background  = `linear-gradient(135deg,${hex},${darker})`;
}

// Wire up native colour picker → hex text input + preview
document.addEventListener('DOMContentLoaded', function() {
  const picker = document.getElementById('accentColorPicker');
  const hex    = document.getElementById('accentColorHex');
  if (picker && hex) {
    picker.addEventListener('input', function() {
      hex.value = picker.value;
      updatePreview(picker.value);
    });
    // Init preview with current colour
    updatePreview(picker.value);
  }
});
</script>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
