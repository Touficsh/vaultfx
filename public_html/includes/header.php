<?php
/**
 * VaultFX — HTML Head + App Shell Header
 * Outputs: <html>, <head>, sidebar, top header
 * Must be included AFTER Auth::require() is called.
 */

$currentUser   = Auth::user();
$currentPage   = $_GET['page'] ?? 'dashboard';
$appName       = setting('app_name', 'VaultFX');
$userTheme     = $currentUser['theme_preference'] ?? 'dark';
$csrfToken     = CSRF::token();
$flash         = get_flash();
$accentColor   = setting('theme_accent_color', '#3b82f6');
// Sanitize to a safe hex color (fallback to default if invalid)
if (!preg_match('/^#[0-9a-fA-F]{6}$/', $accentColor)) {
    $accentColor = '#3b82f6';
}
// Derive hover (slightly darker) and soft (low-opacity) variants from accent hex
function hex_darken(string $hex, float $factor = 0.85): string {
    $r = (int)(hexdec(substr($hex,1,2)) * $factor);
    $g = (int)(hexdec(substr($hex,3,2)) * $factor);
    $b = (int)(hexdec(substr($hex,5,2)) * $factor);
    return sprintf('#%02x%02x%02x', max(0,$r), max(0,$g), max(0,$b));
}
function hex_to_rgb(string $hex): string {
    return hexdec(substr($hex,1,2)).','.hexdec(substr($hex,3,2)).','.hexdec(substr($hex,5,2));
}
$accentHover  = hex_darken($accentColor, 0.82);
$accentSoft   = 'rgba('.hex_to_rgb($accentColor).',0.12)';
$accentGlow   = 'rgba('.hex_to_rgb($accentColor).',0.25)';
$focusRing    = '0 0 0 3px rgba('.hex_to_rgb($accentColor).',0.35)';
// Build SVG favicon data URI using current accent color
$faviconSvg   = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="'.$accentColor.'"/><rect x="8" y="16" width="16" height="11" rx="2" fill="none" stroke="white" stroke-width="2"/><path d="M11 16v-5a5 5 0 0 1 10 0v5" fill="none" stroke="white" stroke-width="2"/><circle cx="16" cy="22" r="1.5" fill="white"/></svg>';
$faviconDataUri = 'data:image/svg+xml;base64,'.base64_encode($faviconSvg);
?>
<!DOCTYPE html>
<html lang="en" data-theme="<?= e($userTheme === 'light' ? 'light' : 'dark') ?>">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="csrf-token" content="<?= e($csrfToken) ?>">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="robots" content="noindex, nofollow">
  <title><?= e($pageTitle ?? 'Dashboard') ?> — <?= e($appName) ?></title>

  <!-- No caching for secure pages -->
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">

  <!-- Dynamic Favicon (uses current theme accent color) -->
  <link rel="icon" type="image/svg+xml" href="<?= $faviconDataUri ?>">
  <link rel="shortcut icon" type="image/svg+xml" href="<?= $faviconDataUri ?>">

  <link rel="stylesheet" href="assets/css/style.css?v=<?= APP_VERSION ?>">

  <!-- Dynamic theme accent override -->
  <style>
    :root {
      --accent:       <?= $accentColor ?>;
      --accent-hover: <?= $accentHover ?>;
      --accent-soft:  <?= $accentSoft ?>;
      --accent-glow:  <?= $accentGlow ?>;
      --border-focus: <?= $accentColor ?>;
      --focus-ring:   <?= $focusRing ?>;
    }
  </style>
  <?php if (!empty($extraCss)): foreach ($extraCss as $css): ?>
  <link rel="stylesheet" href="<?= e($css) ?>?v=<?= APP_VERSION ?>">
  <?php endforeach; endif; ?>

  <!-- Lucide Icons (CDN) -->
  <script src="https://unpkg.com/lucide@latest/dist/umd/lucide.min.js" defer></script>
</head>
<body>

<?php if ($flash): ?>
<div id="php-flash" data-type="<?= e($flash['type']) ?>" data-message="<?= e($flash['message']) ?>" hidden></div>
<?php endif; ?>

<div class="app-layout">
  <!-- ── Sidebar ─────────────────────────────────────── -->
  <aside class="sidebar">
    <div class="sidebar-logo">
      <div class="sidebar-logo-icon">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5">
          <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
          <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
        </svg>
      </div>
      <span class="sidebar-logo-text">Vault<span>FX</span></span>
    </div>

    <div class="sidebar-section">
      <div class="sidebar-section-label">Main</div>
      <ul class="sidebar-nav">
        <li>
          <a href="?page=dashboard" class="<?= $currentPage === 'dashboard' ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect>
              <rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect>
            </svg>
            <span>Dashboard</span>
          </a>
        </li>
        <li>
          <a href="?page=servers" class="<?= in_array($currentPage, ['servers','server-detail']) ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
              <line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line>
            </svg>
            <span>Servers</span>
          </a>
        </li>
      </ul>
    </div>

    <?php if (RBAC::atLeast(RBAC::ADMIN)): ?>
    <div class="sidebar-section">
      <div class="sidebar-section-label">Management</div>
      <ul class="sidebar-nav">
        <?php if (RBAC::canViewAuditLog()): ?>
        <li>
          <a href="?page=audit-log" class="<?= $currentPage === 'audit-log' ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
              <polyline points="14 2 14 8 20 8"></polyline>
              <line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line>
              <polyline points="10 9 9 9 8 9"></polyline>
            </svg>
            <span>Audit Log</span>
          </a>
        </li>
        <?php endif; ?>
        <?php if (RBAC::atLeast(RBAC::ADMIN)): ?>
        <li>
          <a href="?page=login-activity" class="<?= $currentPage === 'login-activity' ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>
              <circle cx="12" cy="7" r="4"></circle>
              <polyline points="12 3 8 8 12 13 16 8"></polyline>
            </svg>
            <span>Login Activity</span>
          </a>
        </li>
        <?php endif; ?>
        <?php if (RBAC::canManageUsers()): ?>
        <li>
          <a href="?page=users" class="<?= $currentPage === 'users' ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
              <circle cx="9" cy="7" r="4"></circle>
              <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
              <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
            </svg>
            <span>Users</span>
          </a>
        </li>
        <?php endif; ?>
        <?php if (RBAC::canViewSettings()): ?>
        <li>
          <a href="?page=settings" class="<?= $currentPage === 'settings' ? 'active' : '' ?>">
            <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="3"></circle>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
            </svg>
            <span>Settings</span>
          </a>
        </li>
        <?php endif; ?>
      </ul>
    </div>
    <?php endif; ?>

    <div class="sidebar-footer">
      <a href="?page=my-account" class="sidebar-user" style="text-decoration:none">
        <div class="sidebar-avatar"><?= e(strtoupper(substr($currentUser['username'], 0, 2))) ?></div>
        <div class="sidebar-user-info">
          <div class="sidebar-username"><?= e($currentUser['username']) ?></div>
          <div class="sidebar-role"><?= e(RBAC::roleLabel($currentUser['role'])) ?></div>
        </div>
      </a>
      <div style="display:flex;gap:4px;margin-top:6px;padding:0 2px">
        <button id="theme-toggle" class="header-btn" title="Toggle theme" style="flex:1;width:auto">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="5"></circle>
            <line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
            <line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
          </svg>
        </button>
        <a href="?page=logout" class="header-btn" title="Logout" style="flex:1;width:auto;text-decoration:none;justify-content:center">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
            <polyline points="16 17 21 12 16 7"></polyline>
            <line x1="21" y1="12" x2="9" y2="12"></line>
          </svg>
        </a>
      </div>
    </div>
  </aside>

  <!-- ── Top Header ───────────────────────────────────── -->
  <header class="app-header">
    <div class="header-search">
      <svg class="header-search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line>
      </svg>
      <input
        type="text"
        id="global-search"
        placeholder="Search servers, accounts, tags…"
        autocomplete="off"
        spellcheck="false"
        maxlength="100">
      <div class="search-results" id="search-results"></div>
    </div>

    <div class="header-actions">
      <?php if (!empty($currentUser['last_login_at'])): ?>
      <span style="font-size:0.76rem;color:var(--text-muted)">
        Last login: <?= e(format_datetime($currentUser['last_login_at'])) ?>
        <?php if (!empty($currentUser['last_login_ip'])): ?>
          · <span class="font-mono"><?= e($currentUser['last_login_ip']) ?></span>
        <?php endif; ?>
      </span>
      <?php endif; ?>

      <?php if ($currentUser['totp_enabled']): ?>
      <span title="2FA Enabled" style="color:var(--success);display:flex;align-items:center">
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
      </span>
      <?php endif; ?>
    </div>
  </header>

  <!-- ── Main Content (individual pages inject here) ── -->
  <main class="main-content">
