<?php
/**
 * VaultFX — Dashboard Page
 */

$pageTitle = 'Dashboard';

// ── Gather stats ───────────────────────────────────────────────
// Use accessible manager IDs so viewers with only manager-level
// grants (no server access) still see their correct counts.
$managerIdsSql = RBAC::accessibleManagerIdsSql();

$stats = [
    'servers'  => (int)DB::scalar(
        "SELECT COUNT(DISTINCT ma.server_id)
         FROM manager_accounts ma
         JOIN servers s ON s.id = ma.server_id
         WHERE ma.id IN {$managerIdsSql} AND ma.is_active = 1 AND s.is_active = 1"
    ),
    'managers' => (int)DB::scalar(
        "SELECT COUNT(*) FROM manager_accounts WHERE id IN {$managerIdsSql} AND is_active = 1"
    ),
    'coverage' => (int)DB::scalar(
        "SELECT COUNT(*) FROM coverage_accounts WHERE manager_account_id IN {$managerIdsSql} AND is_active = 1"
    ),
    'reveals_today' => (int)DB::scalar(
        "SELECT COUNT(*) FROM password_reveals pr
         JOIN manager_accounts ma ON ma.id = pr.credential_id AND pr.credential_type = 'manager'
                                  OR pr.credential_type IN ('coverage','coverage_investor')
         WHERE pr.revealed_at >= CURDATE()"
    ),
];

// Simpler reveals-today count
$stats['reveals_today'] = (int)DB::scalar(
    "SELECT COUNT(*) FROM password_reveals WHERE revealed_at >= CURDATE()"
);

// Recent audit activity
$recentActivity = Audit::recent(15);

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">Dashboard</h1>
    <p class="page-subtitle">Welcome back, <?= e(Auth::userField('username')) ?></p>
  </div>
  <?php if (RBAC::canManageServers()): ?>
  <div class="page-header-actions">
    <button class="btn btn-primary" onclick="VaultFX.openModal('modal-add-server')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
      Add Server
    </button>
  </div>
  <?php endif; ?>
</div>

<!-- ── Stat Cards ─────────────────────────────────────────────── -->
<div class="stat-grid mb-6">
  <div class="stat-card">
    <div class="stat-icon blue">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
        <line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line>
      </svg>
    </div>
    <div>
      <div class="stat-value"><?= e($stats['servers']) ?></div>
      <div class="stat-label">Servers</div>
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-icon green">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
      </svg>
    </div>
    <div>
      <div class="stat-value"><?= e($stats['managers']) ?></div>
      <div class="stat-label">Manager Accounts</div>
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-icon cyan">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle>
        <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
      </svg>
    </div>
    <div>
      <div class="stat-value"><?= e($stats['coverage']) ?></div>
      <div class="stat-label">Coverage Accounts</div>
    </div>
  </div>
  <div class="stat-card">
    <div class="stat-icon <?= $stats['reveals_today'] > 0 ? 'orange' : 'green' ?>">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>
      </svg>
    </div>
    <div>
      <div class="stat-value"><?= e($stats['reveals_today']) ?></div>
      <div class="stat-label">Reveals Today</div>
    </div>
  </div>
</div>

<!-- ── 2FA warning for admin users ────────────────────────────── -->
<?php if (in_array(RBAC::role(), ['super_admin','admin']) && !Auth::userField('totp_enabled')): ?>
<div class="alert alert-warning mb-6">
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="flex-shrink:0;margin-top:2px">
    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
    <line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line>
  </svg>
  <div>
    <strong>2FA Required:</strong> Two-factor authentication is mandatory for your role.
    <a href="?page=2fa-setup" style="color:inherit;text-decoration:underline">Set it up now</a>.
  </div>
</div>
<?php endif; ?>

<!-- ── Recent Activity ──────────────────────────────────────────── -->
<div class="card">
  <div class="card-header">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent)">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
      <polyline points="14 2 14 8 20 8"></polyline>
      <line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line>
    </svg>
    <span class="card-title">Recent Activity</span>
    <a href="?page=audit-log" class="btn btn-ghost btn-sm" style="margin-left:auto">View All</a>
  </div>
  <div class="card-body" style="padding:0">
    <?php if (empty($recentActivity)): ?>
    <div class="empty-state" style="padding:30px 20px">
      <div class="empty-state-title">No recent activity</div>
    </div>
    <?php else: ?>
    <?php foreach ($recentActivity as $entry): ?>
    <div style="display:flex;align-items:flex-start;gap:10px;padding:10px 16px;border-bottom:1px solid var(--border)">
      <div style="width:8px;height:8px;border-radius:50%;margin-top:6px;flex-shrink:0;background:<?=
        $entry['severity'] === 'critical' ? 'var(--danger)' :
        ($entry['severity'] === 'warning' ? 'var(--warning)' : 'var(--text-muted)')
      ?>"></div>
      <div style="flex:1;min-width:0">
        <div style="font-size:0.835rem;color:var(--text-primary)">
          <strong><?= e($entry['username'] ?? 'System') ?></strong>
          · <?= e(str_replace('_', ' ', $entry['action_type'])) ?>
        </div>
        <div style="font-size:0.75rem;color:var(--text-muted)"><?= e(time_ago($entry['created_at'])) ?></div>
      </div>
      <div style="font-size:0.72rem;color:var(--text-muted);white-space:nowrap">
        <?= e($entry['ip_address'] ?? '') ?>
      </div>
    </div>
    <?php endforeach; ?>
    <?php endif; ?>
  </div>
</div>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
