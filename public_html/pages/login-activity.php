<?php
/**
 * VaultFX — Login Activity Page
 * Shows active sessions and login history. Admin-only.
 */

RBAC::assertRole(RBAC::ADMIN);

$pageTitle = 'Login Activity';

// ── Optional filters ──────────────────────────────────────────────
$filterUserId = param_int('user_id', 0, $_GET);
$filterStatus = preg_replace('/[^a-z_]/', '', strtolower($_GET['status'] ?? ''));

// ── Active Sessions ───────────────────────────────────────────────
$activeSessions = DB::rows(
    "SELECT s.id, s.user_id, u.username, u.role, s.ip_address, s.user_agent, s.login_at, s.last_activity
     FROM active_sessions s
     JOIN users u ON u.id = s.user_id
     ORDER BY s.last_activity DESC"
);

// ── Login History ─────────────────────────────────────────────────
$allowedTypes = ['login_success', 'login_failed', 'login_2fa_pending', 'login_new_ip', 'logout', '2fa_failed'];

$whereClauses = ["al.action_type IN ('login_success','login_failed','login_2fa_pending','login_new_ip','logout','2fa_failed')"];
$bindings     = [];

if ($filterUserId > 0) {
    $whereClauses[] = 'al.user_id = ?';
    $bindings[]     = $filterUserId;
}

if ($filterStatus === 'success') {
    $whereClauses[] = "al.action_type = 'login_success'";
} elseif ($filterStatus === 'failed') {
    $whereClauses[] = "al.action_type = 'login_failed'";
}

$whereSQL = implode(' AND ', $whereClauses);

$loginHistory = DB::rows(
    "SELECT al.id, al.user_id, al.username, al.action_type, al.ip_address, al.user_agent, al.details, al.severity, al.created_at
     FROM audit_log al
     WHERE {$whereSQL}
     ORDER BY al.created_at DESC
     LIMIT 200",
    $bindings
);

// ── Helper: action badge ──────────────────────────────────────────
function login_action_badge(string $type): string
{
    $map = [
        'login_success'      => ['success',  'Login'],
        'login_failed'       => ['danger',   'Failed'],
        'login_2fa_pending'  => ['warning',  '2FA Pending'],
        'login_new_ip'       => ['warning',  'New IP'],
        'logout'             => ['secondary','Logout'],
        '2fa_failed'         => ['danger',   '2FA Failed'],
    ];
    $info  = $map[$type] ?? ['secondary', htmlspecialchars($type, ENT_QUOTES)];
    $color = $info[0];
    $label = $info[1];

    $styleMap = [
        'success'   => 'background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.25)',
        'danger'    => 'background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.25)',
        'warning'   => 'background:rgba(234,179,8,.15);color:#ca8a04;border:1px solid rgba(234,179,8,.25)',
        'secondary' => 'background:rgba(148,163,184,.15);color:var(--text-muted);border:1px solid rgba(148,163,184,.2)',
    ];

    $style = $styleMap[$color] ?? $styleMap['secondary'];
    return '<span class="badge" style="' . $style . '">' . $label . '</span>';
}

// ── Collect unique users for filter dropdown ──────────────────────
$filterUsers = DB::rows(
    "SELECT DISTINCT u.id, u.username
     FROM audit_log al JOIN users u ON u.id = al.user_id
     WHERE al.action_type IN ('login_success','login_failed','login_2fa_pending','login_new_ip','logout','2fa_failed')
     ORDER BY u.username ASC"
);

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">Login Activity</h1>
    <p class="page-subtitle">Active sessions and login history</p>
  </div>
</div>

<!-- ══════════════════════════════════════════════════════════════ -->
<!-- Section 1: Active Sessions                                     -->
<!-- ══════════════════════════════════════════════════════════════ -->
<div class="card mb-6">
  <div class="card-header">
    <h2 class="card-title">Active Sessions</h2>
    <span class="badge" style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.25)">
      <?= count($activeSessions) ?> active
    </span>
  </div>

  <?php if (empty($activeSessions)): ?>
  <div class="card-body">
    <div style="text-align:center;padding:32px 0;color:var(--text-muted);font-size:0.875rem">
      No active sessions found.
    </div>
  </div>
  <?php else: ?>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>Username</th>
          <th>Role</th>
          <th>IP Address</th>
          <th>Login Time</th>
          <th>Last Active</th>
          <th>User Agent</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($activeSessions as $sess): ?>
        <tr>
          <td>
            <span style="font-weight:500"><?= e($sess['username']) ?></span>
          </td>
          <td>
            <span class="badge"><?= e(RBAC::roleLabel($sess['role'])) ?></span>
          </td>
          <td class="font-mono text-sm"><?= e($sess['ip_address'] ?? '—') ?></td>
          <td style="font-size:0.835rem;white-space:nowrap">
            <?= $sess['login_at'] ? e(format_datetime($sess['login_at'])) : '—' ?>
          </td>
          <td style="font-size:0.835rem;white-space:nowrap">
            <?= $sess['last_activity'] ? e(time_ago($sess['last_activity'])) : '—' ?>
          </td>
          <td style="font-size:0.78rem;color:var(--text-muted);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= e($sess['user_agent'] ?? '') ?>">
            <?= e(mb_strimwidth($sess['user_agent'] ?? '', 0, 60, '…')) ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>
</div>

<!-- ══════════════════════════════════════════════════════════════ -->
<!-- Section 2: Login History                                       -->
<!-- ══════════════════════════════════════════════════════════════ -->
<div class="card">
  <div class="card-header" style="flex-wrap:wrap;gap:10px">
    <h2 class="card-title">Login History</h2>

    <!-- Filters -->
    <form method="GET" action="" style="display:flex;align-items:center;gap:8px;margin-left:auto">
      <input type="hidden" name="page" value="login-activity">

      <select name="user_id" class="form-control" style="min-width:140px;font-size:0.835rem;padding:5px 10px">
        <option value="0">All users</option>
        <?php foreach ($filterUsers as $fu): ?>
        <option value="<?= (int)$fu['id'] ?>" <?= $filterUserId === (int)$fu['id'] ? 'selected' : '' ?>>
          <?= e($fu['username']) ?>
        </option>
        <?php endforeach; ?>
      </select>

      <select name="status" class="form-control" style="min-width:130px;font-size:0.835rem;padding:5px 10px">
        <option value="">All actions</option>
        <option value="success" <?= $filterStatus === 'success' ? 'selected' : '' ?>>Login Success</option>
        <option value="failed"  <?= $filterStatus === 'failed'  ? 'selected' : '' ?>>Login Failed</option>
      </select>

      <button type="submit" class="btn btn-outline btn-sm">Filter</button>
      <?php if ($filterUserId || $filterStatus): ?>
      <a href="?page=login-activity" class="btn btn-ghost btn-sm">Clear</a>
      <?php endif; ?>
    </form>
  </div>

  <?php if (empty($loginHistory)): ?>
  <div class="card-body">
    <div style="text-align:center;padding:32px 0;color:var(--text-muted);font-size:0.875rem">
      No login records match the selected filters.
    </div>
  </div>
  <?php else: ?>
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th>User</th>
          <th>Action</th>
          <th>IP Address</th>
          <th>Time</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($loginHistory as $entry):
          // Parse details JSON for extra context
          $detailsRaw  = $entry['details'] ?? '';
          $detailsParsed = [];
          if ($detailsRaw) {
              $dec = json_decode($detailsRaw, true);
              if (is_array($dec)) {
                  $detailsParsed = $dec;
              }
          }
          $detailLabel = $detailsParsed['username'] ?? ($detailsParsed['reason'] ?? ($detailsParsed['message'] ?? ''));
        ?>
        <tr>
          <td style="font-weight:500">
            <?= e($entry['username'] ?? ('User #' . $entry['user_id'])) ?>
          </td>
          <td><?= login_action_badge($entry['action_type']) ?></td>
          <td class="font-mono text-sm"><?= e($entry['ip_address'] ?? '—') ?></td>
          <td style="font-size:0.835rem;white-space:nowrap;color:var(--text-secondary)">
            <?= $entry['created_at'] ? e(format_datetime($entry['created_at'])) : '—' ?>
          </td>
          <td style="font-size:0.78rem;color:var(--text-muted);max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
              title="<?= e($detailsRaw) ?>">
            <?= e(mb_strimwidth((string)$detailLabel, 0, 80, '…')) ?>
          </td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <div style="padding:10px 20px;font-size:0.78rem;color:var(--text-muted);border-top:1px solid var(--border)">
    Showing <?= count($loginHistory) ?> most recent record<?= count($loginHistory) !== 1 ? 's' : '' ?><?= ($filterUserId || $filterStatus) ? ' (filtered)' : '' ?>.
  </div>
  <?php endif; ?>
</div>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
