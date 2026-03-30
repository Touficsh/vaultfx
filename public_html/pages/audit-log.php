<?php
/**
 * VaultFX — Audit Log Page
 */

RBAC::assertRole(RBAC::ADMIN);
$pageTitle = 'Audit Log';

// Filters
$filters = [
    'user_id'     => param_int('user_id', 0, $_GET) ?: null,
    'action_type' => get_param('action_type'),
    'target_type' => get_param('target_type'),
    'severity'    => get_param('severity'),
    'date_from'   => get_param('date_from'),
    'date_to'     => get_param('date_to'),
    'ip'          => get_param('ip'),
];

$page    = max(1, param_int('p', 1, $_GET));
$perPage = 50;

$result = Audit::fetch(array_filter($filters), $page, $perPage);
$rows   = $result['rows'];
$total  = $result['total'];
$pages  = (int)ceil($total / $perPage);

// Users list for filter dropdown (admins only see relevant users)
$users  = DB::rows("SELECT id, username FROM users WHERE is_active = 1 ORDER BY username ASC");

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">Audit Log</h1>
    <p class="page-subtitle"><?= e(number_format($total)) ?> events</p>
  </div>
  <?php if (RBAC::canExport()): ?>
  <div class="page-header-actions">
    <a href="api/audit.php?action=export&<?= http_build_query(array_filter($filters)) ?>"
       class="btn btn-outline">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line>
      </svg>
      Export CSV
    </a>
  </div>
  <?php endif; ?>
</div>

<!-- Filters -->
<form method="GET" action="?" class="card mb-6" style="padding:16px 20px">
  <input type="hidden" name="page" value="audit-log">
  <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
    <div class="form-group" style="flex:1;min-width:140px">
      <label class="form-label">User</label>
      <select name="user_id" class="form-control">
        <option value="">All Users</option>
        <?php foreach ($users as $u): ?>
        <option value="<?= (int)$u['id'] ?>" <?= ($filters['user_id'] == $u['id']) ? 'selected' : '' ?>>
          <?= e($u['username']) ?>
        </option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="form-group" style="flex:1;min-width:160px">
      <label class="form-label">Action</label>
      <select name="action_type" class="form-control">
        <option value="">All Actions</option>
        <?php foreach (['login_success','login_failed','logout','password_reveal','credential_create','credential_edit','credential_delete','user_create','user_edit','settings_change','backup','key_rotation','bulk_reveal_flagged'] as $action): ?>
        <option value="<?= e($action) ?>" <?= $filters['action_type'] === $action ? 'selected' : '' ?>><?= e(ucwords(str_replace('_', ' ', $action))) ?></option>
        <?php endforeach; ?>
      </select>
    </div>
    <div class="form-group" style="flex:1;min-width:120px">
      <label class="form-label">Severity</label>
      <select name="severity" class="form-control">
        <option value="">All</option>
        <option value="info"     <?= $filters['severity'] === 'info' ? 'selected' : '' ?>>Info</option>
        <option value="warning"  <?= $filters['severity'] === 'warning' ? 'selected' : '' ?>>Warning</option>
        <option value="critical" <?= $filters['severity'] === 'critical' ? 'selected' : '' ?>>Critical</option>
      </select>
    </div>
    <div class="form-group" style="flex:1;min-width:130px">
      <label class="form-label">From</label>
      <input type="date" name="date_from" class="form-control" value="<?= e($filters['date_from']) ?>">
    </div>
    <div class="form-group" style="flex:1;min-width:130px">
      <label class="form-label">To</label>
      <input type="date" name="date_to" class="form-control" value="<?= e($filters['date_to']) ?>">
    </div>
    <div class="form-group" style="flex:1;min-width:130px">
      <label class="form-label">IP Address</label>
      <input type="text" name="ip" class="form-control" value="<?= e($filters['ip']) ?>" placeholder="192.168.…">
    </div>
    <div style="display:flex;gap:6px">
      <button type="submit" class="btn btn-primary">Filter</button>
      <a href="?page=audit-log" class="btn btn-outline">Clear</a>
    </div>
  </div>
</form>

<!-- Log Table -->
<div class="table-container card">
  <table>
    <thead>
      <tr>
        <th>Time</th>
        <th>User</th>
        <th>Action</th>
        <th>Target</th>
        <th>IP Address</th>
        <th>Severity</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
      <?php if (empty($rows)): ?>
      <tr>
        <td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No audit events found.</td>
      </tr>
      <?php else: ?>
      <?php foreach ($rows as $row): ?>
      <tr style="<?= $row['severity'] === 'critical' ? 'background:rgba(239,68,68,0.04)' : ($row['severity'] === 'warning' ? 'background:rgba(245,158,11,0.03)' : '') ?>">
        <td style="white-space:nowrap">
          <span class="text-sm"><?= e(format_datetime($row['created_at'], 'M j, Y')) ?></span><br>
          <span class="text-xs text-muted font-mono"><?= e(format_datetime($row['created_at'], 'H:i:s')) ?></span>
        </td>
        <td>
          <?php if ($row['username']): ?>
          <span class="font-mono text-sm"><?= e($row['username']) ?></span>
          <?php else: ?>
          <span class="text-muted text-sm">—</span>
          <?php endif; ?>
        </td>
        <td>
          <span style="font-family:monospace;font-size:0.78rem;background:var(--bg-raised);padding:2px 6px;border-radius:4px">
            <?= e($row['action_type']) ?>
          </span>
        </td>
        <td class="text-sm text-muted">
          <?php if ($row['target_type']): ?>
          <?= e($row['target_type']) ?><?= $row['target_id'] ? ' #' . (int)$row['target_id'] : '' ?>
          <?php else: ?>
          —
          <?php endif; ?>
        </td>
        <td class="font-mono text-sm text-muted"><?= e($row['ip_address']) ?></td>
        <td>
          <span class="badge <?=
            $row['severity'] === 'critical' ? 'badge-critical' :
            ($row['severity'] === 'warning' ? 'badge-warning' : 'badge-ok')
          ?>"><?= e($row['severity']) ?></span>
        </td>
        <td class="text-sm text-muted" style="max-width:250px">
          <?php if ($row['details']): ?>
          <?php $details = json_decode($row['details'], true); ?>
          <?php if (is_array($details)): ?>
          <span title="<?= e(json_encode($details, JSON_PRETTY_PRINT)) ?>">
            <?= e(truncate(implode(', ', array_map(fn($k,$v) => "$k: " . (is_array($v) ? json_encode($v) : $v), array_keys($details), $details)), 80)) ?>
          </span>
          <?php else: ?>
          <?= e($row['details']) ?>
          <?php endif; ?>
          <?php else: ?>
          —
          <?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
      <?php endif; ?>
    </tbody>
  </table>
</div>

<!-- Pagination -->
<?php if ($pages > 1): ?>
<div class="pagination">
  <?php if ($page > 1): ?>
  <a href="?page=audit-log&p=<?= $page - 1 ?>&<?= http_build_query(array_filter($filters)) ?>" class="page-btn">‹</a>
  <?php endif; ?>
  <?php for ($i = max(1, $page - 3); $i <= min($pages, $page + 3); $i++): ?>
  <a href="?page=audit-log&p=<?= $i ?>&<?= http_build_query(array_filter($filters)) ?>" class="page-btn <?= $i === $page ? 'active' : '' ?>"><?= $i ?></a>
  <?php endfor; ?>
  <?php if ($page < $pages): ?>
  <a href="?page=audit-log&p=<?= $page + 1 ?>&<?= http_build_query(array_filter($filters)) ?>" class="page-btn">›</a>
  <?php endif; ?>
</div>
<?php endif; ?>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
