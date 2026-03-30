<?php
/**
 * VaultFX — Server Detail Page
 * Shows a specific server with all managers and coverage accounts
 */

$serverId = param_int('id', 0, $_GET);
if ($serverId <= 0) {
    redirect('?page=servers');
}

RBAC::assertServerAccess($serverId);

$server = DB::row(
    "SELECT s.*, u.username AS created_by_name
     FROM servers s LEFT JOIN users u ON u.id = s.created_by
     WHERE s.id = ? AND s.is_active = 1",
    [$serverId]
);

if (!$server) {
    http_response_code(404);
    include WEB_ROOT . '/pages/404.php';
    exit;
}

// Load managers with coverage counts (active AND inactive, filtered to accessible managers)
$accessibleMgrIds = RBAC::accessibleManagerIdsSql();
$managers = DB::rows(
    "SELECT ma.*, u.username AS created_by_name,
            COUNT(ca.id) AS coverage_count
     FROM manager_accounts ma
     LEFT JOIN users u ON u.id = ma.created_by
     LEFT JOIN coverage_accounts ca ON ca.manager_account_id = ma.id AND ca.is_active = 1
     WHERE ma.server_id = ? AND ma.id IN $accessibleMgrIds
     GROUP BY ma.id
     ORDER BY ma.is_active DESC, ma.label ASC",
    [$serverId]
);

// ── Batch-load all coverage (single query) ────────────────────
$managerIds = array_column($managers, 'id');
$coverageByManager = [];
if (!empty($managerIds)) {
    $placeholders = implode(',', array_fill(0, count($managerIds), '?'));
    $allCoverage = DB::rows(
        "SELECT ca.id, ca.manager_account_id, ca.label, ca.login_number,
                ca.notes, ca.tags, ca.encrypted_investor_password,
                ca.created_at, u.username AS created_by_name
         FROM coverage_accounts ca
         LEFT JOIN users u ON u.id = ca.created_by
         WHERE ca.manager_account_id IN ($placeholders) AND ca.is_active = 1
         ORDER BY ca.label ASC",
        $managerIds
    );
    foreach ($allCoverage as $cov) {
        $coverageByManager[(int)$cov['manager_account_id']][] = $cov;
    }
}

// ── Batch-load last reveals (two queries total) ───────────────
$allCoverageFlat = array_merge(...array_values($coverageByManager)) ?: [];
$allCoverageIds  = array_column($allCoverageFlat, 'id');
$mgrLastReveals  = Audit::batchLastReveals('manager', $managerIds);
$covLastReveals  = Audit::batchLastReveals('coverage', $allCoverageIds);

$pageTitle  = e($server['name']) . ' — Server Detail';
$canReveal  = RBAC::canViewPasswords();
$canManage  = RBAC::canManageManagers();

include WEB_ROOT . '/includes/header.php';
?>

<div class="breadcrumb">
  <a href="?page=servers">Servers</a>
  <span class="sep">›</span>
  <span><?= e($server['name']) ?></span>
</div>

<div class="page-header">
  <div>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
      <h1 class="page-title"><?= e($server['name']) ?></h1>
      <span class="badge <?= e(platform_badge_class($server['platform_type'])) ?>"><?= e($server['platform_type']) ?></span>
    </div>
    <?php if ($server['ip_address']): ?>
    <p class="page-subtitle font-mono"><?= e($server['ip_address']) ?></p>
    <?php endif; ?>
  </div>
  <?php if ($canManage): ?>
  <div class="page-header-actions">
    <button class="btn btn-outline" onclick="openEditServerDetail()">Edit Server</button>
    <button class="btn btn-primary" onclick="openAddManagerDetail()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
      Add Manager
    </button>
  </div>
  <?php endif; ?>
</div>

<?php if ($server['notes']): ?>
<div class="card mb-6" style="padding:16px 20px;font-size:0.875rem;color:var(--text-secondary);line-height:1.6">
  <strong style="color:var(--text-primary)">Notes:</strong> <?= e($server['notes']) ?>
</div>
<?php endif; ?>

<!-- Manager Accounts -->
<?php if (empty($managers)): ?>
<div class="card">
  <div class="empty-state">
    <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
    </svg>
    <div class="empty-state-title">No manager accounts</div>
    <div class="empty-state-desc"><?= $canManage ? 'Click "Add Manager" to create the first account.' : 'No accounts have been added to this server yet.' ?></div>
  </div>
</div>
<?php else: ?>
<?php foreach ($managers as $mgr):
    $coverage   = $coverageByManager[(int)$mgr['id']] ?? [];
    $lastReveal = $mgrLastReveals[(int)$mgr['id']] ?? null;
?>
<div class="accordion-item mb-4" id="mgr-accordion-<?= (int)$mgr['id'] ?>"
     data-label="<?= e($mgr['label']) ?>"
     data-login="<?= e($mgr['login_number']) ?>"
     data-notes="<?= e($mgr['notes'] ?? '') ?>"
     data-tags="<?= e($mgr['tags'] ?? '') ?>"
     data-active="<?= $mgr['is_active'] ? '1' : '0' ?>"
     style="<?= !$mgr['is_active'] ? 'opacity:0.6' : '' ?>">

  <!-- ── Accordion Header ──────────────────────────────── -->
  <div class="accordion-header">
    <svg class="accordion-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <polyline points="9 18 15 12 9 6"></polyline>
    </svg>

    <div style="flex:1;min-width:0">
      <div style="display:flex;align-items:center;gap:8px;font-weight:600;font-size:0.9375rem">
        <?= e($mgr['label']) ?>
        <?php if (!$mgr['is_active']): ?>
        <span class="badge badge-inactive" style="font-size:0.68rem">Inactive</span>
        <?php endif; ?>
      </div>
      <div style="font-size:0.78rem;color:var(--text-muted);margin-top:2px">
        Login: <?= e($mgr['login_number']) ?>
        &nbsp;·&nbsp;
        <?= count($coverage) ?> coverage
        <?php if ($lastReveal): ?>
        &nbsp;·&nbsp; Last revealed by <?= e($lastReveal['username']) ?> <?= e(time_ago($lastReveal['revealed_at'])) ?>
        <?php endif; ?>
      </div>
    </div>

    <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
      <?php if ($canManage): ?>
      <button class="btn btn-ghost btn-sm" title="<?= $mgr['is_active'] ? 'Deactivate' : 'Activate' ?>"
              style="font-size:0.78rem;<?= $mgr['is_active'] ? 'color:var(--warning)' : 'color:var(--success)' ?>"
              onclick="event.stopPropagation();toggleManagerActive(<?= (int)$mgr['id'] ?>, <?= $mgr['is_active'] ? 1 : 0 ?>)">
        <?php if ($mgr['is_active']): ?>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
        Deactivate
        <?php else: ?>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>
        Activate
        <?php endif; ?>
      </button>
      <button class="btn btn-ghost btn-icon btn-sm" title="Edit"
              onclick="event.stopPropagation();openEditManager(<?= (int)$mgr['id'] ?>, <?= (int)$serverId ?>)">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
        </svg>
      </button>
      <?php endif; ?>
    </div>
  </div>

  <!-- ── Accordion Body ────────────────────────────────── -->
  <div class="accordion-body" style="padding:20px 24px">

    <!-- Manager credential fields -->
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px">

      <div>
        <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Name</div>
        <div style="font-size:0.9rem;font-weight:500;color:var(--text-primary)"><?= e($mgr['label']) ?></div>
      </div>

      <div>
        <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Login</div>
        <div class="font-mono" style="font-size:0.9rem;color:var(--text-primary)"><?= e($mgr['login_number']) ?></div>
      </div>

      <div>
        <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Server IP</div>
        <div style="display:flex;align-items:center;gap:6px" id="server-ip-display-<?= (int)$serverId ?>">
          <span class="font-mono" style="font-size:0.9rem;color:var(--text-primary)"
                id="server-ip-value-<?= (int)$serverId ?>"><?= e($server['ip_address'] ?? '—') ?></span>
          <?php if ($canManage): ?>
          <button class="btn btn-ghost btn-icon btn-sm" title="Edit server IP"
                  onclick="startEditIp(<?= (int)$serverId ?>)">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
              <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
            </svg>
          </button>
          <?php endif; ?>
        </div>
        <?php if ($canManage): ?>
        <div style="display:none;align-items:center;gap:6px;flex-wrap:wrap" id="server-ip-edit-<?= (int)$serverId ?>">
          <input type="text" id="server-ip-input-<?= (int)$serverId ?>"
                 class="form-control font-mono"
                 style="width:160px;padding:3px 8px;font-size:0.875rem"
                 placeholder="e.g. 192.168.1.1"
                 value="<?= e($server['ip_address'] ?? '') ?>"
                 onkeydown="if(event.key==='Enter')saveIp(<?= (int)$serverId ?>);if(event.key==='Escape')cancelEditIp(<?= (int)$serverId ?>)">
          <button class="btn btn-primary btn-sm" onclick="saveIp(<?= (int)$serverId ?>)">Save</button>
          <button class="btn btn-ghost btn-sm" onclick="cancelEditIp(<?= (int)$serverId ?>)">Cancel</button>
        </div>
        <?php endif; ?>
      </div>

      <div style="grid-column:1/-1">
        <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:6px">Password</div>
        <?php if ($canReveal): ?>
        <div class="credential-password">
          <span id="pw-field-manager-<?= (int)$mgr['id'] ?>" class="credential-password-field font-mono">••••••••••••</span>
          <span id="pw-timer-manager-<?= (int)$mgr['id'] ?>" class="reveal-timer"></span>
          <button
            id="pw-copy-manager-<?= (int)$mgr['id'] ?>"
            class="btn btn-ghost btn-icon btn-sm" disabled title="Copy"
            onclick="Credentials.copyPassword('manager', <?= (int)$mgr['id'] ?>)">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
          </button>
          <button
            id="pw-reveal-manager-<?= (int)$mgr['id'] ?>"
            class="btn btn-outline btn-sm"
            title="Reveal password"
            onclick="event.stopPropagation();Credentials.reveal('manager', <?= (int)$mgr['id'] ?>, this)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
              <circle cx="12" cy="12" r="3"></circle>
            </svg>
            <span>Reveal</span>
          </button>
        </div>
        <?php else: ?>
        <span class="credential-password-field font-mono text-muted">••••••••</span>
        <?php endif; ?>
      </div>

      <?php if (!empty($mgr['notes'])): ?>
      <div style="grid-column:1/-1">
        <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Notes</div>
        <div style="font-size:0.835rem;color:var(--text-secondary);line-height:1.55"><?= e($mgr['notes']) ?></div>
      </div>
      <?php endif; ?>

    </div>

    <!-- Coverage Accounts section -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;padding-top:4px;border-top:1px solid var(--border)">
      <span style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;padding-top:10px">
        Coverage Accounts
      </span>
      <?php if (RBAC::canManageCoverage()): ?>
      <button class="btn btn-ghost btn-sm" style="margin-top:8px"
              onclick="openAddCoverage(<?= (int)$mgr['id'] ?>, <?= (int)$serverId ?>)">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line>
        </svg>
        Add Coverage
      </button>
      <?php endif; ?>
    </div>

    <?php if (empty($coverage)): ?>
    <div style="text-align:center;padding:24px 0;color:var(--text-muted);font-size:0.835rem">
      No coverage accounts for this manager.
    </div>
    <?php else: ?>
    <div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">
      <?php foreach ($coverage as $covIdx => $cov):
        $covReveal = $covLastReveals[(int)$cov['id']] ?? null;
      ?>
      <div data-cov-id="<?= (int)$cov['id'] ?>"
           data-label="<?= e($cov['label']) ?>"
           data-login="<?= e($cov['login_number']) ?>"
           data-notes="<?= e($cov['notes'] ?? '') ?>"
           data-tags="<?= e($cov['tags'] ?? '') ?>"
           style="padding:14px 20px<?= $covIdx > 0 ? ';border-top:1px solid var(--border)' : '' ?>">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">

          <div>
            <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Name</div>
            <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
              <span style="font-size:0.9rem;font-weight:500;color:var(--text-primary)"><?= e($cov['label']) ?></span>
              <?php if ($covReveal): ?>
              <span style="font-size:0.72rem;color:var(--text-muted)">Last revealed <?= e(time_ago($covReveal['revealed_at'])) ?></span>
              <?php endif; ?>
            </div>
          </div>

          <div style="display:flex;align-items:flex-start;gap:0">
            <div style="flex:1">
              <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:4px">Login</div>
              <div class="font-mono" style="font-size:0.9rem;color:var(--text-primary)"><?= e($cov['login_number']) ?></div>
            </div>
            <?php if ($canManage): ?>
            <button class="btn btn-ghost btn-icon btn-sm" title="Edit"
                    onclick="openEditCoverage(<?= (int)$cov['id'] ?>, <?= (int)$mgr['id'] ?>, <?= (int)$serverId ?>)">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
              </svg>
            </button>
            <?php endif; ?>
          </div>

          <div>
            <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:6px">Password</div>
            <?php if ($canReveal): ?>
            <div class="credential-password">
              <span id="pw-field-coverage-<?= (int)$cov['id'] ?>" class="credential-password-field font-mono">••••••••••••</span>
              <span id="pw-timer-coverage-<?= (int)$cov['id'] ?>" class="reveal-timer"></span>
              <button
                id="pw-copy-coverage-<?= (int)$cov['id'] ?>"
                class="btn btn-ghost btn-icon btn-sm" disabled title="Copy"
                onclick="Credentials.copyPassword('coverage', <?= (int)$cov['id'] ?>)">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
              <button
                id="pw-reveal-coverage-<?= (int)$cov['id'] ?>"
                class="btn btn-outline btn-sm"
                title="Reveal"
                onclick="Credentials.reveal('coverage', <?= (int)$cov['id'] ?>, this)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
                <span>Reveal</span>
              </button>
            </div>
            <?php else: ?>
            <span class="font-mono text-muted">••••••••</span>
            <?php endif; ?>
          </div>

          <?php if (!empty($cov['encrypted_investor_password'])): ?>
          <div>
            <div style="font-size:0.7rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:6px">Investor Password</div>
            <?php if ($canReveal): ?>
            <div class="credential-password">
              <span id="pw-field-coverage_investor-<?= (int)$cov['id'] ?>" class="credential-password-field font-mono">••••••••••••</span>
              <span id="pw-timer-coverage_investor-<?= (int)$cov['id'] ?>" class="reveal-timer"></span>
              <button
                id="pw-copy-coverage_investor-<?= (int)$cov['id'] ?>"
                class="btn btn-ghost btn-icon btn-sm" disabled title="Copy"
                onclick="Credentials.copyPassword('coverage_investor', <?= (int)$cov['id'] ?>)">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
              </button>
              <button
                id="pw-reveal-coverage_investor-<?= (int)$cov['id'] ?>"
                class="btn btn-outline btn-sm"
                title="Reveal investor password"
                onclick="Credentials.reveal('coverage_investor', <?= (int)$cov['id'] ?>, this)">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                  <circle cx="12" cy="12" r="3"></circle>
                </svg>
                <span>Reveal</span>
              </button>
            </div>
            <?php else: ?>
            <span class="font-mono text-muted">••••••••</span>
            <?php endif; ?>
          </div>
          <?php endif; ?>

        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

  </div><!-- /.accordion-body -->
</div><!-- /.accordion-item -->
<?php endforeach; ?>
<?php endif; ?>

<?php
$serverDataJson = json_encode([
    'id'            => (int)$server['id'],
    'name'          => $server['name'],
    'ip_address'    => $server['ip_address'],
    'platform_type' => $server['platform_type'],
    'notes'         => $server['notes'],
    'tags'          => $server['tags'],
    'is_active'     => (int)$server['is_active'],
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
?>

<!-- ─────────────────────────── MODALS ─────────────────────────── -->

<!-- Edit Server Modal -->
<div class="modal-overlay" id="modal-server">
  <div class="modal" style="max-width:540px">
    <div class="modal-header">
      <h3 class="modal-title">Edit Server</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-server')" aria-label="Close">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <div id="srv-error" class="alert alert-error mb-4" style="display:none"></div>
      <form id="server-form" onsubmit="return false">
        <input type="hidden" id="srv-id" name="id">
        <div class="form-group">
          <label class="form-label">Name <span class="text-danger">*</span></label>
          <input type="text" id="srv-name" name="name" class="form-control" maxlength="255" required>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div class="form-group">
            <label class="form-label">Platform <span class="text-danger">*</span></label>
            <select id="srv-platform" name="platform_type" class="form-control">
              <?php foreach (['MT4','MT5','cTrader','DXtrade','Other'] as $pt): ?>
              <option value="<?= e($pt) ?>"><?= e($pt) ?></option>
              <?php endforeach; ?>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">IP Address</label>
            <input type="text" id="srv-ip" name="ip_address" class="form-control font-mono" placeholder="192.168.1.1">
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea id="srv-notes" name="notes" class="form-control" rows="3"></textarea>
        </div>
        <div class="form-group">
          <label class="form-label">Tags</label>
          <input type="text" id="srv-tags" name="tags" class="form-control" placeholder="tag1, tag2">
        </div>
        <div class="form-group">
          <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
            <input type="checkbox" id="srv-active" name="is_active" value="1"> Active
          </label>
        </div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-server')">Cancel</button>
      <button class="btn btn-primary" onclick="saveServer()">Save Changes</button>
    </div>
  </div>
</div>

<!-- Add/Edit Manager Modal -->
<div class="modal-overlay" id="modal-manager">
  <div class="modal" style="max-width:560px">
    <div class="modal-header">
      <h3 class="modal-title" id="mgr-modal-title">Add Manager</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-manager')" aria-label="Close">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <div id="mgr-error" class="alert alert-error mb-4" style="display:none"></div>
      <form id="manager-form" onsubmit="return false">
        <input type="hidden" id="mgr-id" name="id">
        <input type="hidden" id="mgr-server-id" name="server_id">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div class="form-group">
            <label class="form-label">Name <span class="text-danger">*</span></label>
            <input type="text" id="mgr-label" name="label" class="form-control" maxlength="100" required>
          </div>
          <div class="form-group">
            <label class="form-label">Login Number <span class="text-danger">*</span></label>
            <input type="text" id="mgr-login" name="login_number" class="form-control font-mono" required>
          </div>
        </div>
        <div class="form-group" id="mgr-password-row">
          <label class="form-label">Password <span id="mgr-pw-hint" class="text-muted text-xs">(leave blank to keep existing)</span></label>
          <input type="password" id="mgr-password" name="password" class="form-control font-mono" autocomplete="new-password">
        </div>
        <div class="form-group">
          <label class="form-label">Tags</label>
          <input type="text" id="mgr-tags" name="tags" class="form-control" placeholder="tag1, tag2">
        </div>
        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea id="mgr-notes" name="notes" class="form-control" rows="3"></textarea>
        </div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-manager')">Cancel</button>
      <button class="btn btn-primary" onclick="saveManager()">Save Manager</button>
    </div>
  </div>
</div>

<!-- Add/Edit Coverage Modal -->
<div class="modal-overlay" id="modal-coverage">
  <div class="modal" style="max-width:560px">
    <div class="modal-header">
      <h3 class="modal-title" id="cov-modal-title">Add Coverage</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-coverage')" aria-label="Close">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <div id="cov-error" class="alert alert-error mb-4" style="display:none"></div>
      <form id="coverage-form" onsubmit="return false">
        <input type="hidden" id="cov-id" name="id">
        <input type="hidden" id="cov-manager-id" name="manager_account_id">
        <input type="hidden" id="cov-server-id" name="server_id">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div class="form-group">
            <label class="form-label">Name <span class="text-danger">*</span></label>
            <input type="text" id="cov-label" name="label" class="form-control" maxlength="100" required>
          </div>
          <div class="form-group">
            <label class="form-label">Login Number <span class="text-danger">*</span></label>
            <input type="text" id="cov-login" name="login_number" class="form-control font-mono" required>
          </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <div class="form-group">
            <label class="form-label">Password <span id="cov-pw-hint" class="text-muted text-xs">(leave blank to keep existing)</span></label>
            <input type="password" id="cov-password" name="password" class="form-control font-mono" autocomplete="new-password">
          </div>
          <div class="form-group">
            <label class="form-label">Investor Password <span class="text-muted text-xs">(optional)</span></label>
            <input type="password" id="cov-investor-pw" name="investor_password" class="form-control font-mono" autocomplete="new-password">
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Tags</label>
          <input type="text" id="cov-tags" name="tags" class="form-control" placeholder="tag1, tag2">
        </div>
        <div class="form-group">
          <label class="form-label">Notes</label>
          <textarea id="cov-notes" name="notes" class="form-control" rows="3"></textarea>
        </div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-coverage')">Cancel</button>
      <button class="btn btn-primary" onclick="saveCoverage()">Save Coverage</button>
    </div>
  </div>
</div>

<?php
$inlineJs = <<<JS
const DETAIL_SERVER_ID = {$serverId};
const SERVER_DATA = {$serverDataJson};
JS;
include WEB_ROOT . '/includes/footer.php';
?>

<script>
// ── Server Edit ───────────────────────────────────────────────
function startEditIp(serverId) {
  document.getElementById('server-ip-display-' + serverId).style.display = 'none';
  const editEl = document.getElementById('server-ip-edit-' + serverId);
  editEl.style.display = 'flex';
  document.getElementById('server-ip-input-' + serverId).focus();
}

function cancelEditIp(serverId) {
  document.getElementById('server-ip-edit-' + serverId).style.display = 'none';
  document.getElementById('server-ip-display-' + serverId).style.display = 'flex';
}

async function saveIp(serverId) {
  const ip  = document.getElementById('server-ip-input-' + serverId).value.trim();
  const fd  = new FormData();
  fd.set('id', serverId);
  fd.set('ip_address', ip);
  const res = await VaultFX.postForm('api/servers.php?action=update-ip', fd);
  if (res.ok && res.data.success) {
    document.getElementById('server-ip-value-' + serverId).textContent = ip || '—';
    cancelEditIp(serverId);
    VaultFX.toast('success', 'Server IP updated.');
  } else {
    const errs = res.data.errors ?? {};
    VaultFX.toast('error', Object.values(errs)[0] || res.data.message || 'Failed to update IP.');
  }
}

function openEditServerDetail() {
  document.getElementById('srv-id').value       = SERVER_DATA.id;
  document.getElementById('srv-name').value     = SERVER_DATA.name;
  document.getElementById('srv-ip').value       = SERVER_DATA.ip_address || '';
  document.getElementById('srv-platform').value = SERVER_DATA.platform_type;
  document.getElementById('srv-notes').value    = SERVER_DATA.notes || '';
  document.getElementById('srv-tags').value     = SERVER_DATA.tags || '';
  document.getElementById('srv-active').checked = SERVER_DATA.is_active == 1;
  document.getElementById('srv-error').style.display = 'none';
  VaultFX.openModal('modal-server');
}

async function saveServer() {
  const fd = new FormData(document.getElementById('server-form'));
  if (!document.getElementById('srv-active').checked) fd.set('is_active', '0');
  const res = await VaultFX.postForm('api/servers.php?action=edit', fd);
  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-server');
    VaultFX.toast('success', res.data.message);
    setTimeout(() => location.reload(), 600);
  } else {
    const errs = res.data.errors ?? {};
    document.getElementById('srv-error').textContent = Object.values(errs)[0] || res.data.message || 'Failed to save server.';
    document.getElementById('srv-error').style.display = 'block';
  }
}

// ── Manager Add/Edit ──────────────────────────────────────────
function openAddManagerDetail() {
  document.getElementById('mgr-id').value        = '0';
  document.getElementById('mgr-server-id').value = DETAIL_SERVER_ID;
  document.getElementById('mgr-label').value     = '';
  document.getElementById('mgr-login').value     = '';
  document.getElementById('mgr-password').value  = '';
  document.getElementById('mgr-notes').value     = '';
  document.getElementById('mgr-tags').value      = '';
  document.getElementById('mgr-modal-title').textContent = 'Add Manager';
  document.getElementById('mgr-pw-hint').style.display  = 'none';
  document.getElementById('mgr-error').style.display    = 'none';
  VaultFX.openModal('modal-manager');
}

function openEditManager(id, serverId) {
  const el = document.getElementById('mgr-accordion-' + id);
  if (!el) return;
  document.getElementById('mgr-id').value        = id;
  document.getElementById('mgr-server-id').value = serverId;
  document.getElementById('mgr-label').value     = el.dataset.label || '';
  document.getElementById('mgr-login').value     = el.dataset.login || '';
  document.getElementById('mgr-password').value  = '';
  document.getElementById('mgr-notes').value     = el.dataset.notes || '';
  document.getElementById('mgr-tags').value      = el.dataset.tags || '';
  document.getElementById('mgr-modal-title').textContent = 'Edit Manager';
  document.getElementById('mgr-pw-hint').style.display   = '';
  document.getElementById('mgr-error').style.display     = 'none';
  VaultFX.openModal('modal-manager');
}

async function saveManager() {
  const id     = document.getElementById('mgr-id').value;
  const action = id === '0' ? 'create' : 'edit';
  const fd     = new FormData(document.getElementById('manager-form'));
  const res    = await VaultFX.postForm('api/managers.php?action=' + action, fd);
  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-manager');
    VaultFX.toast('success', res.data.message);
    setTimeout(() => location.reload(), 600);
  } else {
    const errs = res.data.errors ?? {};
    document.getElementById('mgr-error').textContent = Object.values(errs)[0] || res.data.message || 'Failed to save manager.';
    document.getElementById('mgr-error').style.display = 'block';
  }
}

async function toggleManagerActive(id, currentlyActive) {
  const action  = currentlyActive ? 'deactivate' : 'activate';
  const label   = currentlyActive ? 'Deactivate' : 'Activate';
  const btnClass = currentlyActive ? 'btn-danger' : 'btn-primary';
  const message  = currentlyActive
    ? 'This manager account will be hidden from all users and cannot be revealed until reactivated.'
    : 'This manager account will become visible and accessible again.';

  const ok = await VaultFX.confirm({ title: label + ' Manager', message, confirmText: label, confirmClass: btnClass });
  if (!ok) return;

  const fd = new FormData();
  fd.set('id', id);
  fd.set('action', action);
  const res = await VaultFX.postForm('api/managers.php?action=toggle-active', fd);
  VaultFX.toast(res.data.success ? 'success' : 'error', res.data.message || 'Failed.');
  if (res.data.success) setTimeout(() => location.reload(), 600);
}

async function deleteManager(id) {
  const ok = await VaultFX.confirm({
    title:       'Delete Manager Account',
    message:     'This will deactivate the manager account. Coverage accounts must be removed first.',
    requireTyped: 'DELETE',
    confirmText: 'Delete',
    confirmClass:'btn-danger',
  });
  if (!ok) return;
  const fd = new FormData();
  fd.set('id', id);
  fd.set('confirm', 'DELETE');
  const res = await VaultFX.postForm('api/managers.php?action=delete', fd);
  VaultFX.toast(res.data.success ? 'success' : 'error', res.data.message || 'Failed.');
  if (res.data.success) setTimeout(() => location.reload(), 600);
}

// ── Coverage Add/Edit ─────────────────────────────────────────
function openAddCoverage(managerId, serverId) {
  document.getElementById('cov-id').value          = '0';
  document.getElementById('cov-manager-id').value  = managerId;
  document.getElementById('cov-server-id').value   = serverId;
  document.getElementById('cov-label').value       = '';
  document.getElementById('cov-login').value       = '';
  document.getElementById('cov-password').value    = '';
  document.getElementById('cov-investor-pw').value = '';
  document.getElementById('cov-notes').value       = '';
  document.getElementById('cov-tags').value        = '';
  document.getElementById('cov-modal-title').textContent = 'Add Coverage';
  document.getElementById('cov-pw-hint').style.display   = 'none';
  document.getElementById('cov-error').style.display     = 'none';
  VaultFX.openModal('modal-coverage');
}

function openEditCoverage(id, managerId, serverId) {
  const el = document.querySelector('[data-cov-id="' + id + '"]');
  if (!el) return;
  document.getElementById('cov-id').value          = id;
  document.getElementById('cov-manager-id').value  = managerId;
  document.getElementById('cov-server-id').value   = serverId;
  document.getElementById('cov-label').value       = el.dataset.label || '';
  document.getElementById('cov-login').value       = el.dataset.login || '';
  document.getElementById('cov-password').value    = '';
  document.getElementById('cov-investor-pw').value = '';
  document.getElementById('cov-notes').value       = el.dataset.notes || '';
  document.getElementById('cov-tags').value        = el.dataset.tags || '';
  document.getElementById('cov-modal-title').textContent = 'Edit Coverage';
  document.getElementById('cov-pw-hint').style.display   = '';
  document.getElementById('cov-error').style.display     = 'none';
  VaultFX.openModal('modal-coverage');
}

async function saveCoverage() {
  const id     = document.getElementById('cov-id').value;
  const action = id === '0' ? 'create' : 'edit';
  const fd     = new FormData(document.getElementById('coverage-form'));
  const res    = await VaultFX.postForm('api/coverage.php?action=' + action, fd);
  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-coverage');
    VaultFX.toast('success', res.data.message);
    setTimeout(() => location.reload(), 600);
  } else {
    const errs = res.data.errors ?? {};
    document.getElementById('cov-error').textContent = Object.values(errs)[0] || res.data.message || 'Failed to save coverage.';
    document.getElementById('cov-error').style.display = 'block';
  }
}

async function deleteCoverage(id) {
  const ok = await VaultFX.confirm({
    title:       'Delete Coverage Account',
    message:     'This will deactivate the coverage account.',
    requireTyped: 'DELETE',
    confirmText: 'Delete',
    confirmClass:'btn-danger',
  });
  if (!ok) return;
  const fd = new FormData();
  fd.set('id', id);
  fd.set('confirm', 'DELETE');
  const res = await VaultFX.postForm('api/coverage.php?action=delete', fd);
  VaultFX.toast(res.data.success ? 'success' : 'error', res.data.message || 'Failed.');
  if (res.data.success) setTimeout(() => location.reload(), 600);
}
</script>
