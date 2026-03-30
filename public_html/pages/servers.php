<?php
/**
 * VaultFX — Servers List Page
 * Accordion tree: Server → Managers → Coverage Accounts
 */

$pageTitle = 'Servers';
$serverIdsSql = RBAC::accessibleServerIdsSql();

// Load all accessible servers with counts
$servers = DB::rows(
    "SELECT s.*, u.username AS created_by_name,
            COUNT(DISTINCT ma.id) AS manager_count,
            COUNT(DISTINCT ca.id) AS coverage_count
     FROM servers s
     LEFT JOIN users u ON u.id = s.created_by
     LEFT JOIN manager_accounts ma ON ma.server_id = s.id AND ma.is_active = 1
     LEFT JOIN coverage_accounts ca ON ca.server_id = s.id AND ca.is_active = 1
     WHERE s.id IN {$serverIdsSql} AND s.is_active = 1
     GROUP BY s.id
     ORDER BY s.name ASC"
);

include WEB_ROOT . '/includes/header.php';
?>

<div class="page-header">
  <div>
    <h1 class="page-title">Trading Servers</h1>
    <p class="page-subtitle"><?= e(count($servers)) ?> server<?= count($servers) !== 1 ? 's' : '' ?> accessible</p>
  </div>
  <?php if (RBAC::canManageServers()): ?>
  <div class="page-header-actions">
    <button class="btn btn-primary" onclick="openAddServer()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
      Add Server
    </button>
  </div>
  <?php endif; ?>
</div>

<!-- Search & Filter bar -->
<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:center">
  <div style="position:relative;flex:1;min-width:220px;max-width:360px">
    <svg style="position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text-muted);pointer-events:none" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
    <input type="text" id="manager-search" class="form-control" placeholder="Search by manager name or login…"
           style="padding-left:32px" oninput="onSearchInput(this.value)" autocomplete="off">
  </div>
  <input type="text" id="server-filter" class="form-control" placeholder="Filter servers by name or tags…" style="max-width:260px" oninput="filterServers()">
  <select id="platform-filter" class="form-control" style="max-width:150px" onchange="filterServers()">
    <option value="">All Platforms</option>
    <option value="MT4">MT4</option>
    <option value="MT5">MT5</option>
    <option value="cTrader">cTrader</option>
    <option value="DXtrade">DXtrade</option>
    <option value="Other">Other</option>
  </select>
</div>

<!-- Manager search results (shown only when searching) -->
<div id="search-results" style="display:none;margin-bottom:20px">
  <div class="card">
    <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">
      <span style="font-size:0.8rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em">Search Results</span>
      <span id="search-count" class="text-sm text-muted"></span>
    </div>
    <div id="search-results-body" style="padding:8px 0"></div>
  </div>
</div>

<!-- Server List -->
<div id="servers-list">
<?php if (empty($servers)): ?>
  <div class="card">
    <div class="empty-state">
      <svg class="empty-state-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
        <line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line>
      </svg>
      <div class="empty-state-title">No servers available</div>
      <div class="empty-state-desc">
        <?= RBAC::canManageServers() ? 'Click "Add Server" to create your first trading server.' : 'Contact an administrator to grant you server access.' ?>
      </div>
    </div>
  </div>
<?php else: ?>
<?php foreach ($servers as $server):
    $tags = parse_tags($server['tags']);
?>
<div class="accordion-item server-item"
     data-name="<?= e(strtolower($server['name'])) ?>"
     data-platform="<?= e($server['platform_type']) ?>"
     data-tags="<?= e(strtolower($server['tags'] ?? '')) ?>">

  <div class="accordion-header">
    <svg class="accordion-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
      <polyline points="9 18 15 12 9 6"></polyline>
    </svg>
    <span class="badge <?= e(platform_badge_class($server['platform_type'])) ?>"><?= e($server['platform_type']) ?></span>
    <div style="flex:1;min-width:0">
      <div style="font-weight:600;font-size:0.95rem"><?= e($server['name']) ?></div>
      <?php if ($server['ip_address']): ?>
      <div style="font-size:0.78rem;color:var(--text-muted);font-family:monospace"><?= e($server['ip_address']) ?></div>
      <?php endif; ?>
    </div>
    <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
      <?php if (!empty($tags)): ?>
      <div class="tag-list" style="max-width:200px">
        <?php foreach (array_slice($tags, 0, 3) as $tag): ?>
        <span class="tag"><?= e($tag) ?></span>
        <?php endforeach; ?>
      </div>
      <?php endif; ?>
      <div style="font-size:0.78rem;color:var(--text-secondary);white-space:nowrap">
        <?= e($server['manager_count']) ?> manager · <?= e($server['coverage_count']) ?> coverage
      </div>
      <?php if (RBAC::canManageServers()): ?>
      <div style="display:flex;gap:4px">
        <button class="btn btn-ghost btn-icon btn-sm" title="Edit server"
          onclick="event.stopPropagation();openEditServer(<?= (int)$server['id'] ?>)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
          </svg>
        </button>
      </div>
      <?php endif; ?>
      <a href="?page=server-detail&id=<?= (int)$server['id'] ?>" class="btn btn-outline btn-sm"
         onclick="event.stopPropagation()">
        Detail
      </a>
    </div>
  </div>

  <div class="accordion-body">
    <div id="managers-<?= (int)$server['id'] ?>" style="padding:8px">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 12px 8px">
        <span style="font-size:0.8rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em">Manager Accounts</span>
        <?php if (RBAC::canManageManagers()): ?>
        <button class="btn btn-ghost btn-sm" onclick="openAddManager(<?= (int)$server['id'] ?>)">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
          Add Manager
        </button>
        <?php endif; ?>
      </div>
      <div class="skeleton-list" id="mgr-list-<?= (int)$server['id'] ?>" style="padding:0 4px 8px">
        <!-- Loaded by JS on accordion open -->
        <div class="text-muted text-sm" style="padding:12px;text-align:center">Click to load accounts…</div>
      </div>
    </div>
  </div>

</div>
<?php endforeach; ?>
<?php endif; ?>
</div>

<!-- Add/Edit Server Modal -->
<div class="modal-overlay" id="modal-server">
  <div class="modal">
    <div class="modal-header">
      <h3 class="modal-title" id="server-modal-title">Add Server</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-server')">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <form id="server-form" autocomplete="off">
        <input type="hidden" id="server-id" name="id" value="0">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Server Name <span class="required">*</span></label>
            <input type="text" id="server-name" name="name" class="form-control" maxlength="255" required autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Platform <span class="required">*</span></label>
            <select id="server-platform" name="platform_type" class="form-control">
              <option value="MT4">MT4</option>
              <option value="MT5">MT5</option>
              <option value="cTrader">cTrader</option>
              <option value="DXtrade">DXtrade</option>
              <option value="Other">Other</option>
            </select>
          </div>
        </div>
        <div class="form-group mt-4">
          <label class="form-label">IP Address / Hostname</label>
          <input type="text" id="server-ip" name="ip_address" class="form-control" maxlength="255" placeholder="192.168.1.1 or trade.example.com" autocomplete="off">
        </div>
        <div class="form-group mt-4">
          <label class="form-label">Tags <span class="form-hint">(comma-separated)</span></label>
          <input type="text" id="server-tags" name="tags" class="form-control" maxlength="500" placeholder="Production, Live, Client-A" autocomplete="off">
        </div>
        <div class="form-group mt-4">
          <label class="form-label">Notes</label>
          <textarea id="server-notes" name="notes" class="form-control" maxlength="5000" rows="3"></textarea>
        </div>
        <div id="server-error" class="form-error mt-2" style="display:none"></div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-server')">Cancel</button>
      <button class="btn btn-primary" onclick="saveServer()">
        <span id="server-save-label">Save Server</span>
      </button>
    </div>
  </div>
</div>

<!-- Add Manager Modal -->
<div class="modal-overlay" id="modal-manager">
  <div class="modal">
    <div class="modal-header">
      <h3 class="modal-title" id="manager-modal-title">Add Manager Account</h3>
      <button class="modal-close" onclick="VaultFX.closeModal('modal-manager')">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
    </div>
    <div class="modal-body">
      <form id="manager-form" autocomplete="off">
        <input type="hidden" id="manager-id" name="id" value="0">
        <input type="hidden" id="manager-server-id" name="server_id" value="0">
        <div class="form-grid">
          <div class="form-group">
            <label class="form-label">Label / Alias <span class="required">*</span></label>
            <input type="text" id="manager-label" name="label" class="form-control" maxlength="100" required autocomplete="off">
          </div>
          <div class="form-group">
            <label class="form-label">Login Number <span class="required">*</span></label>
            <input type="text" id="manager-login" name="login_number" class="form-control" maxlength="20" required autocomplete="off" inputmode="numeric">
          </div>
        </div>
        <div class="form-group mt-4">
          <label class="form-label">Password <span class="required">*</span></label>
          <div class="password-field">
            <input type="password" id="manager-password" name="password" class="form-control" maxlength="500" autocomplete="new-password">
            <button type="button" class="password-toggle" onclick="toggleField('manager-password')">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
            </button>
          </div>
          <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
            <button type="button" class="btn btn-ghost btn-sm" onclick="generateAndFill('manager-password')">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path></svg>
              Generate
            </button>
          </div>
        </div>
        <div class="form-group mt-4">
          <label class="form-label">Tags</label>
          <input type="text" id="manager-tags" name="tags" class="form-control" maxlength="500" placeholder="Live, Primary" autocomplete="off">
        </div>
        <div class="form-group mt-4">
          <label class="form-label">Notes</label>
          <textarea id="manager-notes" name="notes" class="form-control" rows="2" maxlength="5000"></textarea>
        </div>
        <div id="manager-error" class="form-error mt-2" style="display:none"></div>
      </form>
    </div>
    <div class="modal-footer">
      <button class="btn btn-outline" onclick="VaultFX.closeModal('modal-manager')">Cancel</button>
      <button class="btn btn-primary" onclick="saveManager()">Save Manager Account</button>
    </div>
  </div>
</div>

<?php
$inlineJs = <<<'JS'

// ── Server Accordion lazy-load ────────────────────────────────
const loadedManagers = new Set();

document.querySelectorAll('.accordion-header').forEach(header => {
  header.addEventListener('click', () => {
    const item     = header.closest('.accordion-item');
    const isOpen   = item.classList.contains('open');
    const serverId = item.querySelector('[id^="managers-"]')?.id?.split('-')[1];

    if (isOpen || !serverId || loadedManagers.has(serverId)) return;
    loadManagers(serverId);
  });
});

async function loadManagers(serverId) {
  const container = document.getElementById(`mgr-list-${serverId}`);
  VaultFX.showSkeleton(container, 2);

  const res  = await VaultFX.fetch(`api/managers.php?action=list&server_id=${serverId}`);
  loadedManagers.add(serverId);

  if (!res.ok || !res.data.success) {
    container.innerHTML = `<div class="text-muted text-sm" style="padding:12px;text-align:center">Failed to load accounts.</div>`;
    return;
  }

  const managers = res.data.data.managers;
  if (!managers.length) {
    container.innerHTML = `<div class="text-muted text-sm" style="padding:12px;text-align:center">No manager accounts on this server.</div>`;
    return;
  }

  container.innerHTML = managers.map(m => `
    <div class="manager-row" style="border:1px solid var(--border);border-radius:8px;margin-bottom:6px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--bg-raised)">
        <span style="font-weight:600;font-size:0.875rem">${VaultFX.escapeHtml(m.label)}</span>
        <span class="font-mono text-sm text-muted">${VaultFX.escapeHtml(m.login_number)}</span>
        <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
          ${m.can_reveal ? Credentials.buildRevealHtml('manager', m.id, true) : Credentials.buildRevealHtml('manager', m.id, false)}
        </div>
      </div>
      ${m.coverage_count > 0 ? `<div style="padding:6px 12px 8px;font-size:0.78rem;color:var(--text-muted)">${m.coverage_count} coverage account${m.coverage_count > 1 ? 's' : ''} — <a href="?page=server-detail&id=${m.server_id}&manager=${m.id}">View Detail</a></div>` : ''}
    </div>
  `).join('');
}

// ── Server CRUD ───────────────────────────────────────────────
function openAddServer() {
  document.getElementById('server-id').value    = '0';
  document.getElementById('server-name').value  = '';
  document.getElementById('server-ip').value    = '';
  document.getElementById('server-platform').value = 'MT4';
  document.getElementById('server-tags').value  = '';
  document.getElementById('server-notes').value = '';
  document.getElementById('server-modal-title').textContent = 'Add Server';
  document.getElementById('server-save-label').textContent  = 'Save Server';
  document.getElementById('server-error').style.display = 'none';
  VaultFX.openModal('modal-server');
}

function openEditServer(id) {
  // Fetch server data and populate form
  VaultFX.fetch(`api/servers.php?action=list`).then(res => {
    if (!res.ok) return;
    const server = res.data.data.servers.find(s => s.id == id);
    if (!server) return;
    document.getElementById('server-id').value    = server.id;
    document.getElementById('server-name').value  = server.name;
    document.getElementById('server-ip').value    = server.ip_address ?? '';
    document.getElementById('server-platform').value = server.platform_type;
    document.getElementById('server-tags').value  = server.tags ?? '';
    document.getElementById('server-notes').value = server.notes ?? '';
    document.getElementById('server-modal-title').textContent = 'Edit Server';
    document.getElementById('server-save-label').textContent  = 'Update Server';
    document.getElementById('server-error').style.display = 'none';
    VaultFX.openModal('modal-server');
  });
}

async function saveServer() {
  const id  = document.getElementById('server-id').value;
  const fd  = new FormData(document.getElementById('server-form'));
  const action = id === '0' ? 'create' : 'edit';

  const res = await VaultFX.postForm(`api/servers.php?action=${action}`, fd);
  const errEl = document.getElementById('server-error');

  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-server');
    VaultFX.toast('success', res.data.message);
    setTimeout(() => location.reload(), 500);
  } else {
    errEl.textContent = res.data.message ?? 'Failed to save server.';
    errEl.style.display = 'block';
  }
}

// ── Manager CRUD ──────────────────────────────────────────────
function openAddManager(serverId) {
  document.getElementById('manager-id').value        = '0';
  document.getElementById('manager-server-id').value = serverId;
  document.getElementById('manager-label').value     = '';
  document.getElementById('manager-login').value     = '';
  document.getElementById('manager-password').value  = '';
  document.getElementById('manager-tags').value      = '';
  document.getElementById('manager-notes').value     = '';
  document.getElementById('manager-modal-title').textContent = 'Add Manager Account';
  document.getElementById('manager-error').style.display = 'none';
  VaultFX.openModal('modal-manager');
}

async function saveManager() {
  const id     = document.getElementById('manager-id').value;
  const fd     = new FormData(document.getElementById('manager-form'));
  const action = id === '0' ? 'create' : 'edit';

  const res  = await VaultFX.postForm(`api/managers.php?action=${action}`, fd);
  const errEl = document.getElementById('manager-error');

  if (res.ok && res.data.success) {
    VaultFX.closeModal('modal-manager');
    VaultFX.toast('success', res.data.message);
    const serverId = document.getElementById('manager-server-id').value;
    loadedManagers.delete(serverId);
    loadManagers(serverId);
  } else {
    const errors = res.data.errors ?? {};
    const firstErr = Object.values(errors)[0] || res.data.message || 'Validation failed.';
    errEl.textContent = firstErr;
    errEl.style.display = 'block';
  }
}

// ── Utilities ─────────────────────────────────────────────────
function toggleField(id) {
  const f = document.getElementById(id);
  if (f) f.type = f.type === 'password' ? 'text' : 'password';
}

async function generateAndFill(targetId) {
  const res = await VaultFX.fetch('api/managers.php?action=generate-password&length=20');
  if (res.ok && res.data.success) {
    const input = document.getElementById(targetId);
    if (input) { input.value = res.data.data.password; input.type = 'text'; }
  }
}

// ── Server filter (client-side) ───────────────────────────────
function filterServers() {
  const q  = document.getElementById('server-filter').value.toLowerCase();
  const pl = document.getElementById('platform-filter').value;

  document.querySelectorAll('.server-item').forEach(item => {
    const name = item.dataset.name ?? '';
    const tags = item.dataset.tags ?? '';
    const plat = item.dataset.platform ?? '';

    const matchQ  = !q || name.includes(q) || tags.includes(q);
    const matchPl = !pl || plat === pl;

    item.style.display = matchQ && matchPl ? '' : 'none';
  });
}

// ── Manager search (server-side, debounced) ───────────────────
let _searchTimer = null;

function onSearchInput(value) {
  clearTimeout(_searchTimer);
  const q = value.trim();

  if (q.length < 2) {
    document.getElementById('search-results').style.display = 'none';
    return;
  }

  _searchTimer = setTimeout(() => searchManagers(q), 280);
}

async function searchManagers(q) {
  const resultsBox  = document.getElementById('search-results');
  const resultsBody = document.getElementById('search-results-body');
  const countEl     = document.getElementById('search-count');

  resultsBody.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:0.875rem">Searching…</div>';
  resultsBox.style.display = '';

  const res = await VaultFX.fetch(`api/managers.php?action=search&q=${encodeURIComponent(q)}`);

  if (!res.ok || !res.data.success) {
    resultsBody.innerHTML = '<div style="padding:16px;color:var(--text-muted);font-size:0.875rem">Search failed.</div>';
    return;
  }

  const managers = res.data.data.managers;
  countEl.textContent = managers.length ? `${managers.length} result${managers.length !== 1 ? 's' : ''}` : '';

  if (!managers.length) {
    resultsBody.innerHTML = '<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:0.875rem">No managers found matching that name or login.</div>';
    return;
  }

  // Group by server
  const byServer = {};
  managers.forEach(m => {
    const key = m.server_id;
    if (!byServer[key]) byServer[key] = { name: m.server_name, platform: m.platform_type, id: m.server_id, items: [] };
    byServer[key].items.push(m);
  });

  resultsBody.innerHTML = Object.values(byServer).map(group => `
    <div style="padding:8px 16px 4px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="font-size:0.75rem;font-weight:700;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.06em">${VaultFX.escapeHtml(group.name)}</span>
        <span class="badge badge-${group.platform.toLowerCase()}">${VaultFX.escapeHtml(group.platform)}</span>
      </div>
      ${group.items.map(m => `
        <a href="?page=server-detail&id=${m.server_id}" style="display:flex;align-items:center;gap:12px;padding:9px 12px;border-radius:8px;background:var(--bg-raised);border:1px solid var(--border);margin-bottom:6px;text-decoration:none;color:inherit;transition:border-color 0.15s" onmouseover="this.style.borderColor='var(--primary)'" onmouseout="this.style.borderColor='var(--border)'">
          <span style="font-weight:600;font-size:0.875rem">${VaultFX.escapeHtml(m.label)}</span>
          <span class="font-mono text-sm text-muted">${VaultFX.escapeHtml(m.login_number)}</span>
          <svg style="margin-left:auto;color:var(--text-muted)" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="9 18 15 12 9 6"></polyline></svg>
        </a>
      `).join('')}
    </div>
  `).join('<div style="height:4px"></div>');
}
JS;
?>

<?php include WEB_ROOT . '/includes/footer.php'; ?>
