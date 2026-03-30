<?php
/**
 * VaultFX — Footer: closes main content, loads scripts, session monitor
 */
?>
  </main><!-- /.main-content -->
</div><!-- /.app-layout -->

<!-- Session Warning UI -->
<div class="session-warning" id="session-warning">
  <div class="session-warning-title">&#9888; Session Expiring Soon</div>
  <div class="session-warning-msg">Your session will expire due to inactivity in:</div>
  <div class="session-warning-time" id="session-countdown">05:00</div>
  <div style="display:flex;gap:8px">
    <button class="btn btn-primary btn-sm" style="flex:1" onclick="SessionMonitor.extendSession()">Stay Logged In</button>
    <a href="?page=logout" class="btn btn-outline btn-sm">Log Out</a>
  </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toast-container"></div>

<!-- Scripts -->
<script src="assets/js/app.js?v=<?= APP_VERSION ?>"></script>
<script src="assets/js/credentials.js?v=<?= APP_VERSION ?>"></script>
<script src="assets/js/search.js?v=<?= APP_VERSION ?>"></script>
<script src="assets/js/session-monitor.js?v=<?= APP_VERSION ?>"></script>

<?php if (!empty($extraJs)): foreach ($extraJs as $js): ?>
<script src="<?= e($js) ?>?v=<?= APP_VERSION ?>"></script>
<?php endforeach; endif; ?>

<?php if (!empty($inlineJs)): ?>
<script>
<?= $inlineJs ?>
</script>
<?php endif; ?>

<script>
// Initialize Lucide icons
if (window.lucide) lucide.createIcons();
</script>
</body>
</html>
