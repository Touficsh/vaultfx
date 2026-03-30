<?php
/**
 * VaultFX — API Bootstrap
 * ========================
 * Auto-discovers config by walking up the directory tree.
 * Works regardless of where the project is deployed.
 */

if (!defined('VAULTFX_BOOT')) {
    http_response_code(403);
    exit('Forbidden');
}

$_vfxSearchDir = __DIR__;
$_vfxConfig    = null;
for ($i = 0; $i < 6; $i++) {
    $_vfxSearchDir = dirname($_vfxSearchDir);
    if (file_exists($_vfxSearchDir . '/config/config.php')) {
        $_vfxConfig = $_vfxSearchDir . '/config/config.php';
        break;
    }
}
if ($_vfxConfig === null) {
    http_response_code(503);
    exit(json_encode(['success' => false, 'message' => 'Application not configured.']));
}
require_once $_vfxConfig;
unset($_vfxSearchDir, $_vfxConfig, $i);
