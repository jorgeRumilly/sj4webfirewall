<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once dirname(__DIR__) . '/classes/FirewallStorage.php';

/**
 * @param Sj4webFirewall $module
 *
 * @return bool
 */
function upgrade_module_1_5_0($module)
{
    if (!$module->installSchema()) {
        return false;
    }

    $registered = $module->registerHook('actionDispatcherAfter');
    if (!$registered) {
        return false;
    }

    if (!$module->initializeConfigurationValues()) {
        return false;
    }

    if (!$module->synchronizeKnownBotsConfiguration()) {
        return false;
    }

    if (!FirewallStorage::hasRequiredTables()) {
        return false;
    }

    return $module->migrateLegacyJsonStorage();
}
