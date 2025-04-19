<?php
class Sj4webFirewallConfigHelper
{
    protected static $configKeys = [
        'SJ4WEB_FW_WHITELIST_IPS',
        'SJ4WEB_FW_SAFEBOTS',
        'SJ4WEB_FW_MALICIOUSBOTS',
        'SJ4WEB_FW_ENABLE_SLEEP',
        'SJ4WEB_FW_SLEEP_DELAY_MS',
        'SJ4WEB_FW_COUNTRIES_BLOCKED',
    ];

    protected static $defaults = null;

    protected static function loadDefaults()
    {
        if (self::$defaults === null) {
            self::$defaults = require _PS_MODULE_DIR_ . 'sj4webfirewall/config/default_config.php';
        }
    }

    public static function get($key)
    {
        self::loadDefaults();
        $val = Configuration::get($key);
        if ($val === false && isset(self::$defaults[$key])) {
            Configuration::updateValue($key, self::$defaults[$key]);
            return self::$defaults[$key];
        }
        return $val;
    }

    public static function getAll()
    {
        $values = [];
        foreach (self::$configKeys as $key) {
            $val = self::get($key);
            $values[$key] = is_array($val) ? implode("\n", $val) : $val;
        }
        return $values;
    }

    public static function getKeys()
    {
        return self::$configKeys;
    }
}