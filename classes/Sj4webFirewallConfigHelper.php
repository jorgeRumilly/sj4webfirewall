<?php
class Sj4webFirewallConfigHelper
{
    protected static $configKeys = [
        'SJ4WEB_FW_WHITELIST_IPS',
        'SJ4WEB_FW_SAFEBOTS',
        'SJ4WEB_FW_MALICIOUSBOTS',
        'SJ4WEB_FW_ENABLE_SLEEP',
        'SJ4WEB_FW_ACTIVATE_FIREWALL',
        'SJ4WEB_FW_SLEEP_DELAY_MS',
        'SJ4WEB_FW_COUNTRIES_BLOCKED',
        'SJ4WEB_FW_SCORE_LIMIT_SLOW',
        'SJ4WEB_FW_BLOCK_DURATION',
        'SJ4WEB_FW_SCORE_LIMIT_BLOCK',
        'SJ4WEB_FW_LOG_ENABLED',
        'SJ4WEB_FW_ALERT_EMAIL_ENABLED',
        'SJ4WEB_FW_ALERT_RECIPIENTS',
        'SJ4WEB_FW_ALERT_THRESHOLD',
        'SJ4WEB_FW_CONTACT_PROTECTION_ENABLED',
        'SJ4WEB_FW_CONTACT_MAX_PER_PERIOD',
        'SJ4WEB_FW_CONTACT_PERIOD_MINUTES',
        'SJ4WEB_FW_CONTACT_MAX_DAILY'
    ];

    protected static $defaults = null;

    public static function getMultilineKeys()
    {
        return [
            'SJ4WEB_FW_WHITELIST_IPS',
            'SJ4WEB_FW_SAFEBOTS',
            'SJ4WEB_FW_MALICIOUSBOTS',
            'SJ4WEB_FW_COUNTRIES_BLOCKED',
        ];
    }

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
            $val = self::$defaults[$key];
            // Si c’est un tableau, on encode avant de stocker
            $storedValue = in_array($key, self::getMultilineKeys(), true) && is_array($val)
                ? json_encode($val)
                : $val;

            Configuration::updateValue($key, $storedValue);
        }

        if (in_array($key, self::getMultilineKeys(), true)) {
            // Cas pathologique : un array a été stocké directement en base
            if (is_array($val)) {
                // On corrige la base immédiatement
                Configuration::updateValue($key, json_encode($val));
                return $val;
            }

            $decoded = json_decode($val, true);
            return is_array($decoded) ? $decoded : [];
        }

        return $val;
    }

    public static function getAll()
    {
        $values = [];
        foreach (self::$configKeys as $key) {
            $values[$key] = self::get($key);
        }
        return $values;
    }

    public static function getKeys()
    {
        return self::$configKeys;
    }
}