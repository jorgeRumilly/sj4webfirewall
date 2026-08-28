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
        'SJ4WEB_FW_STATE_RETENTION_DAYS',
        'SJ4WEB_FW_EVENT_RETENTION_DAYS',
        'SJ4WEB_FW_CONTACT_RETENTION_DAYS',
        'SJ4WEB_FW_STATS_RETENTION_DAYS',
        'SJ4WEB_FW_LAST_CLEANUP_AT',
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

    /**
     * Ecrit un fichier PHP plat (pays bloques + whitelist) lisible sans DB ni
     * kernel PrestaShop, pour permettre un blocage geographique tout en amont
     * (index.php, avant meme le cache de pages) - mesure temporaire en
     * attendant Cloudflare ou un serveur dedie. A appeler apres chaque
     * sauvegarde du formulaire d'admin (SJ4WEB_FW_COUNTRIES_BLOCKED /
     * SJ4WEB_FW_WHITELIST_IPS) pour que le cache reste synchronise.
     *
     * Ecriture atomique (fichier temporaire + rename) pour ne jamais laisser
     * index.php lire un fichier a moitie ecrit.
     */
    public static function writeCountryBlockCache()
    {
        // Filet de securite : re-eclate au cas ou une entree contiendrait encore des virgules
        // (ex: config modifiee autrement que par le formulaire d'admin, qui fait deja ce travail
        // en amont) - constat du 15/08/2026, une liste "RU, BR, SG" tapee sur une seule ligne
        // finissait comme une seule entree, qui ne matchait jamais aucun code ISO individuel.
        $countries = [];
        foreach ((array) self::get('SJ4WEB_FW_COUNTRIES_BLOCKED') as $raw) {
            foreach (preg_split('/[\r\n,]+/', (string) $raw) as $c) {
                $countries[] = strtoupper(trim($c));
            }
        }
        $countries = array_values(array_unique(array_filter($countries, function ($c) {
            return $c !== '';
        })));

        $whitelist = array_map('trim', (array) self::get('SJ4WEB_FW_WHITELIST_IPS'));
        $whitelist = array_values(array_filter($whitelist, function ($ip) {
            return $ip !== '';
        }));

        $payload = [
            'generated_at' => date('Y-m-d H:i:s'),
            'countries' => $countries,
            'whitelist' => $whitelist,
        ];

        $geoDir = _PS_MODULE_DIR_ . 'sj4webfirewall/geo';
        if (!is_dir($geoDir)) {
            @mkdir($geoDir, 0755, true);
        }

        $cacheFile = $geoDir . '/country_block_cache.php';
        $tmpFile = $geoDir . '/.country_block_cache.tmp';

        $written = @file_put_contents($tmpFile, '<?php return ' . var_export($payload, true) . ";\n");
        if ($written === false) {
            return false;
        }

        return @rename($tmpFile, $cacheFile);
    }
}
