<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__.'/classes/FirewallGeo.php';
require_once __DIR__.'/classes/FirewallStorage.php';
require_once __DIR__.'/classes/Sj4webFirewallConfigHelper.php';

class Sj4webFirewall extends Module
{
    public function __construct()
    {
        $this->name = 'sj4webfirewall';
        $this->tab = 'administration';
        $this->version = '1.0.0';
        $this->author = 'SJ4WEB.FR';
        $this->need_instance = 0;
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->trans('SJ4WEB Firewall', [], 'Modules.Sj4webfirewall.Admin');
        $this->description = $this->trans('Module de filtrage comportemental, IP, bots et pays.', [], 'Modules.Sj4webfirewall.Admin');
    }

    /**
     * Installation du module : enregistrement des hooks.
     */
    public function install()
    {
        return parent::install() &&
            $this->registerHook('displayBackOfficeHeader') &&
            $this->registerHook('displayBeforeHeader');
    }

    /**
     * Désinstallation du module.
     */
    public function uninstall()
    {
        return parent::uninstall();
    }

    public function getContent()
    {
        Tools::redirectAdmin($this->context->link->getAdminLink('AdminSj4webFirewall'));
    }

    public function hookDisplayBackOfficeHeader()
    {
        if (Tools::getValue('controller') === 'AdminSj4webFirewall') {
            $this->context->controller->addCss($this->_path . 'views/css/sjfirewall_admin.css');
        }
    }


    /**
     * Hook exécuté avant l'affichage de la page : point d'entrée du filtrage.
     */
    public function hookDisplayBeforeHeader()
    {
//        $config = [];
//        foreach (array_keys(require __DIR__.'/config/default_config.php') as $key) {
//            $val = Configuration::get($key);
//            if (is_string($val) && strpos($val, "\n") !== false) {
//                $config[$key] = array_map('trim', explode("\n", $val));
//            } else {
//                $config[$key] = $val;
//            }
//        }

        $config = Sj4webFirewallConfigHelper::getAll();

        // Parser les lignes multiples une seule fois ici si nécessaire :
        foreach (['SJ4WEB_FW_WHITELIST_IPS', 'SJ4WEB_FW_SAFEBOTS', 'SJ4WEB_FW_MALICIOUSBOTS', 'SJ4WEB_FW_COUNTRIES_BLOCKED'] as $key) {
            if (is_string($config[$key]) && strpos($config[$key], "\n") !== false) {
                $config[$key] = array_map('trim', explode("\n", $config[$key]));
            }
        }

        $ip = Tools::getRemoteAddr();
        $userAgent = Tools::getUserAgent();

        $storage = new FirewallStorage(
            (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
            (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
            (int)$config['SJ4WEB_FW_BLOCK_DURATION']
        );

        $status = $storage->getStatusForIp($ip);
        if ($status === 'blocked') {
            $storage->logEvent($ip, 'IP bloquée par score');
            header('HTTP/1.1 403 Forbidden');
            exit('Access denied.');
        }

        // 1. Vérification des IPs autorisées (whitelist)
        if ($this->isIpWhitelisted($ip, $config['SJ4WEB_FW_WHITELIST_IPS'])) {
            return;
        }

        // 2. Laisser passer les bots SEO connus
        if ($this->isKnownSafeBot($userAgent, $config['SJ4WEB_FW_SAFEBOTS'])) {
            return;
        }

        // 3. Blocage immédiat des bots malveillants connus
        if ($this->isMaliciousBot($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
            $storage->updateScore($ip, -20);
            $storage->logEvent($ip, 'bot_suspect');
            $this->logAction($ip, $userAgent, 'bot_suspect');
            header('HTTP/1.1 403 Forbidden');
            exit('Access denied.');
        }

        // 4. Blocage par pays si activé
        $geo = new FirewallGeo();
        $country = $geo->getCountryCode($ip);
        if ($country && in_array($country, $config['SJ4WEB_FW_COUNTRIES_BLOCKED'])) {
            $storage->updateScore($ip, -10);
            $storage->logEvent($ip, 'pays_bloque: ' . $country);
            $this->logAction($ip, $userAgent, 'pays_bloque: ' . $country);
            header('HTTP/1.1 403 Forbidden');
            exit('Access denied by country restriction.');
        }

        // 5. Optionnel : ralentissement doux pour visiteurs suspects
        if ($config['SJ4WEB_FW_ENABLE_SLEEP']) {
            $storage->logEvent($ip, 'ralenti: score faible');
            usleep((int)$config['SJ4WEB_FW_SLEEP_DELAY_MS'] * 1000);
        }
    }

    /**
     * Vérifie si l'IP est autorisée (exacte ou préfixe IPv6).
     */
    protected function isIpWhitelisted($ip, array $allowedList)
    {
        foreach ($allowedList as $allowed) {
            if (strpos($allowed, '/') !== false) {
                if ($this->ipInRange($ip, $allowed)) {
                    return true;
                }
            } elseif ($ip === $allowed) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si l'user-agent appartient à un bot SEO reconnu.
     */
    protected function isKnownSafeBot($userAgent, array $safeBots)
    {
        foreach ($safeBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Vérifie si l'user-agent appartient à un bot malveillant.
     */
    protected function isMaliciousBot($userAgent, array $maliciousBots)
    {
        foreach ($maliciousBots as $bad) {
            if (stripos($userAgent, $bad) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Enregistre une action suspecte dans les logs du module.
     */
    protected function logAction($ip, $userAgent, $reason)
    {
        $log = sprintf("[%s] %s - %s (%s)\n", date('Y-m-d H:i:s'), $ip, $reason, $userAgent);
        $logFile = _PS_MODULE_DIR_.'sj4webfirewall/logs/firewall.log';
        file_put_contents($logFile, $log, FILE_APPEND);
    }

    /**
     * Vérifie si une IP appartient à une plage CIDR.
     */
    protected function ipInRange($ip, $range)
    {
        if (!strpos($range, '/')) return false;
        list($subnet, $bits) = explode('/', $range);
        $ip = ip2long($ip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask;
        return ($ip & $mask) === $subnet;
    }

    public function isUsingNewTranslationSystem()
    {
        return true;
    }
}
