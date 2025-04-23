<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__.'/classes/FirewallGeo.php';
require_once __DIR__.'/classes/FirewallStorage.php';
require_once __DIR__.'/classes/Sj4webFirewallConfigHelper.php';
require_once __DIR__.'/classes/FirewallStatsLogger.php';

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
            $this->registerHook('displayHeader');
    }

    /**
     * Désinstallation du module.
     */
    public function uninstall()
    {
        foreach (Sj4webFirewallConfigHelper::getKeys() as $key) {
            Configuration::deleteByName($key);
        }

        return parent::uninstall();
    }

    public function getContent()
    {
        Tools::redirectAdmin($this->context->link->getAdminLink('AdminSj4webFirewall'));
    }

    public function hookDisplayBackOfficeHeader()
    {
        if (Tools::getValue('controller') === 'AdminSj4webFirewall' || Tools::getValue('controller') === 'AdminSj4webFirewallLog') {
            $this->context->controller->addCss($this->_path . 'views/css/sjfirewall_admin.css');
        }
    }


    /**
     * Hook exécuté avant l'affichage de la page : point d'entrée du filtrage.
     */
    public function hookDisplayHeader()
    {

        $config = Sj4webFirewallConfigHelper::getAll();
        $ip = Tools::getRemoteAddr();
        $userAgent = $this->getUserAgent();
         try {
             // Parser les lignes multiples une seule fois ici si nécessaire :
             foreach (['SJ4WEB_FW_WHITELIST_IPS', 'SJ4WEB_FW_SAFEBOTS', 'SJ4WEB_FW_MALICIOUSBOTS', 'SJ4WEB_FW_COUNTRIES_BLOCKED'] as $key) {
                 if (is_string($config[$key]) && strpos($config[$key], "\n") !== false) {
                     $config[$key] = array_map('trim', explode("\n", $config[$key]));
                 }
             }

             $storage = new FirewallStorage(
                 (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
                 (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
                 (int)$config['SJ4WEB_FW_BLOCK_DURATION']
             );

             $is_active_firewall = $config['SJ4WEB_FW_ACTIVATE_FIREWALL'] ?? false;

             // 1. Vérification des IPs autorisées (whitelist)
             if ($this->isIpWhitelisted($ip, $config['SJ4WEB_FW_WHITELIST_IPS'])) {
                 FirewallStatsLogger::logVisit($userAgent, 'human');
                 return '';
             }

             // 2. Vérification des IPs bloquées (blacklist)
             $status = $storage->getStatusForIp($ip);
             if ($status === 'blocked') {
                 $storage->logEvent($ip, 'IP bloquée par score');
                 FirewallStatsLogger::logVisit($userAgent, 'blocked'); // ou 'blocked' si tu veux un type dédié
                if ($is_active_firewall) {
                    header('HTTP/1.1 403 Forbidden');
                    exit('Access denied.');
                } else {
                    return '';
                }
             }

             // 3. Laisser passer les bots SEO connus
             if ($this->isKnownSafeBot($userAgent, $config['SJ4WEB_FW_SAFEBOTS'])) {
                 if (!$storage->has($ip)) {
                     $storage->updateScore($ip, 0);
                 }

                 $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_SAFEBOTS']);
                 $storage->logEvent($ip, 'IP OK - Bot SEO reconnu');
                 $this->logAction($ip, $userAgent, 'safe_bot');
                 FirewallStatsLogger::logVisit($userAgent, 'safe', $botName);
                 return '';
             }

             // 4. Blocage immédiat des bots malveillants connus
             if ($this->isMaliciousBot($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
                 $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS']);
                 $storage->updateScore($ip, -20);
                 $storage->logEvent($ip, 'bot_suspect');
                 $this->logAction($ip, $userAgent, 'bot_suspect');
                 FirewallStatsLogger::logVisit($userAgent, 'bad', $botName);

                 if ($is_active_firewall) {
                     header('HTTP/1.1 403 Forbidden');
                     exit('Access denied.');
                 } else {
                     return '';
                 }
             }

             // 5. Pays bloqué
             $geo = new FirewallGeo();
             $country = $geo->getCountryCode($ip);
             if ($country && in_array($country, $config['SJ4WEB_FW_COUNTRIES_BLOCKED'])) {
                 $storage->updateScore($ip, -10);
                 $storage->logEvent($ip, 'pays_bloque: ' . $country);
                 $this->logAction($ip, $userAgent, 'pays_bloque: ' . $country);
                 FirewallStatsLogger::logVisit($userAgent, 'bad', 'pays:' . $country);
                 if ($is_active_firewall) {
                     header('HTTP/1.1 403 Forbidden');
                     exit('Access denied by country restriction.');
                 }
                 return '';
             }

             // 6. Optionnel : ralentissement doux pour visiteurs suspects
             if ($config['SJ4WEB_FW_ENABLE_SLEEP']) {
                 $storage->logEvent($ip, 'ralenti: score faible');
                 FirewallStatsLogger::logVisit($userAgent, 'human');
                 if ($is_active_firewall) {
                     usleep((int)$config['SJ4WEB_FW_SLEEP_DELAY_MS'] * 1000);
                 } else {
                     return '';
                 }
             }

             FirewallStatsLogger::logVisit($userAgent, 'human');
         } catch (Exception $e) {
             $this->logAction($ip, $userAgent, 'Erreur execution : ' . $e->getMessage());
         }
         return '';
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
//    protected function ipInRange($ip, $range)
//    {
//        if (!strpos($range, '/')) return false;
//        list($subnet, $bits) = explode('/', $range);
//        $ip = ip2long($ip);
//        $subnet = ip2long($subnet);
//        $mask = -1 << (32 - $bits);
//        $subnet &= $mask;
//        return ($ip & $mask) === $subnet;
//    }
    protected function ipInRange($ip, $range)
    {
        if (!strpos($range, '/')) {
            return false;
        }

        [$subnet, $bits] = explode('/', $range);

        $ip_bin = inet_pton($ip);
        $subnet_bin = inet_pton($subnet);

        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }

        $ip_len = strlen($ip_bin); // 4 pour IPv4, 16 pour IPv6
        $bit_max = $ip_len * 8;

        if ($bits > $bit_max) {
            return false;
        }

        $bytes = intdiv($bits, 8);
        $bits_remain = $bits % 8;

        // Compare les octets entiers
        if (strncmp($ip_bin, $subnet_bin, $bytes) !== 0) {
            return false;
        }

        if ($bits_remain === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $bits_remain)) & 0xFF;

        return (ord($ip_bin[$bytes]) & $mask) === (ord($subnet_bin[$bytes]) & $mask);
    }

    protected function getUserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    public function isUsingNewTranslationSystem()
    {
        return true;
    }
}
