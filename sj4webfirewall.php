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
        $this->version = '1.1.0';
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

             $is_active_firewall = (bool)$config['SJ4WEB_FW_ACTIVATE_FIREWALL'] ?? false;
             $geo = new FirewallGeo();
             $country = $geo->getCountryCode($ip);

             $storage = new FirewallStorage(
                 (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
                 (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
                 (int)$config['SJ4WEB_FW_BLOCK_DURATION'],
                 (int)$config['SJ4WEB_FW_ALERT_THRESHOLD'],
                $userAgent,
                 $country,
                 (bool)$config['SJ4WEB_FW_ALERT_EMAIL_ENABLED']
             );
             $score = $storage->getScore($ip);

             // 1. Vérification des IPs autorisées (whitelist)
             if ($this->isIpWhitelisted($ip, $config['SJ4WEB_FW_WHITELIST_IPS'])) {
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);
                 return '';
             }

             $manage_score = [
                 'ip' => $ip,
                 'log_event_reason' => '',
                 'score' => 0,
                 'update_score' => true];

             // 2. Vérification des IPs bloquées (blacklist)
             $status = $storage->getStatusForIp($ip);
             if ($status === 'blocked') {
                 $manage_score['log_event_reason'] = 'IP bloquée par score';
                 $manage_score['update_score'] = false;
                 $storage->manageStorage($manage_score);
//                 $storage->logEvent($ip, 'IP bloquée par score');
//                 $storage->incrementVisit($ip);
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'blocked', null, $country, 403, $score);
                if ($is_active_firewall) {
                    header('HTTP/1.1 403 Forbidden');
                    exit('Access denied.');
                } else {
                    return '';
                }
             }

             // 3. Laisser passer les bots SEO connus
             if ($this->isKnownSafeBot($userAgent, $config['SJ4WEB_FW_SAFEBOTS'])) {
//                 if (!$storage->has($ip)) {
//                     $storage->updateScore($ip, 0);
//                 }
                 $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_SAFEBOTS']);
                 $manage_score['log_event_reason'] ='IP OK - Bot SEO reconnu - ' . $botName;
//                 $storage->logEvent($ip, 'IP OK - Bot SEO reconnu - ' . $botName);
//                 $storage->incrementVisit($ip);
                 $storage->manageStorage($manage_score);
                 $this->logAction($ip, $userAgent, 'safe_bot');
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_safe', $botName, $country, 200, $score);
                 return '';
             }

             // 4. Blocage immédiat des bots malveillants connus
             if ($this->isMaliciousBot($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
                 $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS']);
//                 $storage->updateScore($ip, -20);
//                 $storage->logEvent($ip, 'bot_suspect - ' . $botName);
//                 $storage->incrementVisit($ip);
                 $manage_score['log_event_reason'] ='bot_suspect - ' . $botName;
                 $manage_score['score'] = -20;
                 $storage->manageStorage($manage_score);
                 $this->logAction($ip, $userAgent, 'bot_suspect');
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', $botName, $country, 403, $score);
                 if ($is_active_firewall) {
                     header('HTTP/1.1 403 Forbidden');
                     exit('Access denied.');
                 } else {
                     return '';
                 }
             }

             // 5. Pays bloqué
             if ($country && in_array($country, $config['SJ4WEB_FW_COUNTRIES_BLOCKED'])) {
//                 $storage->updateScore($ip, -10);
//                 $storage->incrementVisit($ip);
//                 $storage->logEvent($ip, 'pays_bloque: ' . $country);
                 $manage_score['log_event_reason'] = 'pays_bloque: ' . $country;
                 $manage_score['score'] = -10;
                 $storage->manageStorage($manage_score);

                 $this->logAction($ip, $userAgent, 'pays_bloque: ' . $country);
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', 'pays:' . $country, $country, 403, $score);
                 if ($is_active_firewall) {
                     header('HTTP/1.1 403 Forbidden');
                     exit('Access denied by country restriction.');
                 }
                 return '';
             }

             // 6. Optionnel : ralentissement doux pour visiteurs suspects
             if ($config['SJ4WEB_FW_ENABLE_SLEEP'] && $score <= $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
//                 $storage->logEvent($ip, 'ralenti: score faible');
//                 $storage->incrementVisit($ip);
                 $manage_score['log_event_reason'] = 'ralenti: score faible';
                 $manage_score['updateScore'] = false;
                 $storage->manageStorage($manage_score);
                 FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);
                 if ($is_active_firewall) {
                     usleep((int)$config['SJ4WEB_FW_SLEEP_DELAY_MS'] * 1000);
                 }
                 return '';
             }
             $httpCode = (int)http_response_code();
             // Degrade le score si 404 ou 403
             if ($httpCode === 404) {
                 $storage->updateScore($ip, -1);
             }
             if ($httpCode === 403) {
                 $storage->updateScore($ip, -5);
             }
             FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, $httpCode, $score);

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
