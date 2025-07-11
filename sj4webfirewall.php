<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/classes/FirewallGeo.php';
require_once __DIR__ . '/classes/FirewallStorage.php';
require_once __DIR__ . '/classes/Sj4webFirewallConfigHelper.php';
require_once __DIR__ . '/classes/FirewallStatsLogger.php';

class Sj4webFirewall extends Module
{
    public function __construct()
    {
        $this->name = 'sj4webfirewall';
        $this->tab = 'administration';
        $this->version = '1.4.0';
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
            $this->registerHook('displayHeader') &&
            $this->registerHook('actionContactFormSubmitBefore') &&
            $this->installTabs();
    }

    /**
     * Désinstallation du module.
     */
    public function uninstall()
    {
        foreach (Sj4webFirewallConfigHelper::getKeys() as $key) {
            Configuration::deleteByName($key);
        }

        return parent::uninstall() && $this->uninstallTabs();
    }

    public function installTabs()
    {
        // Vérifie si l'onglet parent existe déjà pour éviter doublon
        if (Tab::getIdFromClassName('AdminSj4webFirewallParent')) {
            return true;
        }

        // Onglet parent
        $parentTab = new Tab();
        $parentTab->class_name = 'AdminSj4webFirewallParent';
        $parentTab->module = $this->name;
//        $parentTab->id_parent = 0; // Racine
        $parentTab->id_parent = Tab::getIdFromClassName('IMPROVE'); // Racine
        $parentTab->active = 1;
        $parentTab->icon = 'security'; // Icône de l'onglet

        foreach (Language::getLanguages(false) as $lang) {
            $parentTab->name[$lang['id_lang']] = $this->trans('SJ4WEB Firewall', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$parentTab->add()) {
            return false;
        }

        // Onglet Configuration
        $configTab = new Tab();
        $configTab->class_name = 'AdminSj4webFirewall';
        $configTab->module = $this->name;
        $configTab->id_parent = $parentTab->id;
        $configTab->active = 1;
        $configTab->icon = 'settings'; // Icône de l'onglet

        foreach (Language::getLanguages(false) as $lang) {
            $configTab->name[$lang['id_lang']] = $this->trans('Configuration', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$configTab->add()) {
            return false;
        }

        // Onglet Suivi
        $logTab = new Tab();
        $logTab->class_name = 'AdminSj4webFirewallLog';
        $logTab->module = $this->name;
        $logTab->id_parent = $parentTab->id;
        $logTab->active = 1;
        $logTab->icon = 'track_changes'; // Icône de l'onglet

        foreach (Language::getLanguages(false) as $lang) {
            $logTab->name[$lang['id_lang']] = $this->trans('Real-time tracking', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$logTab->add()) {
            return false;
        }

        // Onglet Logs (futur)
        $statsTab = new Tab();
        $statsTab->class_name = 'AdminSj4webFirewallStats';
        $statsTab->module = $this->name;
        $statsTab->id_parent = $parentTab->id;
        $statsTab->active = 1;
        $statsTab->icon = 'description'; // Icône de l'onglet

        foreach (Language::getLanguages(false) as $lang) {
            $statsTab->name[$lang['id_lang']] = $this->trans('Daily tracking logs', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$statsTab->add()) {
            return false;
        }

        return true;
    }

    public function uninstallTabs()
    {
        foreach (['AdminSj4webFirewallParent', 'AdminSj4webFirewall', 'AdminSj4webFirewallLog', 'AdminSj4webFirewallStats'] as $class_name) {
            $idTab = (int)Tab::getIdFromClassName($class_name);
            if ($idTab) {
                $tab = new Tab($idTab);
                $tab->delete();
            }
        }
        return true;
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

        // Initialisation des variables de travail
        $config = Sj4webFirewallConfigHelper::getAll();

        /** @var $storage FirewallStorage */

        list($ip, $userAgent, $country, $storage) = $this->initWorkingVars($config);

        $is_active_firewall = (bool)$config['SJ4WEB_FW_ACTIVATE_FIREWALL'] ?? false;

        try {
            // Parser les lignes multiples une seule fois ici si nécessaire :
            foreach (['SJ4WEB_FW_WHITELIST_IPS', 'SJ4WEB_FW_SAFEBOTS', 'SJ4WEB_FW_MALICIOUSBOTS', 'SJ4WEB_FW_COUNTRIES_BLOCKED'] as $key) {
                if (is_string($config[$key]) && strpos($config[$key], "\n") !== false) {
                    $config[$key] = array_map('trim', explode("\n", $config[$key]));
                }
            }

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
                $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_SAFEBOTS']);
                $manage_score['log_event_reason'] = 'IP OK - Bot SEO reconnu - ' . $botName;
                $storage->manageStorage($manage_score);
                $this->logAction($ip, $userAgent, 'safe_bot');
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_safe', $botName, $country, 200, $score);
                return '';
            }

            // 4. Blocage immédiat des bots malveillants connus
            if ($this->isMaliciousBot($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
                $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS']);
                $manage_score['log_event_reason'] = 'bot_suspect - ' . $botName;
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
                $manage_score['log_event_reason'] = 'ralenti: score faible';
                $manage_score['update_score'] = false;
                $storage->manageStorage($manage_score);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);
                if ($is_active_firewall) {
                    usleep((int)$config['SJ4WEB_FW_SLEEP_DELAY_MS'] * 1000);
                }
                return '';
            }
            $httpCode = (int)http_response_code();
            $pageRequested = $_SERVER['REQUEST_URI'] ?? 'unknown';

            // Degrade le score si 404 ou 403
            if ($httpCode === 404) {
                $manage_score['score'] = -1;
                $manage_score['log_event_reason'] = 'Erreur 404 : ' . $pageRequested;
                $storage->manageStorage($manage_score);
            }
            if ($httpCode === 403) {
                $manage_score['score'] = -5;
                $manage_score['log_event_reason'] = 'Erreur 403 : ' . $pageRequested;
                $storage->manageStorage($manage_score);
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
        $logFile = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/firewall.log';
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

    /**
     * Récupère l'user-agent du visiteur.
     * Utilisé pour le filtrage et la journalisation.
     *
     * @return string
     */
    protected function getUserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    /**
     * Hook exécuté avant la soumission du formulaire de contact.
     * Permet de filtrer les soumissions de formulaire de contact pour éviter le spam.
     *
     * @param array $params
     */
    public function hookActionContactFormSubmitBefore(array $params)
    {

        $config = Sj4webFirewallConfigHelper::getAll();
        $is_contact_protection_enabled = (bool)$config['SJ4WEB_FW_CONTACT_PROTECTION_ENABLED'] ?? false;

        if ($this->context->customer->isLogged() || !$is_contact_protection_enabled) {
            return; // Pas de limite pour les utilisateurs connectés ou si la protection est désactivée
        }

        $ts = Tools::getValue('sj4web_fw_ts');
        $token = Tools::getValue('sj4web_fw_token');
        /** @var $storage FirewallStorage */
        list($ip, $userAgent, $country, $storage) = $this->initWorkingVars($config);

        // 1. Honeypot
        if (!empty($token)) {
            $storage->logEvent($ip, 'contact_blocked: honeypot');
            $storage->blockIp($ip);
            die();
        }

        // 2. Timer
        if (!$ts || (time() - (int)$ts < 5)) {
            $storage->logEvent($ip, 'contact_blocked: timer < 5s');
            $storage->blockIp($ip);
            die();
        }

        // 3. Limite personnalisée
        $max = (int)$config['SJ4WEB_FW_CONTACT_MAX_PER_PERIOD'];
        $minutes = (int)$config['SJ4WEB_FW_CONTACT_PERIOD_MINUTES'];
        $maxDaily = (int)$config['SJ4WEB_FW_CONTACT_MAX_DAILY'];

        $recentAttempts = $storage->getContactAttemptsInLastXMinutes($ip, $minutes);
        $dailyAttempts = $storage->getDailyContactAttempts($ip);

        if ($dailyAttempts >= $maxDaily) {
            $storage->logEvent($ip, 'contact_blocked: spam (daily limit)');
            $storage->blockIp($ip);
            $message_text = $this->trans('Maximum number of contact form messages reached for today: %d.', [$maxDaily], 'Modules.Sj4webfirewall.Shop');
            FirewallMailer::sendAlert($ip, $userAgent, 0, $country, $message_text);
            $msg = $this->trans(
                'You have reached the maximum number of contact form messages allowed for today. Due to spam suspicion, your IP has been blocked.',
                [],
                'Modules.Sj4webfirewall.Shop'
            );
            $this->context->controller->errors[] = $msg;
            return;
        }

        if ($recentAttempts >= $max) {
            $msg = $this->trans(
                'You have reached the maximum number of contact form messages allowed in this period. Please try again later.',
                [],
                'Modules.Sj4webfirewall.Shop'
            );
            $this->context->controller->errors[] = $msg;
            return;
        }

        // 4. Tout est OK
        $storage->incrementHourlyContactAttempt($ip);
    }

    /**
     * @param string $ip
     * @param $userAgent
     * @return string|null
     */
    public function getCountry(string $ip, $userAgent = null): ?string
    {
        $geo = new FirewallGeo();
        $country = null;
        try {
            $country = $geo->getCountryCode($ip) ?: 'null';
        } catch (Exception $e) {
            $this->logAction($ip, $userAgent ?: 'N/A', 'Erreur de récupération de la configuration : ' . $e->getMessage());
        }
        return $country;
    }

    /**
     * Initialise les variables de travail pour le FirewallStorage
     * Permet d'initialiser $ip, $userAgent, $country et $storage.
     * @param null $config
     * @return array
     */
    public function initWorkingVars($config = null): array
    {
        if ($config === null) {
            $config = Sj4webFirewallConfigHelper::getAll();
        }
        $ip = $this->getIp();
        $userAgent = $this->getUserAgent();

        //Recupère le pays de l'IP
        $country = $this->getCountry($ip, $userAgent);

        $storage = new FirewallStorage(
            (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
            (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
            (int)$config['SJ4WEB_FW_BLOCK_DURATION'],
            (int)$config['SJ4WEB_FW_ALERT_THRESHOLD'],
            $userAgent,
            $country,
            (bool)$config['SJ4WEB_FW_ALERT_EMAIL_ENABLED']
        );
        return array($ip, $userAgent, $country, $storage);
    }

    protected function getIp() {
        $ip = Tools::getRemoteAddr();
        return $ip;
    }

    public function isUsingNewTranslationSystem()
    {
        return true;
    }

}
