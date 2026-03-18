<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/classes/FirewallGeo.php';
require_once __DIR__ . '/classes/FirewallStorage.php';
require_once __DIR__ . '/classes/Sj4webFirewallConfigHelper.php';
require_once __DIR__ . '/classes/Sj4webFirewallUserAgentMatcher.php';
require_once __DIR__ . '/classes/FirewallStatsLogger.php';

class Sj4webFirewall extends Module
{
    /**
     * Contexte de tracking reporte a la fin de la requete pour recuperer
     * le vrai code HTTP (404/403) une fois le controller execute.
     *
     * @var array<string, mixed>|null
     */
    protected $deferredRequestTracking;

    public function __construct()
    {
        $this->name = 'sj4webfirewall';
        $this->tab = 'administration';
        $this->version = '1.5.0';
        $this->author = 'SJ4WEB.FR';
        $this->need_instance = 0;
        $this->bootstrap = true;

        parent::__construct();

        $this->displayName = $this->trans('SJ4WEB - Firewall', [], 'Modules.Sj4webfirewall.Admin');
        $this->description = $this->trans('Module de filtrage comportemental, IP, bots et pays.', [], 'Modules.Sj4webfirewall.Admin');
    }

    /**
     * Installation du module et de sa persistance SQL.
     */
    public function install()
    {
        return parent::install()
            && $this->installSchema()
            && $this->initializeConfigurationValues()
            && $this->synchronizeKnownBotsConfiguration()
            && $this->registerHook('displayBackOfficeHeader')
            && $this->registerHook('displayHeader')
            && $this->registerHook('actionDispatcherAfter')
            && $this->registerHook('actionContactFormSubmitBefore')
            && $this->installTabs();
    }

    /**
     * Desinstallation complete du module.
     */
    public function uninstall()
    {
        foreach (Sj4webFirewallConfigHelper::getKeys() as $key) {
            Configuration::deleteByName($key);
        }

        return $this->uninstallTabs()
            && $this->uninstallSchema()
            && parent::uninstall();
    }

    /**
     * Installe les tables SQL utilisees par le module.
     */
    public function installSchema()
    {
        return $this->executeSqlFile(__DIR__ . '/sql/install.sql')
            && FirewallStorage::hasRequiredTables();
    }

    /**
     * Supprime les tables SQL du module.
     */
    public function uninstallSchema()
    {
        return $this->executeSqlFile(__DIR__ . '/sql/uninstall.sql');
    }

    /**
     * Initialise les valeurs de configuration manquantes.
     */
    public function initializeConfigurationValues()
    {
        $defaults = require __DIR__ . '/config/default_config.php';
        foreach ($defaults as $key => $value) {
            if (Configuration::get($key) !== false) {
                continue;
            }

            if (in_array($key, Sj4webFirewallConfigHelper::getMultilineKeys(), true) && is_array($value)) {
                $value = json_encode($value);
            }

            Configuration::updateValue($key, $value);
        }

        return true;
    }

    /**
     * Nettoie les listes legacy et ajoute les bots safe indispensables.
     */
    public function synchronizeKnownBotsConfiguration()
    {
        $safeBots = (array) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_SAFEBOTS');
        $maliciousBots = (array) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_MALICIOUSBOTS');

        $safeBots = Sj4webFirewallUserAgentMatcher::mergeRecommendedSafeBots($safeBots);
        $maliciousBots = Sj4webFirewallUserAgentMatcher::sanitizeList($maliciousBots, 'malicious');

        Configuration::updateValue('SJ4WEB_FW_SAFEBOTS', json_encode($safeBots));
        Configuration::updateValue('SJ4WEB_FW_MALICIOUSBOTS', json_encode($maliciousBots));

        return true;
    }

    /**
     * Execute un fichier SQL avec remplacement du prefixe PrestaShop.
     */
    public function executeSqlFile($filepath)
    {
        if (!file_exists($filepath)) {
            return false;
        }

        $sql = str_replace('PREFIX_', _DB_PREFIX_, (string) file_get_contents($filepath));
        $queries = preg_split('/;\s*(?:\r?\n|$)/', trim($sql));

        foreach ($queries as $query) {
            $query = trim($query);
            if ($query === '') {
                continue;
            }

            if (!Db::getInstance()->execute($query)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Migre les donnees legacy du gros JSON vers le nouveau stockage SQL.
     */
    public function migrateLegacyJsonStorage($maxLogsPerIp = 25)
    {
        if (!FirewallStorage::hasRequiredTables()) {
            return false;
        }

        $legacyFile = __DIR__ . '/logs/ip_scores.json';
        if (!file_exists($legacyFile)) {
            return true;
        }

        $storage = new FirewallStorage(
            (int) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_SCORE_LIMIT_BLOCK'),
            (int) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_SCORE_LIMIT_SLOW'),
            (int) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_BLOCK_DURATION'),
            (int) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_ALERT_THRESHOLD'),
            '',
            null,
            (bool) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_ALERT_EMAIL_ENABLED')
        );

        if ($storage->countTrackedIps() > 0) {
            return true;
        }

        $data = json_decode((string) file_get_contents($legacyFile), true);
        if (!is_array($data)) {
            return true;
        }

        foreach ($data as $ip => $entry) {
            $score = (int) ($entry['score'] ?? 0);
            $hasBlock = !empty($entry['blocked_until']);
            $hasContactHistory = !empty($entry['contact_attempts']) || !empty($entry['daily_attempts']);

            if (!$score && !$hasBlock && !$hasContactHistory) {
                continue;
            }

            $storage->importLegacyEntry((string) $ip, (array) $entry, (int) $maxLogsPerIp);
        }

        return true;
    }

    public function installTabs()
    {
        if (Tab::getIdFromClassName('AdminSj4webFirewallParent')) {
            return true;
        }

        $parentTab = new Tab();
        $parentTab->class_name = 'AdminSj4webFirewallParent';
        $parentTab->module = $this->name;
        $parentTab->id_parent = Tab::getIdFromClassName('IMPROVE');
        $parentTab->active = 1;
        $parentTab->icon = 'security';

        foreach (Language::getLanguages(false) as $lang) {
            $parentTab->name[$lang['id_lang']] = $this->trans('SJ4WEB - Firewall', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$parentTab->add()) {
            return false;
        }

        $configTab = new Tab();
        $configTab->class_name = 'AdminSj4webFirewall';
        $configTab->module = $this->name;
        $configTab->id_parent = $parentTab->id;
        $configTab->active = 1;
        $configTab->icon = 'settings';

        foreach (Language::getLanguages(false) as $lang) {
            $configTab->name[$lang['id_lang']] = $this->trans('Configuration', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$configTab->add()) {
            return false;
        }

        $logTab = new Tab();
        $logTab->class_name = 'AdminSj4webFirewallLog';
        $logTab->module = $this->name;
        $logTab->id_parent = $parentTab->id;
        $logTab->active = 1;
        $logTab->icon = 'track_changes';

        foreach (Language::getLanguages(false) as $lang) {
            $logTab->name[$lang['id_lang']] = $this->trans('Real-time tracking', [], 'Modules.Sj4webfirewall.Admin');
        }

        if (!$logTab->add()) {
            return false;
        }

        $statsTab = new Tab();
        $statsTab->class_name = 'AdminSj4webFirewallStats';
        $statsTab->module = $this->name;
        $statsTab->id_parent = $parentTab->id;
        $statsTab->active = 1;
        $statsTab->icon = 'description';

        foreach (Language::getLanguages(false) as $lang) {
            $statsTab->name[$lang['id_lang']] = $this->trans('Daily tracking logs', [], 'Modules.Sj4webfirewall.Admin');
        }

        return $statsTab->add();
    }

    public function uninstallTabs()
    {
        foreach (['AdminSj4webFirewallParent', 'AdminSj4webFirewall', 'AdminSj4webFirewallLog', 'AdminSj4webFirewallStats'] as $className) {
            $idTab = (int) Tab::getIdFromClassName($className);
            if (!$idTab) {
                continue;
            }

            $tab = new Tab($idTab);
            $tab->delete();
        }

        return true;
    }

    public function getContent()
    {
        Tools::redirectAdmin($this->context->link->getAdminLink('AdminSj4webFirewall'));
    }

    public function hookDisplayBackOfficeHeader()
    {
        if (in_array(Tools::getValue('controller'), ['AdminSj4webFirewall', 'AdminSj4webFirewallLog'], true)) {
            $this->context->controller->addCss($this->_path . 'views/css/sjfirewall_admin.css');
        }
    }

    /**
     * Hook principal du firewall sur le front office.
     *
     * Le module suit toujours les visites, mais n'alimente l'etat detaille
     * que pour les IPs suspectes, bloquees ou protegees. Le trafic nominal
     * et les bots safe partent uniquement dans les statistiques journalieres.
     */
    public function hookDisplayHeader()
    {
        $config = Sj4webFirewallConfigHelper::getAll();
        list($ip, $userAgent, $country, $storage) = $this->initWorkingVars($config);
        $isActiveFirewall = (bool) ($config['SJ4WEB_FW_ACTIVATE_FIREWALL'] ?? false);

        try {
            $storage->cleanupIfNeeded(
                (int) ($config['SJ4WEB_FW_STATE_RETENTION_DAYS'] ?? 60),
                (int) ($config['SJ4WEB_FW_EVENT_RETENTION_DAYS'] ?? 30),
                (int) ($config['SJ4WEB_FW_CONTACT_RETENTION_DAYS'] ?? 30),
                (int) ($config['SJ4WEB_FW_STATS_RETENTION_DAYS'] ?? 180)
            );

            $score = $storage->getScore($ip);

            if ($this->isIpWhitelisted($ip, (array) $config['SJ4WEB_FW_WHITELIST_IPS'])) {
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);

                return '';
            }

            $manageScore = [
                'ip' => $ip,
                'log_event_reason' => '',
                'score' => 0,
                'update_score' => true,
            ];

            $status = $storage->getStatusForIp($ip);
            if ($status === 'blocked') {
                $manageScore['log_event_reason'] = 'IP bloquee par score';
                $manageScore['update_score'] = false;
                $storage->manageStorage($manageScore);

                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'blocked', null, $country, 403, $storage->getScore($ip));
                if ($isActiveFirewall) {
                    header('HTTP/1.1 403 Forbidden');
                    exit('Access denied.');
                }

                return '';
            }

            if ($this->isKnownSafeBot($userAgent, (array) $config['SJ4WEB_FW_SAFEBOTS'])) {
                $botName = FirewallStatsLogger::detectBotName($userAgent, (array) $config['SJ4WEB_FW_SAFEBOTS']);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_safe', $botName, $country, 200, $score);

                return '';
            }

            if ($this->isMaliciousBot($userAgent, (array) $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
                $botName = FirewallStatsLogger::detectBotName($userAgent, (array) $config['SJ4WEB_FW_MALICIOUSBOTS']);
                $manageScore['log_event_reason'] = 'bot_suspect - ' . $botName;
                $manageScore['score'] = -20;
                $storage->manageStorage($manageScore);
                $this->logAction($ip, $userAgent, 'bot_suspect - ' . $botName);

                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', $botName, $country, 403, $storage->getScore($ip));
                if ($isActiveFirewall) {
                    header('HTTP/1.1 403 Forbidden');
                    exit('Access denied.');
                }

                return '';
            }

            if ($country && in_array($country, (array) $config['SJ4WEB_FW_COUNTRIES_BLOCKED'], true)) {
                $manageScore['log_event_reason'] = 'pays_bloque: ' . $country;
                $manageScore['score'] = -10;
                $storage->manageStorage($manageScore);
                $this->logAction($ip, $userAgent, 'pays_bloque: ' . $country);

                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', 'pays:' . $country, $country, 403, $storage->getScore($ip));
                if ($isActiveFirewall) {
                    header('HTTP/1.1 403 Forbidden');
                    exit('Access denied by country restriction.');
                }

                return '';
            }

            if (!empty($config['SJ4WEB_FW_ENABLE_SLEEP']) && $score <= (int) $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
                $manageScore['log_event_reason'] = 'ralenti: score faible';
                $manageScore['update_score'] = false;
                $storage->manageStorage($manageScore);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $storage->getScore($ip));

                if ($isActiveFirewall) {
                    usleep((int) $config['SJ4WEB_FW_SLEEP_DELAY_MS'] * 1000);
                }

                return '';
            }

            $this->deferredRequestTracking = [
                'ip' => $ip,
                'user_agent' => $userAgent,
                'country' => $country,
            ];
        } catch (Exception $e) {
            $this->logAction($ip, $userAgent, 'Erreur execution : ' . $e->getMessage());
        }

        return '';
    }

    /**
     * Finalise le tracking des requetes nominales apres execution du controller.
     */
    public function hookActionDispatcherAfter()
    {
        if (empty($this->deferredRequestTracking)) {
            return;
        }

        $context = $this->deferredRequestTracking;
        $this->deferredRequestTracking = null;

        $config = Sj4webFirewallConfigHelper::getAll();
        $storage = new FirewallStorage(
            (int) $config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
            (int) $config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
            (int) $config['SJ4WEB_FW_BLOCK_DURATION'],
            (int) $config['SJ4WEB_FW_ALERT_THRESHOLD'],
            (string) $context['user_agent'],
            $context['country'],
            (bool) $config['SJ4WEB_FW_ALERT_EMAIL_ENABLED']
        );

        $httpCode = (int) http_response_code();
        $pageRequested = $_SERVER['REQUEST_URI'] ?? 'unknown';
        $manageScore = [
            'ip' => (string) $context['ip'],
            'log_event_reason' => '',
            'score' => 0,
            'update_score' => true,
        ];

        if ($httpCode === 404) {
            $manageScore['score'] = -1;
            $manageScore['log_event_reason'] = 'Erreur 404 : ' . $pageRequested;
            $storage->manageStorage($manageScore);
        } elseif ($httpCode === 403) {
            $manageScore['score'] = -5;
            $manageScore['log_event_reason'] = 'Erreur 403 : ' . $pageRequested;
            $storage->manageStorage($manageScore);
        }

        FirewallStatsLogger::logVisitPerIp(
            (string) $context['ip'],
            (string) $context['user_agent'],
            'human',
            null,
            $context['country'],
            $httpCode,
            $storage->getScore((string) $context['ip'])
        );
    }

    /**
     * Verifie si l'IP appartient a la whitelist.
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
     * Verifie si le user-agent correspond a un bot safe.
     */
    protected function isKnownSafeBot($userAgent, array $safeBots)
    {
        return Sj4webFirewallUserAgentMatcher::matchesAny($userAgent, $safeBots);
    }

    /**
     * Verifie si le user-agent correspond a un bot malveillant.
     */
    protected function isMaliciousBot($userAgent, array $maliciousBots)
    {
        return Sj4webFirewallUserAgentMatcher::matchesAny($userAgent, $maliciousBots);
    }

    /**
     * Ecrit un log texte uniquement si la journalisation detaillee est active.
     */
    protected function logAction($ip, $userAgent, $reason)
    {
        if (!(bool) Sj4webFirewallConfigHelper::get('SJ4WEB_FW_LOG_ENABLED')) {
            return;
        }

        $log = sprintf("[%s] %s - %s (%s)\n", date('Y-m-d H:i:s'), $ip, $reason, $userAgent);
        $logFile = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/firewall.log';
        file_put_contents($logFile, $log, FILE_APPEND);
    }

    /**
     * Verifie si une IP appartient a une plage CIDR.
     */
    protected function ipInRange($ip, $range)
    {
        if (!strpos($range, '/')) {
            return false;
        }

        list($subnet, $bits) = explode('/', $range);
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) {
            return false;
        }

        $ipLen = strlen($ipBin);
        $bitMax = $ipLen * 8;

        if ($bits > $bitMax) {
            return false;
        }

        $bytes = intdiv((int) $bits, 8);
        $bitsRemain = (int) $bits % 8;

        if (strncmp($ipBin, $subnetBin, $bytes) !== 0) {
            return false;
        }

        if ($bitsRemain === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $bitsRemain)) & 0xFF;

        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }

    /**
     * Retourne le user-agent courant.
     */
    protected function getUserAgent()
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? '';
    }

    /**
     * Protege le formulaire de contact contre le spam.
     */
    public function hookActionContactFormSubmitBefore(array $params)
    {
        $config = Sj4webFirewallConfigHelper::getAll();
        $isContactProtectionEnabled = (bool) ($config['SJ4WEB_FW_CONTACT_PROTECTION_ENABLED'] ?? false);

        if ($this->context->customer->isLogged() || !$isContactProtectionEnabled) {
            return;
        }

        $ts = Tools::getValue('sj4web_fw_ts');
        $token = Tools::getValue('sj4web_fw_token');
        list($ip, $userAgent, $country, $storage) = $this->initWorkingVars($config);

        if (!empty($token)) {
            $storage->logEvent($ip, 'contact_blocked: honeypot', 403, 'contact');
            $storage->blockIp($ip);
            die();
        }

        if (!$ts || (time() - (int) $ts < 5)) {
            $storage->logEvent($ip, 'contact_blocked: timer < 5s', 403, 'contact');
            $storage->blockIp($ip);
            die();
        }

        $max = (int) $config['SJ4WEB_FW_CONTACT_MAX_PER_PERIOD'];
        $minutes = (int) $config['SJ4WEB_FW_CONTACT_PERIOD_MINUTES'];
        $maxDaily = (int) $config['SJ4WEB_FW_CONTACT_MAX_DAILY'];

        $recentAttempts = $storage->getContactAttemptsInLastXMinutes($ip, $minutes);
        $dailyAttempts = $storage->getDailyContactAttempts($ip);

        if ($dailyAttempts >= $maxDaily) {
            $storage->logEvent($ip, 'contact_blocked: spam (daily limit)', 403, 'contact');
            $storage->blockIp($ip);

            $messageText = $this->trans('Maximum number of contact form messages reached for today: %d.', [$maxDaily], 'Modules.Sj4webfirewall.Shop');
            FirewallMailer::sendAlert($ip, $userAgent, 0, $country, $messageText);

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

        $storage->incrementHourlyContactAttempt($ip);
    }

    /**
     * Retourne le pays ISO alpha-2 de l'IP.
     */
    public function getCountry(string $ip, $userAgent = null)
    {
        $geo = new FirewallGeo();

        try {
            return $geo->getCountryCode($ip) ?: null;
        } catch (Exception $e) {
            $this->logAction($ip, $userAgent ?: 'N/A', 'Erreur de recuperation du pays : ' . $e->getMessage());
        }

        return null;
    }

    /**
     * Initialise les variables de travail du firewall.
     *
     * @return array{0:string,1:string,2:?string,3:FirewallStorage}
     */
    public function initWorkingVars($config = null)
    {
        if ($config === null) {
            $config = Sj4webFirewallConfigHelper::getAll();
        }

        $ip = $this->getIp();
        $userAgent = $this->getUserAgent();
        $country = $this->getCountry($ip, $userAgent);

        $storage = new FirewallStorage(
            (int) $config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
            (int) $config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
            (int) $config['SJ4WEB_FW_BLOCK_DURATION'],
            (int) $config['SJ4WEB_FW_ALERT_THRESHOLD'],
            $userAgent,
            $country,
            (bool) $config['SJ4WEB_FW_ALERT_EMAIL_ENABLED']
        );

        return [$ip, $userAgent, $country, $storage];
    }

    protected function getIp()
    {
        return Tools::getRemoteAddr();
    }

    public function isUsingNewTranslationSystem()
    {
        return true;
    }
}
