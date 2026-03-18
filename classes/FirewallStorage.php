<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

include_once __DIR__ . '/FirewallMailer.php';

class FirewallStorage
{
    protected const EVENT_LOG_LIMIT_PER_IP = 200;

    protected $schemaReady;
    protected $scoreLimitBlock;
    protected $scoreLimitSlow;
    protected $blockDuration;
    protected $scoreLimitAlert;
    protected $userAgent;
    protected $country;
    protected $sendAlertEnabled;

    /**
     * Initialise la couche de persistance du firewall.
     *
     * Le module utilise des tables SQL pour eviter les reecritures completes
     * d'un gros fichier JSON a chaque requete.
     */
    public function __construct(
        $scoreLimitBlock = -70,
        $scoreLimitSlow = -10,
        $blockDuration = 3600,
        $scoreLimitAlert = -30,
        $userAgent = '',
        $country = 'N/A',
        $sendAlertEnabled = true
    ) {
        $this->scoreLimitBlock = (int) $scoreLimitBlock;
        $this->scoreLimitSlow = (int) $scoreLimitSlow;
        $this->blockDuration = (int) $blockDuration;
        $this->scoreLimitAlert = (int) $scoreLimitAlert;
        $this->userAgent = (string) $userAgent;
        $this->country = $country ?: null;
        $this->sendAlertEnabled = (bool) $sendAlertEnabled;
        $this->schemaReady = self::hasRequiredTables();
    }

    /**
     * Indique si la persistance SQL du module est disponible.
     */
    public static function hasRequiredTables()
    {
        return self::tableExists(self::getStateTable())
            && self::tableExists(self::getEventTable())
            && self::tableExists(self::getContactAttemptTable())
            && self::tableExists(self::getDailyStatTable())
            && self::tableExists(self::getDailySummaryTable());
    }

    /**
     * Verifie l'existence d'une table SQL.
     */
    protected static function tableExists($tableName)
    {
        $sql = 'SHOW TABLES LIKE "'  . _DB_PREFIX_ . pSQL((string) $tableName) . '"';
        $result = Db::getInstance()->executeS($sql);

        return !empty($result);
    }

    /**
     * Retourne le nom de la table stockant l'etat courant des IPs.
     */
    public static function getStateTable()
    {
        return  'sj4web_firewall_ip_state';
    }

    /**
     * Retourne le nom de la table stockant les evenements par IP.
     */
    public static function getEventTable()
    {
        return 'sj4web_firewall_ip_event';
    }

    /**
     * Retourne le nom de la table stockant les tentatives du formulaire de contact.
     */
    public static function getContactAttemptTable()
    {
        return 'sj4web_firewall_contact_attempt';
    }

    /**
     * Retourne le nom de la table stockant les statistiques journalières.
     */
    public static function getDailyStatTable()
    {
        return 'sj4web_firewall_daily_stat';
    }

    /**
     * Retourne le nom de la table stockant les resumes journaliers.
     */
    public static function getDailySummaryTable()
    {
        return 'sj4web_firewall_daily_summary';
    }

    /**
     * Retourne le statut actuel d'une IP.
     */
    public function getStatusForIp($ip)
    {
        if (!$this->schemaReady) {
            return 'normal';
        }

        $entry = $this->getStateByIp($ip);
        if ($entry === null) {
            return 'normal';
        }

        $now = date('Y-m-d H:i:s');
        if (!empty($entry['blocked_until']) && $entry['blocked_until'] > $now) {
            return 'blocked';
        }

        if ((int) $entry['score'] <= $this->scoreLimitBlock) {
            if (empty($entry['blocked_until']) || $entry['blocked_until'] <= $now) {
                $entry['blocked_until'] = $this->formatDateTime(time() + $this->blockDuration);
                $this->persistState($entry);
            }

            return 'blocked';
        }

        if ((int) $entry['score'] <= $this->scoreLimitSlow) {
            return 'slow';
        }

        return 'normal';
    }

    /**
     * Met a jour le score d'une IP.
     */
    public function updateScore($ip, $variation)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getOrCreateState($ip);
        $this->applyScoreToState($ip, $state, (int) $variation);
        $this->persistState($state);
    }

    /**
     * Incremente le compteur de visites d'une IP.
     */
    public function incrementVisit($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getOrCreateState($ip);
        $state['hit_count'] = (int) $state['hit_count'] + 1;
        $state['updated_at'] = $this->formatDateTime();
        $state['country'] = $state['country'] ?: $this->country;
        $state['user_agent'] = $this->userAgent;
        $this->persistState($state);
    }

    /**
     * Verifie si une IP est deja suivie.
     */
    public function has($ip)
    {
        if (!$this->schemaReady) {
            return false;
        }

        return $this->getStateByIp($ip) !== null;
    }

    /**
     * Retourne le score actuel d'une IP.
     */
    public function getScore($ip)
    {
        if (!$this->schemaReady) {
            return 0;
        }

        $entry = $this->getStateByIp($ip);

        return $entry !== null ? (int) $entry['score'] : 0;
    }

    /**
     * Retourne le nombre de visites actuel d'une IP suivie.
     */
    public function getCount($ip)
    {
        if (!$this->schemaReady) {
            return 0;
        }

        $entry = $this->getStateByIp($ip);

        return $entry !== null ? (int) $entry['hit_count'] : 0;
    }

    /**
     * Enregistre un evenement sur une IP sans reecrire toute la persistance.
     */
    public function logEvent($ip, $reason, $statusCode = null, $eventType = 'runtime')
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getOrCreateState($ip);
        $state['updated_at'] = $this->formatDateTime();
        $state['last_event_reason'] = Tools::substr((string) $reason, 0, 255);
        $state['country'] = $state['country'] ?: $this->country;
        $state['user_agent'] = $this->userAgent;

        $this->persistState($state);
        $this->insertEvent($ip, $reason, $statusCode, $eventType);
    }

    /**
     * Traite une decision runtime en une seule mise a jour SQL.
     *
     * Le but est d'eviter la triplette updateScore + incrementVisit + logEvent
     * qui reecrivait auparavant tout le fichier JSON plusieurs fois par requete.
     *
     * @param array{
     *   ip: string,
     *   log_event_reason: string,
     *   update_score: bool,
     *   score: int
     * } $data
     */
    public function manageStorage(array $data)
    {
        if (!$this->schemaReady) {
            return;
        }

        if (
            !isset($data['ip'], $data['log_event_reason'], $data['update_score'], $data['score']) ||
            !is_string($data['ip']) ||
            !is_string($data['log_event_reason']) ||
            !is_bool($data['update_score']) ||
            !is_int($data['score'])
        ) {
            throw new InvalidArgumentException('Le tableau $data ne respecte pas le patron attendu.');
        }

        $ip = $data['ip'];
        $state = $this->getOrCreateState($ip);

        if ($data['update_score']) {
            $this->applyScoreToState($ip, $state, $data['score']);
        }

        $state['hit_count'] = (int) $state['hit_count'] + 1;
        $state['updated_at'] = $this->formatDateTime();
        $state['country'] = $state['country'] ?: $this->country;
        $state['user_agent'] = $this->userAgent;
        $state['last_event_reason'] = Tools::substr($data['log_event_reason'], 0, 255);

        $this->persistState($state);
        $this->insertEvent($ip, $data['log_event_reason']);
    }

    /**
     * Purge periodiquement les donnees trop anciennes.
     */
    public function cleanupIfNeeded($stateRetentionDays, $eventRetentionDays, $contactRetentionDays, $statsRetentionDays)
    {
        if (!$this->schemaReady) {
            return;
        }

        $today = date('Y-m-d');
        if ((string) Configuration::get('SJ4WEB_FW_LAST_CLEANUP_AT') === $today) {
            return;
        }

        $this->cleanupState((int) $stateRetentionDays);
        $this->cleanupEvents((int) $eventRetentionDays);
        $this->cleanupContactAttempts((int) $contactRetentionDays);
        $this->cleanupDailyStats((int) $statsRetentionDays);

        Configuration::updateValue('SJ4WEB_FW_LAST_CLEANUP_AT', $today);
    }

    /**
     * Enregistre une tentative de formulaire de contact.
     */
    public function incrementHourlyContactAttempt($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        Db::getInstance()->insert(
            self::getContactAttemptTable(),
            [
                'ip' => $ip,
                'created_at' => $this->formatDateTime(),
            ]
        );
    }

    /**
     * Retourne le nombre de tentatives de contact du jour pour une IP.
     */
    public function getDailyContactAttempts($ip)
    {
        if (!$this->schemaReady) {
            return 0;
        }

        $sql = 'SELECT COUNT(*) AS total
            FROM `' . _DB_PREFIX_ . pSQL(self::getContactAttemptTable()) . '`
            WHERE `ip` = "' . pSQL($ip) . '"
              AND DATE(`created_at`) = CURDATE()';

        $result = Db::getInstance()->executeS($sql);

        return isset($result[0]['total']) ? (int) $result[0]['total'] : 0;
    }

    /**
     * Retourne le nombre de tentatives de contact sur une periode glissante.
     */
    public function getContactAttemptsInLastXMinutes($ip, $minutes)
    {
        if (!$this->schemaReady) {
            return 0;
        }

        $threshold = $this->formatDateTime(time() - ((int) $minutes * 60));
        $sql = 'SELECT COUNT(*) AS total
            FROM `' . _DB_PREFIX_ . pSQL(self::getContactAttemptTable()) . '`
            WHERE `ip` = "' . pSQL($ip) . '"
              AND `created_at` >= "' . pSQL($threshold) . '"';

        $result = Db::getInstance()->executeS($sql);

        return isset($result[0]['total']) ? (int) $result[0]['total'] : 0;
    }

    /**
     * Force le blocage d'une IP pour la duree configuree.
     */
    public function blockIp($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getOrCreateState($ip);
        $state['blocked_until'] = $this->formatDateTime(time() + $this->blockDuration);
        $state['updated_at'] = $this->formatDateTime();
        $state['last_event_reason'] = 'IP bloquee manuellement';
        $state['country'] = $state['country'] ?: $this->country;
        $state['user_agent'] = $this->userAgent;

        $this->persistState($state);
        $this->insertEvent($ip, 'IP bloquee manuellement', 403, 'manual_block');
    }

    /**
     * Debloque une IP sans supprimer son historique.
     */
    public function unblockIp($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getStateByIp($ip);
        if ($state === null) {
            return;
        }

        $state['blocked_until'] = null;
        $state['updated_at'] = $this->formatDateTime();
        $state['last_event_reason'] = 'Deblocage manuel';

        $this->persistState($state);
        $this->insertEvent($ip, 'Deblocage manuel', null, 'manual_unblock');
    }

    /**
     * Reinitialise le score d'une IP sans supprimer ses traces.
     */
    public function resetIp($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getStateByIp($ip);
        if ($state === null) {
            return;
        }

        $state['score'] = 0;
        $state['blocked_until'] = null;
        $state['alerted'] = 0;
        $state['updated_at'] = $this->formatDateTime();
        $state['last_event_reason'] = 'Score reinitialise depuis le BO';

        $this->persistState($state);
        $this->insertEvent($ip, 'Score reinitialise depuis le BO', null, 'admin_reset');
    }

    /**
     * Supprime une IP de l'etat courant et de son historique detaille.
     */
    public function deleteIp($ip)
    {
        if (!$this->schemaReady) {
            return;
        }

        Db::getInstance()->delete(self::getStateTable(), '`ip` = "' . pSQL($ip) . '"');
        Db::getInstance()->delete(self::getEventTable(), '`ip` = "' . pSQL($ip) . '"');
        Db::getInstance()->delete(self::getContactAttemptTable(), '`ip` = "' . pSQL($ip) . '"');
    }

    /**
     * Retourne la liste des IPs suivies pour le BO.
     *
     * @return array<int, array<string, mixed>>
     */
    public function getTrackedEntries()
    {
        if (!$this->schemaReady) {
            return [];
        }

        $sql = 'SELECT `ip`, `country`, `score`, `hit_count`, `first_seen`, `updated_at`, `blocked_until`, `last_event_reason`
            FROM `' . _DB_PREFIX_ . pSQL(self::getStateTable()) . '`';
        $rows = Db::getInstance()->executeS($sql);
        $entries = [];

        foreach ($rows as $row) {
            $entries[] = [
                'ip' => $row['ip'],
                'country' => $row['country'] ?: '-',
                'score' => (int) $row['score'],
                'status' => $this->resolveStatusFromRow($row),
                'count' => (int) $row['hit_count'],
                'log' => [],
                'last_log' => $row['last_event_reason'] ? $row['updated_at'] . ' - ' . $row['last_event_reason'] : '-',
                'first_seen' => $row['first_seen'] ?: '-',
                'updated_at' => $row['updated_at'] ?: '-',
                'blocked_until' => $row['blocked_until'] ?: null,
            ];
        }

        return $entries;
    }

    /**
     * Retourne les evenements detailes d'une IP.
     *
     * @return array<int, array<string, string>>
     */
    public function getLogsForIp($ip, $limit = self::EVENT_LOG_LIMIT_PER_IP)
    {
        if (!$this->schemaReady) {
            return [];
        }

        $sql = 'SELECT `created_at`, `reason`
            FROM `' . _DB_PREFIX_ . pSQL(self::getEventTable()) . '`
            WHERE `ip` = "' . pSQL($ip) . '"
            ORDER BY `created_at` DESC, `id_sj4web_firewall_ip_event` DESC
            LIMIT ' . (int) $limit;

        $rows = Db::getInstance()->executeS($sql);
        $logs = [];

        foreach ($rows as $row) {
            $logs[] = [
                'time' => $row['created_at'],
                'reason' => $row['reason'],
            ];
        }

        return $logs;
    }

    /**
     * Retourne le nombre d'IPs suivies dans la nouvelle persistance.
     */
    public function countTrackedIps()
    {
        if (!$this->schemaReady) {
            return 0;
        }

        $sql = 'SELECT COUNT(*) AS total FROM `' . _DB_PREFIX_ . pSQL(self::getStateTable()) . '`';
        $result = Db::getInstance()->executeS($sql);

        return isset($result[0]['total']) ? (int) $result[0]['total'] : 0;
    }

    /**
     * Importe une entree legacy issue du JSON historique.
     */
    public function importLegacyEntry($ip, array $entry, $maxLogs = 25)
    {
        if (!$this->schemaReady) {
            return;
        }

        $state = $this->getStateByIp($ip);
        if ($state !== null) {
            return;
        }

        $logs = isset($entry['log']) && is_array($entry['log']) ? array_slice($entry['log'], -((int) $maxLogs)) : [];
        $lastReason = !empty($logs) ? (string) $logs[count($logs) - 1]['reason'] : null;

        $importState = [
            'ip' => $ip,
            'score' => (int) ($entry['score'] ?? 0),
            'hit_count' => (int) ($entry['count'] ?? 0),
            'first_seen' => $this->formatDateTime(isset($entry['first_seen']) ? (int) $entry['first_seen'] : time()),
            'updated_at' => $this->formatDateTime(isset($entry['updated_at']) ? (int) $entry['updated_at'] : time()),
            'blocked_until' => !empty($entry['blocked_until']) ? $this->formatDateTime((int) $entry['blocked_until']) : null,
            'alerted' => !empty($entry['alerted']) ? 1 : 0,
            'country' => !empty($entry['country']) ? (string) $entry['country'] : null,
            'user_agent' => !empty($entry['user_agent']) ? (string) $entry['user_agent'] : null,
            'last_event_reason' => $lastReason ? Tools::substr($lastReason, 0, 255) : null,
        ];

        Db::getInstance()->insert(self::getStateTable(), $importState, false, true, Db::INSERT_IGNORE);

        foreach ($logs as $log) {
            if (empty($log['reason'])) {
                continue;
            }

            Db::getInstance()->insert(self::getEventTable(), [
                'ip' => $ip,
                'created_at' => (string) ($log['time'] ?? $importState['updated_at']),
                'reason' => Tools::substr((string) $log['reason'], 0, 255),
                'event_type' => 'legacy_import',
                'status_code' => null,
                'user_agent' => $importState['user_agent'],
            ]);
        }
    }

    /**
     * Recupere l'etat d'une IP.
     */
    protected function getStateByIp($ip)
    {
        $sql = 'SELECT `ip`, `score`, `hit_count`, `first_seen`, `updated_at`, `blocked_until`, `alerted`, `country`, `user_agent`, `last_event_reason`
            FROM `' . _DB_PREFIX_ . pSQL(self::getStateTable()) . '`
            WHERE `ip` = "' . pSQL($ip) . '"
            LIMIT 1';
        $result = Db::getInstance()->executeS($sql);

        return !empty($result) ? $result[0] : null;
    }

    /**
     * Cree une ligne d'etat par defaut si l'IP n'existe pas encore.
     *
     * @return array<string, mixed>
     */
    protected function getOrCreateState($ip)
    {
        $state = $this->getStateByIp($ip);
        if ($state !== null) {
            return $state;
        }

        $now = $this->formatDateTime();
        $state = [
            'ip' => $ip,
            'score' => 0,
            'hit_count' => 0,
            'first_seen' => $now,
            'updated_at' => $now,
            'blocked_until' => null,
            'alerted' => 0,
            'country' => $this->country,
            'user_agent' => $this->userAgent,
            'last_event_reason' => null,
        ];

        $this->persistState($state);

        return $state;
    }

    /**
     * Persiste l'etat courant d'une IP.
     */
    protected function persistState(array $state)
    {
        $data = [
            'score' => (int) $state['score'],
            'hit_count' => (int) $state['hit_count'],
            'first_seen' => (string) $state['first_seen'],
            'updated_at' => (string) $state['updated_at'],
            'blocked_until' => !empty($state['blocked_until']) ? (string) $state['blocked_until'] : null,
            'alerted' => !empty($state['alerted']) ? 1 : 0,
            'country' => !empty($state['country']) ? (string) $state['country'] : null,
            'user_agent' => !empty($state['user_agent']) ? (string) $state['user_agent'] : null,
            'last_event_reason' => !empty($state['last_event_reason']) ? Tools::substr((string) $state['last_event_reason'], 0, 255) : null,
        ];

        $exists = $this->has($state['ip']);
        if ($exists) {
            Db::getInstance()->update(self::getStateTable(), $data, '`ip` = "' . pSQL($state['ip']) . '"');

            return;
        }

        $data['ip'] = $state['ip'];
        Db::getInstance()->insert(self::getStateTable(), $data, false, true, Db::INSERT_IGNORE);
    }

    /**
     * Applique une variation de score a l'etat d'une IP.
     */
    protected function applyScoreToState($ip, array &$state, $variation)
    {
        $state['score'] = (int) $state['score'] + (int) $variation;
        $state['updated_at'] = $this->formatDateTime();
        $state['country'] = $state['country'] ?: $this->country;

        if ((int) $state['score'] > $this->scoreLimitBlock) {
            $state['blocked_until'] = null;
        }

        if (
            $this->sendAlertEnabled &&
            (int) $state['score'] <= $this->scoreLimitAlert &&
            empty($state['alerted'])
        ) {
            FirewallMailer::sendAlert($ip, $this->userAgent, (int) $state['score'], $this->country);
            $state['alerted'] = 1;
        }
    }

    /**
     * Insere un evenement detaille puis supprime l'exces historique.
     */
    protected function insertEvent($ip, $reason, $statusCode = null, $eventType = 'runtime')
    {
        Db::getInstance()->insert(self::getEventTable(), [
            'ip' => $ip,
            'created_at' => $this->formatDateTime(),
            'reason' => Tools::substr((string) $reason, 0, 255),
            'event_type' => (string) $eventType,
            'status_code' => $statusCode !== null ? (int) $statusCode : null,
            'user_agent' => $this->userAgent !== '' ? $this->userAgent : null,
        ]);

        $this->trimEventsForIp($ip);
    }

    /**
     * Conserve un historique borne pour chaque IP afin de garder le BO lisible.
     */
    protected function trimEventsForIp($ip)
    {
        $sql = 'DELETE FROM `' . _DB_PREFIX_ . pSQL(self::getEventTable()) . '`
            WHERE `ip` = "' . pSQL($ip) . '"
              AND `id_sj4web_firewall_ip_event` NOT IN (
                  SELECT `id_sj4web_firewall_ip_event`
                  FROM (
                      SELECT `id_sj4web_firewall_ip_event`
                      FROM `' . _DB_PREFIX_ . pSQL(self::getEventTable()) . '`
                      WHERE `ip` = "' . pSQL($ip) . '"
                      ORDER BY `created_at` DESC, `id_sj4web_firewall_ip_event` DESC
                      LIMIT ' . (int) self::EVENT_LOG_LIMIT_PER_IP . '
                  ) AS `recent_events`
              )';

        Db::getInstance()->execute($sql);
    }

    /**
     * Supprime les IPs inactives depuis trop longtemps.
     */
    protected function cleanupState($retentionDays)
    {
        if ($retentionDays <= 0) {
            return;
        }

        $threshold = $this->formatDateTime(time() - ($retentionDays * 86400));
        $sql = 'DELETE FROM `' . _DB_PREFIX_ . pSQL(self::getStateTable()) . '`
            WHERE `updated_at` < "' . pSQL($threshold) . '"
              AND (`blocked_until` IS NULL OR `blocked_until` < NOW())';

        Db::getInstance()->execute($sql);
    }

    /**
     * Supprime les evenements detailes trop anciens.
     */
    protected function cleanupEvents($retentionDays)
    {
        if ($retentionDays <= 0) {
            return;
        }

        $threshold = $this->formatDateTime(time() - ($retentionDays * 86400));
        Db::getInstance()->delete(self::getEventTable(), '`created_at` < "' . pSQL($threshold) . '"');
    }

    /**
     * Supprime les traces anciennes du formulaire de contact.
     */
    protected function cleanupContactAttempts($retentionDays)
    {
        if ($retentionDays <= 0) {
            return;
        }

        $threshold = $this->formatDateTime(time() - ($retentionDays * 86400));
        Db::getInstance()->delete(self::getContactAttemptTable(), '`created_at` < "' . pSQL($threshold) . '"');
    }

    /**
     * Supprime les stats journalieres trop anciennes.
     */
    protected function cleanupDailyStats($retentionDays)
    {
        if ($retentionDays <= 0) {
            return;
        }

        $thresholdDate = date('Y-m-d', time() - ($retentionDays * 86400));
        Db::getInstance()->delete(self::getDailyStatTable(), '`log_date` < "' . pSQL($thresholdDate) . '"');
        Db::getInstance()->delete(self::getDailySummaryTable(), '`log_date` < "' . pSQL($thresholdDate) . '"');
    }

    /**
     * Calcule le statut a partir d'une ligne SQL deja chargee.
     */
    protected function resolveStatusFromRow(array $row)
    {
        $now = date('Y-m-d H:i:s');

        if (!empty($row['blocked_until']) && $row['blocked_until'] > $now) {
            return 'blocked';
        }

        if ((int) $row['score'] <= $this->scoreLimitBlock) {
            return 'blocked';
        }

        if ((int) $row['score'] <= $this->scoreLimitSlow) {
            return 'slow';
        }

        return 'normal';
    }

    /**
     * Formate un timestamp Unix en DATETIME SQL.
     */
    protected function formatDateTime($timestamp = null)
    {
        return date('Y-m-d H:i:s', $timestamp ?: time());
    }
}
