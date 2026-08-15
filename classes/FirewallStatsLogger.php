<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

require_once __DIR__ . '/Sj4webFirewallUserAgentMatcher.php';

class FirewallStatsLogger
{
    /**
     * Enregistre un resume journalier global.
     *
     * Cette methode legacy n'est pas utilisee par le runtime principal,
     * mais elle est conservee pour compatibilite avec les tests internes.
     */
    public static function logVisit($userAgent, $type = 'human', $botName = null)
    {
        $sql = 'INSERT INTO `' . _DB_PREFIX_ . pSQL(FirewallStorage::getDailySummaryTable()) . '`
            (`log_date`, `traffic_type`, `bot_name`, `total_count`)
            VALUES (
                CURDATE(),
                "' . pSQL((string) $type) . '",
                "' . pSQL((string) ($botName ?: '')) . '",
                1
            )
            ON DUPLICATE KEY UPDATE `total_count` = `total_count` + 1';

        Db::getInstance()->execute($sql);
    }

    /**
     * Enregistre une visite par IP dans la table d'agregats journaliers.
     */
    public static function logVisitPerIp($ip, $userAgent, $type, $botName = null, $country = null, $statusCode = 200, $score = 0)
    {
        $safeIp = pSQL((string) $ip);
        $safeUserAgent = pSQL((string) $userAgent, true);
        $safeType = pSQL((string) $type);
        $safeBotName = pSQL((string) ($botName ?: ''));
        $safeCountry = $country ? '"' . pSQL((string) $country) . '"' : 'NULL';
        $error404 = (int) ($statusCode === 404);
        $error403 = (int) ($statusCode === 403);

        $sql = 'INSERT INTO `' . _DB_PREFIX_ . pSQL(FirewallStorage::getDailyStatTable()) . '`
            (`log_date`, `ip`, `type`, `bot_name`, `user_agent`, `country`, `access_count`, `error_404_count`, `error_403_count`, `first_seen`, `last_seen`, `score`)
            VALUES (
                CURDATE(),
                "' . $safeIp . '",
                "' . $safeType . '",
                "' . $safeBotName . '",
                "' . $safeUserAgent . '",
                ' . $safeCountry . ',
                1,
                ' . $error404 . ',
                ' . $error403 . ',
                NOW(),
                NOW(),
                ' . (int) $score . '
            )
            ON DUPLICATE KEY UPDATE
                `type` = VALUES(`type`),
                `bot_name` = VALUES(`bot_name`),
                `user_agent` = VALUES(`user_agent`),
                `country` = COALESCE(VALUES(`country`), `country`),
                `access_count` = `access_count` + 1,
                `error_404_count` = `error_404_count` + ' . $error404 . ',
                `error_403_count` = `error_403_count` + ' . $error403 . ',
                `last_seen` = NOW(),
                `score` = ' . (int) $score;

        Db::getInstance()->execute($sql);
    }

    /**
     * Detecte le nom du bot correspondant a un user-agent.
     */
    public static function detectBotName($userAgent, array $botList)
    {
        return Sj4webFirewallUserAgentMatcher::detect($userAgent, $botList);
    }

    /**
     * Charge les statistiques agregees d'une date donnee.
     *
     * @return array<string, mixed>|null
     */
    public static function getStatsForDate($date)
    {
        $sql = 'SELECT `ip`, `type`, `bot_name`, `user_agent`, `country`, `access_count`, `error_404_count`, `error_403_count`, `first_seen`, `last_seen`, `score`
            FROM `' . _DB_PREFIX_ . pSQL(FirewallStorage::getDailyStatTable()) . '`
            WHERE `log_date` = "' . pSQL((string) $date) . '"
            ORDER BY `access_count` DESC';
        $rows = Db::getInstance()->executeS($sql);

        if (empty($rows)) {
            return null;
        }

        $stats = [
            'date' => $date,
            'ips' => [],
        ];

        foreach ($rows as $row) {
            $stats['ips'][$row['ip']] = [
                'type' => $row['type'],
                'bot_name' => $row['bot_name'] ?: null,
                'user_agent' => $row['user_agent'],
                'country' => $row['country'] ?: null,
                'access_count' => (int) $row['access_count'],
                'error_404_count' => (int) $row['error_404_count'],
                'error_403_count' => (int) $row['error_403_count'],
                'first_seen' => $row['first_seen'],
                'last_seen' => $row['last_seen'],
                'score' => (int) $row['score'],
            ];
        }

        return $stats;
    }

    /**
     * Liste les dates disponibles dans la nouvelle persistance SQL.
     *
     * @return array<int, string>
     */
    public static function listAvailableDates()
    {
        $sql = 'SELECT DISTINCT `log_date`
            FROM `' . _DB_PREFIX_ . pSQL(FirewallStorage::getDailyStatTable()) . '`
            ORDER BY `log_date` ASC';
        $rows = Db::getInstance()->executeS($sql);
        $dates = [];

        foreach ($rows as $row) {
            $dates[] = $row['log_date'];
        }

        return $dates;
    }
}
