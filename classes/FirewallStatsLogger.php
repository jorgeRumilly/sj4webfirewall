<?php

class FirewallStatsLogger
{
    protected static $logDir = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/stats/';

    /**
     * Enregistre une visite dans le fichier du jour.
     * @param string $userAgent
     * @param string $type : 'safe', 'bad', 'human'
     * @param string|null $botName
     */
    public static function logVisit($userAgent, $type = 'human', $botName = null)
    {
        $date = date('Y-m-d');
        $file = self::$logDir . $date . '.json';

        if (!is_dir(self::$logDir)) {
            mkdir(self::$logDir, 0755, true);
        }

        $data = [];

        if (file_exists($file)) {
            $data = json_decode(file_get_contents($file), true) ?: [];
        }

        // total
        if (!isset($data['total'])) {
            $data['total'] = 0;
        }
        $data['total']++;

        switch ($type) {
            case 'safe':
                $section = 'safe_bots';
                break;
            case 'bad':
                $section = 'bad_bots';
                break;
            case 'human':
            default:
                $section = 'humans';
                break;
        }

        if ($section === 'humans') {
            if (!isset($data['humans'])) {
                $data['humans'] = 0;
            }
            $data['humans']++;
        } else {
            if (!$botName) {
                $botName = 'Unknown';
            }
            if (!isset($data[$section])) {
                $data[$section] = [];
            }
            if (!isset($data[$section][$botName])) {
                $data[$section][$botName] = 0;
            }
            $data[$section][$botName]++;
        }

        file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
    }

    /**
     * Enregistre une visite par IP.
     * @param $ip
     * @param $userAgent
     * @param $type
     * @param $botName
     * @param $country
     * @param $statusCode
     * @param $score
     * @return void
     */
    public static function logVisitPerIp($ip, $userAgent, $type, $botName = null, $country = null, $statusCode = 200, $score = 0)
    {
        $date = date('Y-m-d');
        $logPath = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/stats/' . $date . '.json';

        // Lecture existante
        if (file_exists($logPath)) {
            $content = json_decode(file_get_contents($logPath), true);
        } else {
            $content = [
                'date' => $date,
                'ips' => []
            ];
        }

        // Initialiser l'IP si inconnue
        if (!isset($content['ips'][$ip])) {
            $content['ips'][$ip] = [
                'type' => $type,
                'bot_name' => $botName,
                'user_agent' => $userAgent,
                'country' => $country,
                'access_count' => 0,
                'error_404_count' => 0,
                'error_403_count' => 0,
                'first_seen' => date('c'),
                'last_seen' => date('c'),
                'score' => $score
            ];
        }

        // Mise à jour
        $content['ips'][$ip]['access_count'] += 1;
        $content['ips'][$ip]['last_seen'] = date('c');

        // Incrémentation des erreurs HTTP
        if ($statusCode === 404) {
            $content['ips'][$ip]['error_404_count'] += 1;
        } elseif ($statusCode === 403) {
            $content['ips'][$ip]['error_403_count'] += 1;
        }

        // Écriture
        file_put_contents($logPath, json_encode($content, JSON_PRETTY_PRINT));
    }


    /**
     * Détecte le nom du bot dans un user-agent donné à partir d’une liste.
     * @param string $userAgent
     * @param array $botList
     * @return string|null
     */
    public static function detectBotName($userAgent, array $botList)
    {
        foreach ($botList as $bot) {
            $bot = trim($bot);
            if ($bot && stripos($userAgent, $bot) !== false) {
                return $bot;
            }
        }

        return null;
    }

    /**
     * Charge les statistiques d’une date donnée (format YYYY-MM-DD).
     * @param string $date
     * @return array|null
     */
    public static function getStatsForDate($date)
    {
        $file = self::$logDir . $date . '.json';
        if (file_exists($file)) {
            return json_decode(file_get_contents($file), true) ?: [];
        }
        return null;
    }

    /**
     * Liste tous les fichiers de stats disponibles.
     * @return array
     */
    public static function listAvailableDates()
    {
        if (!is_dir(self::$logDir)) {
            return [];
        }

        $files = scandir(self::$logDir);
        $dates = [];

        foreach ($files as $file) {
            if (preg_match('/^(\d{4}-\d{2}-\d{2})\.json$/', $file, $matches)) {
                $dates[] = $matches[1];
            }
        }

        sort($dates);
        return $dates;
    }
}
