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
