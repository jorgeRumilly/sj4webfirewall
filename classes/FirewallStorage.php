<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

include_once __DIR__ . '/FirewallMailer.php';

class FirewallStorage
{
    protected $filepath;
    protected $data = [];
    protected $scoreLimitBlock;
    protected $scoreLimitSlow;
    protected $blockDuration;
    protected $scoreLimitAlert;
    protected $userAgent;
    protected $country;
    protected $sendAlertEnabled;

    /**
     * Initialise la classe de stockage avec les seuils et le chemin du fichier JSON.
     */
    public function __construct($scoreLimitBlock = -70,
                                $scoreLimitSlow = -10,
                                $blockDuration = 3600,
                                $scoreLimitAlert = -30,
                                $userAgent = '',
                                $country = 'N/A',
                                $sendAlertEnabled = true)
    {
        $logsDir = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/';

        if (!is_dir($logsDir)) {
            mkdir($logsDir, 0755, true);
        }

        $this->filepath = $logsDir . 'ip_scores.json';
        $this->scoreLimitBlock = (int)$scoreLimitBlock;
        $this->scoreLimitSlow = (int)$scoreLimitSlow;
        $this->blockDuration = (int)$blockDuration;
        $this->scoreLimitAlert = (int)$scoreLimitAlert;
        $this->userAgent = $userAgent;
        $this->country = $country;
        $this->sendAlertEnabled = (bool)$sendAlertEnabled;
        $this->load();
    }


    /**
     * Retourne le statut actuel d'une IP : normal, slow, ou blocked.
     */
    public function getStatusForIp($ip)
    {
        if (!isset($this->data[$ip])) {
            return 'normal';
        }

        $entry = $this->data[$ip];
        $now = time();

        if (isset($entry['blocked_until']) && $entry['blocked_until'] > $now) {
            return 'blocked';
        }

        if ($entry['score'] <= $this->scoreLimitBlock) {
            // ✅ Ne poser le blocage que si ce n’est pas déjà fait
            if (!isset($entry['blocked_until']) || $entry['blocked_until'] < $now) {
                $this->data[$ip]['blocked_until'] = $now + $this->blockDuration;
                $this->save();
            }
            return 'blocked';
        }

        if ($entry['score'] <= $this->scoreLimitSlow) {
            return 'slow';
        }

        return 'normal';
    }

    /**
     * Met à jour le score d'une IP.
     */
    public function updateScore($ip, $variation)
    {
        if (!isset($this->data[$ip])) {
            $this->data[$ip] = [
                'score' => 0,
                'count' => 0,
                'log' => [],
                'contact_attempts' => [],
                'first_seen' => time(),
                'updated_at' => time(),
                'alerted' => false,
                'country' => $this->country,
            ];
        }
        $this->data[$ip]['score'] += $variation;
        $this->data[$ip]['updated_at'] = time();
        $this->data[$ip]['country'] = (empty($this->data[$ip]['country'])) ? $this->country : $this->data[$ip]['country'];
        // Si le score est redevenu acceptable, on enlève le blocage
        if ($this->data[$ip]['score'] > $this->scoreLimitBlock) {
            unset($this->data[$ip]['blocked_until']);
        }

        // Ajout d'une alerte si seuil dépassé et pas encore alerté
        if (
            $this->sendAlertEnabled &&
            $this->data[$ip]['score'] <= $this->scoreLimitAlert &&
            empty($this->data[$ip]['alerted'])
        ) {
            FirewallMailer::sendAlert($ip, $this->userAgent, $this->data[$ip]['score'], $this->country);
            $this->data[$ip]['alerted'] = true;
        }

        $this->save();
    }

    /**
     * Incrémente le compteur de visites pour une IP spécifique,
     * sans toucher au score. Utile pour suivre les IPs connues (bots, suspects…).
     *
     * @param string $ip
     */
    public function incrementVisit($ip)
    {
        if (!isset($this->data[$ip])) {
            $this->data[$ip] = [
                'score' => 0,
                'count' => 1,
                'log' => [],
                'contact_attempts' => [],
                'first_seen' => time(),
                'updated_at' => time(),
                'alerted' => false,
                'country' => $this->country,
            ];
        } else {
            if (!isset($this->data[$ip]['count'])) {
                $this->data[$ip]['count'] = 0;
            }
            $this->data[$ip]['count'] += 1;
            $this->data[$ip]['updated_at'] = time();
        }

        $this->save();
    }

    /**
     * Vérifie si une IP est déjà enregistrée.
     */
    public function has($ip)
    {
        return isset($this->data[$ip]);
    }

    /**
     * Récupère le score d'une IP.
     * @param $ip
     * @return int|mixed
     */
    public function getScore($ip)
    {
        return isset($this->data[$ip]['score']) ? $this->data[$ip]['score'] : 0;
    }

    public function getCount($ip)
    {
        return isset($this->data[$ip]['count']) ? $this->data[$ip]['count'] : 0;
    }

    /**
     * Ajoute un évènement au journal d'une IP.
     */
    public function logEvent($ip, $reason): void
    {
        if (!isset($this->data[$ip])) {
            $this->updateScore($ip, 0);
        }

        $this->data[$ip]['log'][] = [
            'time' => date('Y-m-d H:i:s'),
            'reason' => $reason
        ];

        if (count($this->data[$ip]['log']) > 200) {
            $this->data[$ip]['log'] = array_slice($this->data[$ip]['log'], -200);
        }

        $this->save();
    }

    /**
     * Supprime les IPs inactives depuis plus de X secondes.
     */
//    public function cleanup($timeout = 86400)
//    {
//        if($timeout == 0) {
//            return; // Pas de nettoyage si le timeout est 0
//        }
//        $now = time();
//        foreach ($this->data as $ip => $entry) {
//            if (($now - $entry['updated_at']) > $timeout) {
//                unset($this->data[$ip]);
//            }
//        }
//        $this->save();
//    }

    /**
     * Charge les données depuis le fichier JSON.
     */
    protected function load(): void
    {

        if (!file_exists($this->filepath)) {
            $this->data = [];
            return;
        }

        $fp = fopen($this->filepath, 'r');
        if ($fp && flock($fp, LOCK_SH)) { // Verrou lecture
            $json = stream_get_contents($fp);
            flock($fp, LOCK_UN);
            fclose($fp);

            $this->data = json_decode($json, true) ?: [];

            // Patch pour ajouter 'alerted'
            foreach ($this->data as &$ipData) {
                if (!isset($ipData['alerted'])) {
                    $ipData['alerted'] = false;
                }
            }
            unset($ipData);
        } elseif ($fp) {
            fclose($fp);
            $this->data = [];
        }
    }

    /**
     * Sauvegarde le fichier JSON des scores IP de manière atomique et sécurisée.
     */
    public function save(): void
    {
        if (!is_array($this->data)) {
            return;
        }

        $dir = dirname($this->filepath);
        $tempFile = tempnam($dir, 'tmp_fw_');

        if ($tempFile === false) {
            // Échec création fichier temporaire
            return;
        }

        $json = json_encode($this->data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $fp = fopen($tempFile, 'c');
        if ($fp === false) {
            return;
        }

        // Lock en écriture exclusive
        if (flock($fp, LOCK_EX)) {
            ftruncate($fp, 0);
            fwrite($fp, $json);
            fflush($fp); // Flush au disque
            flock($fp, LOCK_UN);
            fclose($fp);

            // Remplace l’ancien fichier par le nouveau (atomique sur système de fichiers Unix)
            rename($tempFile, $this->filepath);
        } else {
            fclose($fp);
            unlink($tempFile);
        }
    }

    /**
     * Gère le stockage des données pour une IP spécifique.
     * @param array{
     *   ip: string,
     *   log_event_reason: string,
     *   updateScore: bool,
     *   score: int
     * } $data
     */
    public function manageStorage(array $data)
    {
        // Validation simple
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
        $updateScore = $data['update_score'];
        $score = $data['score'];
        $logEventReason = $data['log_event_reason'];
        if ($updateScore) {
            $this->updateScore($ip, $score);
        }
        $this->incrementVisit($ip);
        $this->logEvent($ip, $logEventReason);
    }

    /**
     * Incrémente le compteur de tentatives de contact pour une IP spécifique.
     * Utilisé pour suivre les tentatives de contact (par exemple, via un formulaire).
     * @param $ip
     * @return void
     */
    public function incrementHourlyContactAttempt($ip): void
    {
        if (!isset($this->data[$ip])) {
            $this->updateScore($ip, 0); // Initialise l'entrée si absente
        }

        $hourKey = date('YmdH');
        $dayKey = date('Ymd');

        // Horaire
        if (!isset($this->data[$ip]['contact_attempts'])) {
            $this->data[$ip]['contact_attempts'] = [];
        }
        if (!isset($this->data[$ip]['contact_attempts'][$hourKey])) {
            $this->data[$ip]['contact_attempts'][$hourKey] = 0;
        }
        $this->data[$ip]['contact_attempts'][$hourKey]++;

        // Journalier
        if (!isset($this->data[$ip]['daily_attempts'])) {
            $this->data[$ip]['daily_attempts'] = [];
        }
        if (!isset($this->data[$ip]['daily_attempts'][$dayKey])) {
            $this->data[$ip]['daily_attempts'][$dayKey] = 0;
        }
        $this->data[$ip]['daily_attempts'][$dayKey]++;

        $this->data[$ip]['updated_at'] = time();

        $this->save();
    }


    /**
     * Incrémente le compteur de tentatives de contact pour une IP spécifique
     * sur une base quotidienne.
     * @param $ip
     * @return int|null
     */
    public function getDailyContactAttempts($ip): ?int
    {
        $key = date('Ymd');
        return $this->data[$ip]['daily_attempts'][$key] ?? 0;
    }

    /**
     * Récupère le nombre de tentatives de contact pour une IP spécifique
     * dans les X dernières minutes.
     *
     * @param string $ip
     * @param int $minutes Nombre de minutes à considérer
     * @return int Nombre de tentatives de contact dans la période spécifiée
     */
    public function getContactAttemptsInLastXMinutes($ip, $minutes)
    {
        if (!isset($this->data[$ip]['contact_attempts'])) {
            return 0;
        }

        $threshold = time() - ($minutes * 60);
        $count = 0;

        foreach ($this->data[$ip]['contact_attempts'] as $key => $val) {
            $timestamp = strtotime(substr($key, 0, 8) . ' ' . substr($key, 8, 2) . ':00:00');
            if ($timestamp >= $threshold) {
                $count += $val;
            }
        }

        return $count;
    }


    /**
     * Bloque une IP pour une durée définie.
     * Met à jour le champ 'blocked_until' de l'entrée IP.
     *
     * @param string $ip
     */
    public function blockIp($ip): void
    {
        $now = time();
        if (!isset($this->data[$ip])) {
            $this->updateScore($ip, 0); // Crée l'entrée si inexistante
        }

        $this->data[$ip]['blocked_until'] = $now + $this->blockDuration;
        $this->data[$ip]['updated_at'] = $now;

        $this->save();
    }

}

