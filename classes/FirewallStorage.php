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
        $this->scoreLimitBlock = (int) $scoreLimitBlock;
        $this->scoreLimitSlow = (int) $scoreLimitSlow;
        $this->blockDuration = (int) $blockDuration;
        $this->scoreLimitAlert = (int) $scoreLimitAlert;
        $this->userAgent = $userAgent;
        $this->country = $country;
        $this->sendAlertEnabled = (bool) $sendAlertEnabled;
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
                'first_seen' => time(),
                'updated_at' => time(),
                'alerted' => false,
                'country' => $this->country,
            ];
        }
        $this->data[$ip]['score'] += $variation;
        $this->data[$ip]['updated_at'] = time();
        $this->data[$ip]['country'] = (empty($this->data[$ip]['country'])) ? $this->country : $this->data[$ip]['country'];
        // ✅ Si le score est redevenu acceptable, on enlève le blocage
        if ($this->data[$ip]['score'] > $this->scoreLimitBlock) {
            unset($this->data[$ip]['blocked_until']);
        }

        // 🚨 Ajout d'une alerte si seuil dépassé et pas encore alerté
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
    public function logEvent($ip, $reason)
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
    protected function load()
    {
        if (file_exists($this->filepath)) {
            $json = file_get_contents($this->filepath);
            $this->data = json_decode($json, true) ?: [];
            // Patch pour ajouter 'alerted'
            foreach ($this->data as &$ipData) {
                if (!isset($ipData['alerted'])) {
                    $ipData['alerted'] = false;
                }
            }
            unset($ipData);
        }
    }

    /**
     * Sauvegarde les données dans le fichier JSON.
     */
    protected function save()
    {
        file_put_contents($this->filepath, json_encode($this->data, JSON_PRETTY_PRINT));
    }

    /**
     * @param array{
     *   ip: string,
     *   log_event_reason: string,
     *   updateScore: bool,
     *   score: int
     * } $data
     */
    public function manageStorage(array $data) {
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
        if( $updateScore ) {
            $this->updateScore($ip, $score);
        }
        $this->incrementVisit($ip);
        $this->logEvent($ip, $logEventReason);
    }

}

