<?php

if (!defined('_PS_VERSION_')) {
    exit;
}

class FirewallStorage
{
    protected $filepath;
    protected $data = [];
    protected $scoreLimitBlock;
    protected $scoreLimitSlow;
    protected $blockDuration;

    /**
     * Initialise la classe de stockage avec les seuils et le chemin du fichier JSON.
     */
    public function __construct($scoreLimitBlock = -40, $scoreLimitSlow = -10, $blockDuration = 3600)
    {
        $logsDir = _PS_MODULE_DIR_ . 'sj4webfirewall/logs/';

        if (!is_dir($logsDir)) {
            mkdir($logsDir, 0755, true);
        }

        $this->filepath = $logsDir . 'ip_scores.json';
        $this->scoreLimitBlock = $scoreLimitBlock;
        $this->scoreLimitSlow = $scoreLimitSlow;
        $this->blockDuration = $blockDuration;
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
                'updated_at' => time(),
            ];
        }
        $this->data[$ip]['score'] += $variation;
        $this->data[$ip]['updated_at'] = time();
        // ✅ Si le score est redevenu acceptable, on enlève le blocage
        if ($this->data[$ip]['score'] > $this->scoreLimitBlock) {
            unset($this->data[$ip]['blocked_until']);
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
                'updated_at' => time(),
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
    public function cleanup($timeout = 86400)
    {
        $now = time();
        foreach ($this->data as $ip => $entry) {
            if (($now - $entry['updated_at']) > $timeout) {
                unset($this->data[$ip]);
            }
        }
        $this->save();
    }

    /**
     * Charge les données depuis le fichier JSON.
     */
    protected function load()
    {
        if (file_exists($this->filepath)) {
            $json = file_get_contents($this->filepath);
            $this->data = json_decode($json, true) ?: [];
        }
    }

    /**
     * Sauvegarde les données dans le fichier JSON.
     */
    protected function save()
    {
        file_put_contents($this->filepath, json_encode($this->data, JSON_PRETTY_PRINT));
    }
}

