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
        $this->filepath = _PS_MODULE_DIR_.'sj4webfirewall/logs/ip_scores.json';
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
            $this->data[$ip]['blocked_until'] = $now + $this->blockDuration;
            $this->save();
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
                'log' => [],
                'updated_at' => time(),
            ];
        }

        $this->data[$ip]['score'] += $variation;
        $this->data[$ip]['updated_at'] = time();
        $this->save();
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

        if (count($this->data[$ip]['log']) > 20) {
            $this->data[$ip]['log'] = array_slice($this->data[$ip]['log'], -20);
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

