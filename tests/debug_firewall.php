<?php

require_once dirname(__DIR__) . '/../../config/config.inc.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStatsLogger.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStorage.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallGeo.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/Sj4webFirewallConfigHelper.php';

class TestFirewallHook
{
    private $fakeIp;
    private $fakeUserAgent;

    private $fakeHttpCode = 200; // Simulated HTTP code for testing

    public function __construct($ip, $userAgent, $fakeHttpCode = 200)
    {
        $this->fakeIp = $ip;
        $this->fakeUserAgent = $userAgent;
        $this->fakeHttpCode = $fakeHttpCode;
    }

    public function getUserAgent()
    {
        return $this->fakeUserAgent;
    }

    public function isIpWhitelisted($ip, $whitelist)
    {
        return in_array($ip, is_array($whitelist) ? $whitelist : []);
    }

    public function isKnownSafeBot($userAgent, $safeBots)
    {
        foreach ($safeBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                return true;
            }
        }
        return false;
    }

    public function isMaliciousBot($userAgent, $badBots)
    {
        foreach ($badBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                return true;
            }
        }
        return false;
    }

    public function logAction($ip, $userAgent, $reason)
    {
        echo "LogAction: IP=$ip, Reason=$reason\n";
    }

    public function hookDisplayHeader()
    {
        $config = Sj4webFirewallConfigHelper::getAll();
        $ip = $this->fakeIp;
        $userAgent = $this->getUserAgent();

        try {
            foreach (['SJ4WEB_FW_WHITELIST_IPS', 'SJ4WEB_FW_SAFEBOTS', 'SJ4WEB_FW_MALICIOUSBOTS', 'SJ4WEB_FW_COUNTRIES_BLOCKED'] as $key) {
                if (is_string($config[$key]) && strpos($config[$key], "\n") !== false) {
                    $config[$key] = array_map('trim', explode("\n", $config[$key]));
                }
            }

            // GeoIP
            $geo = new FirewallGeo();
            $country = $geo->getCountryCode($ip) ?: 'null';
            echo "Pays détecté pour l'IP $ip : $country<br/>\n";

            $is_active_firewall = (bool)$config['SJ4WEB_FW_ACTIVATE_FIREWALL'] ?? false;

            $storage = new FirewallStorage(
                (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
                (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
                (int)$config['SJ4WEB_FW_BLOCK_DURATION'],
                (int)$config['SJ4WEB_FW_ALERT_THRESHOLD'],
                $userAgent,
                $country,
                (bool)$config['SJ4WEB_FW_ALERT_EMAIL_ENABLED']
            );
            $score = $storage->getScore($ip);

            if ($this->isIpWhitelisted($ip, $config['SJ4WEB_FW_WHITELIST_IPS'])) {
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);
                echo "Whitelisted, accès autorisé<br/>\n";
                return;
            }

            $status = $storage->getStatusForIp($ip);
            if ($status === 'blocked') {
                $storage->logEvent($ip, 'IP bloquée par score');
                $storage->incrementVisit($ip);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'blocked', null, $country, 403, $score);
                echo "403 Access Denied (blocked by score)<br/>\n";
                return;
            }

            if ($this->isKnownSafeBot($userAgent, $config['SJ4WEB_FW_SAFEBOTS'])) {
                if (!$storage->has($ip)) {
                    $storage->updateScore($ip, 0);
                }
                $storage->incrementVisit($ip);
                $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_SAFEBOTS']);
                $storage->logEvent($ip, 'IP OK - Bot SEO reconnu - ' . $botName);
                $this->logAction($ip, $userAgent, 'safe_bot');
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_safe', $botName, $country, 200, $score);
                echo "Bot safe ($botName), accès autorisé<br/>\n";
                return;
            }

            if ($this->isMaliciousBot($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS'])) {
                $botName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS']);
                $storage->updateScore($ip, -20);
                $storage->incrementVisit($ip);
                $storage->logEvent($ip, 'bot_suspect - ' . $botName);
                $this->logAction($ip, $userAgent, 'bot_suspect');
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', $botName, $country, 403, $score);
                echo "403 Access Denied (malicious bot: $botName)<br/>\n";
                return;
            }

            if ($country && in_array($country, $config['SJ4WEB_FW_COUNTRIES_BLOCKED'])) {
                $storage->updateScore($ip, -10);
                $storage->incrementVisit($ip);
                $storage->logEvent($ip, 'pays_bloque: ' . $country);
                $this->logAction($ip, $userAgent, 'pays_bloque: ' . $country);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'bot_malicious', 'pays:' . $country, $country, 403, $score);
                echo "403 Access Denied (country blocked: $country)<br/>\n";
                return;
            }

            if ($config['SJ4WEB_FW_ENABLE_SLEEP'] && $score <= $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
                $storage->logEvent($ip, 'ralenti: score faible');
                $storage->incrementVisit($ip);
                FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, 200, $score);
                echo "Slow down applied<br/>\n";
                return;
            }

            // Default case
            $httpCode = $this->fakeHttpCode;
            // Degrade le score si 404 ou 403
            if ($httpCode === 404) {
                $storage->updateScore($ip, -1);
            }
            if ($httpCode === 403) {
                $storage->updateScore($ip, -5);
            }
            FirewallStatsLogger::logVisitPerIp($ip, $userAgent, 'human', null, $country, $httpCode, $score);
            echo "Accès normal, code HTTP ".$httpCode."<br/>\n";

        } catch (Exception $e) {
            $this->logAction($ip, $userAgent, 'Erreur execution : ' . $e->getMessage());
        }
    }
}

// Exemple de test
//$test = new TestFirewallHook('185.177.126.152', 'curl/8.12.1');
// $test = new TestFirewallHook('162.19.24.167', 'curl/8.12.1');
for($i=0; $i < 60; $i++) {
    $test = new TestFirewallHook('77.111.246.48', 'jorgenl.com/1.0 (+https://jorgenl.com)', 404);
    $test->hookDisplayHeader();
}

for($i=0; $i < 40; $i++) {
    $test = new TestFirewallHook('149.102.242.89', 'jorgenl.com/1.0 (+https://jorgenl.com)', 403);
    $test->hookDisplayHeader();
}
