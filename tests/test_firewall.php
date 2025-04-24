<html>
<head>
    <title>Firewall Test</title>
</head>
<body>
<?php

require_once dirname(__DIR__, 3) . '/config/config.inc.php';
require_once dirname(__DIR__, 3) . '/init.php';

// 🔧 Inclure les classes nécessaires du module
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStorage.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallStatsLogger.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/FirewallGeo.php';
require_once _PS_MODULE_DIR_ . 'sj4webfirewall/classes/Sj4webFirewallConfigHelper.php';

$ip = $_GET['ip'] ?? '8.8.8.8';
$userAgent = $_GET['ua'] ?? 'Mozilla/5.0';
$_SERVER['REMOTE_ADDR'] = $ip;
$_SERVER['HTTP_USER_AGENT'] = $userAgent;

$config = Sj4webFirewallConfigHelper::getAll();

// Parser les champs multilignes
foreach (['SJ4WEB_FW_WHITELIST_IPS', 'SJ4WEB_FW_SAFEBOTS', 'SJ4WEB_FW_MALICIOUSBOTS', 'SJ4WEB_FW_COUNTRIES_BLOCKED'] as $key) {
    if (is_string($config[$key]) && strpos($config[$key], "\n") !== false) {
        $config[$key] = array_map('trim', explode("\n", $config[$key]));
    }
}

$storage = new FirewallStorage(
    (int)$config['SJ4WEB_FW_SCORE_LIMIT_BLOCK'],
    (int)$config['SJ4WEB_FW_SCORE_LIMIT_SLOW'],
    (int)$config['SJ4WEB_FW_BLOCK_DURATION']
);

// 🧪 Test dans l’ordre logique

echo '<h2>Firewall test</h2>';
echo '<p><strong>IP :</strong> ' . $ip . '</p>';
echo '<p><strong>User-Agent :</strong> ' . $userAgent . '</p>';

function out($label) {
    echo '<p>🧪 <strong>' . $label . '</strong></p>';
//    exit;
}

// 1. IP whitelistée
if (in_array($ip, $config['SJ4WEB_FW_WHITELIST_IPS'])) {
    FirewallStatsLogger::logVisit($userAgent, 'human');
    out('WHITELIST');
}

// 2. Bloqué par score
$status = $storage->getStatusForIp($ip);
if ($status === 'blocked') {
    $storage->logEvent($ip, 'IP bloquée par score');
    FirewallStatsLogger::logVisit($userAgent, 'blocked_score');
    out('BLOCKED_SCORE');
}

// 3. Bot autorisé
$safeBotName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_SAFEBOTS']);
if ($safeBotName !== null) {
    if (!$storage->has($ip)) {
        $storage->updateScore($ip, 0);
    }
    $storage->logEvent($ip, 'IP OK - Bot SEO reconnu');
    FirewallStatsLogger::logVisit($userAgent, 'safe', $safeBotName);
    out('SAFE_BOT: ' . $safeBotName);
}

// 4. Bot malveillant
$badBotName = FirewallStatsLogger::detectBotName($userAgent, $config['SJ4WEB_FW_MALICIOUSBOTS']);
if ($badBotName !== null) {
    $storage->updateScore($ip, -25);
    $storage->logEvent($ip, 'bot_suspect');
    FirewallStatsLogger::logVisit($userAgent, 'bad', $badBotName);
    out('BAD_BOT: ' . $badBotName);
}

// 5. Blocage par pays
$geo = new FirewallGeo();
$country = $geo->getCountryCode($ip);
if ($country && in_array($country, $config['SJ4WEB_FW_COUNTRIES_BLOCKED'])) {
    $storage->updateScore($ip, -10);
    $storage->logEvent($ip, 'pays_bloque: ' . $country);
    FirewallStatsLogger::logVisit($userAgent, 'bad', 'pays:' . $country);
    out('BLOCKED_COUNTRY: ' . $country);
}

// 6. Ralentissement
$score = $storage->getScore($ip);
if ($config['SJ4WEB_FW_ENABLE_SLEEP'] && $score <= $config['SJ4WEB_FW_SCORE_LIMIT_SLOW']) {
    $storage->logEvent($ip, 'ralenti: score faible');
    FirewallStatsLogger::logVisit($userAgent, 'human');
    out('HUMAN (RALENTI)');
}

// 7. Visiteur humain classique
FirewallStatsLogger::logVisit($userAgent, 'human');
out('HUMAN NORMAL');
?>

<hr>
<h3>Tests rapides</h3>
<p>Cliquer sur un cas pour simuler :</p>
<ul>
    <li><a href="?ip=127.0.0.1&ua=Mozilla/5.0">🟢 IP whitelistée (127.0.0.1)</a></li>
    <li><a href="?ip=8.8.8.8&ua=Mozilla/5.0">🔴 IP bloquée par score (manuellement)</a></li>
    <li><a href="?ip=9.9.9.9&ua=Googlebot">🟢 Bot SEO autorisé (Googlebot)</a></li>
    <li><a href="?ip=10.10.10.10&ua=AhrefsBot">🔴 Bot malveillant (AhrefsBot)</a></li>
    <li><a href="?ip=11.11.11.11&ua=Mozilla/5.0">🌍 IP bloquée par pays (ex: CN, si configuré)</a></li>
    <li><a href="?ip=12.12.12.12&ua=Mozilla/5.0">👤 Visiteur normal</a></li>
</ul>

<form method="get" style="margin-top:20px;">
    <h4>Test personnalisé :</h4>
    <label>IP : <input type="text" name="ip" value="<?= htmlspecialchars($ip) ?>" /></label><br>
    <label>User-Agent : <input type="text" name="ua" value="<?= htmlspecialchars($userAgent) ?>" size="80" /></label><br>
    <button type="submit">Tester</button>
</form>
</body>
</html>