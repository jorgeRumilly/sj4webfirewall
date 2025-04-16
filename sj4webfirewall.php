<?php
if (!defined('_PS_VERSION_')) {
    exit;
}

class Sj4webFirewall extends Module
{
    public function __construct()
    {
        $this->name = 'sj4webfirewall';
        $this->tab = 'security';
        $this->version = '1.0.0';
        $this->author = 'SJ4WEB.FR';
        $this->need_instance = 0;

        parent::__construct();

        $this->displayName = $this->l('SJ4WEB Firewall');
        $this->description = $this->l('Module de filtrage comportemental, IP et bots.');
    }

    public function install()
    {
        return parent::install() && $this->registerHook('displayBeforeHeader');
    }

    public function hookDisplayBeforeHeader()
    {
        $ip = Tools::getRemoteAddr();
        $userAgent = Tools::getUserAgent();

        // Liste des IP autorisées (whitelist)
        $allowedIPs = [
            '88.125.107.215',
            '31.35.195.23',
            '91.172.92.135',
        ];

        // Ranges IPv6 simples (à étendre avec validation CIDR si besoin)
        $allowedIP6Prefixes = [
            '2a01:e0a:55a:f5e0::',
            '2001:861:43c0:3170::'
        ];

        // Bots SEO acceptés
        $safeBots = [
            'googlebot', 'bingbot', 'duckduckbot', 'yandexbot', 'baiduspider', 'msnbot',
            'slurp', 'facebot', 'ia_archiver'
        ];

        // Bots ou agents suspects connus
        $maliciousBots = [
            'ahrefsbot', 'semrushbot', 'mj12bot', 'dotbot', 'rogerbot', 'linkpadbot',
            'screaming frog seo spider', 'sitebulb', 'seokicks-robot', 'linkchecker',
            'netpeak spider', 'buzzbot', 'spbot', 'curl', 'python-requests', 'wget',
            'oppo\\sa33', '(?:c99|php|web)shell', 'site.{0,2}copier', 'base64_decode',
            'bin/bash', 'disconnect', 'eval', 'unserializ', 'libwww-perl', 'pycurl',
            'scan', 'ahref', 'acapbot', 'acoonbot', 'alexibot', 'asterias', 'attackbot',
            'babbar', 'barkrowler', 'backdorbot', 'becomebot', 'binlar', 'blackwidow',
            'blekkobot', 'blexbot', 'blowfish', 'bullseye', 'bunnys', 'butterfly',
            'bytespider', 'careerbot', 'casper', 'checkpriv', 'cheesebot', 'cherrypick',
            'chinaclaw', 'choppy', 'clshttp', 'cmsworld', 'copernic', 'copyrightcheck',
            'cosmos', 'crescent', 'cy_cho', 'datacha', 'demon', 'diavol', 'discobot',
            'dittospyder', 'dotbot', 'dotnetdotcom', 'dumbot', 'econtext',
            'emailcollector', 'emailsiphon', 'emailwolf', 'eolasbot', 'eventures',
            'extract', 'eyenetie', 'feedfinder', 'flaming', 'flashget', 'flicky',
            'foobot', 'fuck', 'g00g1e', 'getright', 'gigabot', 'go-ahead-got', 'gozilla',
            'grabnet', 'grafula', 'harvest', 'heritrix', 'httracks?', 'icarus6j', 'jetbot',
            'jetcar', 'jikespider', 'kmccrew', 'leechftp', 'libweb', 'liebaofast',
            'linkscan', 'linkwalker', 'loader', 'lwp-download', 'majestic', 'masscan',
            'miner', 'mechanize', 'mj12bot', 'morfeus', 'moveoverbot', 'netmechanic',
            'netspider', 'nicerspro', 'nikto', 'ninja', 'nominet', 'nutch', 'octopus',
            'pagegrabber', 'planetwork', 'postrank', 'proximic', 'purebot', 'queryn',
            'queryseeker', 'radian6', 'radiation', 'realdownload', 'remoteview',
            'rogerbot', 'scan', 'scooter', 'seekerspid', 'serpstatbot', 'semalt',
            'siclab', 'sindice', 'sistrix', 'sitebot', 'siteexplorer', 'sitesnagger',
            'skygrid', 'smartdownload', 'snoopy', 'sosospider', 'spankbot', 'spbot',
            'sqlmap', 'stackrambler', 'stripper', 'sucker', 'surftbot', 'sux0r',
            'suzukacz', 'suzuran', 'takeout', 'teleport', 'telesoft', 'true_robots',
            'turingos', 'turnit', 'vampire', 'vikspider', 'voideye', 'webleacher',
            'webreaper', 'webstripper', 'webvac', 'webviewer', 'webwhacker', 'winhttp',
            'wwwoffle', 'woxbot', 'xaldon', 'xxxyy', 'yamanalab', 'yioopbot', 'youda',
            'zeus', 'zmeu', 'zune', 'zyborg', '80legs', 'curl', 'wget', 'python-requests',
            'python-urllib', 'scrapy', 'httpclient', 'nikto', 'libwww-perl', 'nmap',
            'fimap', 'httprint', 'httprecon', 'zmeu', 'bcrawl', 'blackwidow', 'paros',
            'w3af', 'nessus', 'whatweb', 'openvas', 'sf', 'jaeles', 'arachni', 'acunetix',
            'netsparker', 'dirbuster', 'dirb', 'gobuster', 'webscarab', 'webshag',
            'metasploit', 'sqlninja', 'sqlsus', 'sqlbrute', 'sqlpwn', 'sqliv', 'sqlmap',
            'sqlmate', 'sqlscan', 'sqlsec', 'sqlsploit', 'sqltool', 'sqlworm', 'sqlx',
            'sqlz'
        ];

        // Vérification whitelist IP
        if (in_array($ip, $allowedIPs)) {
            return;
        }

        foreach ($allowedIP6Prefixes as $prefix) {
            if (stripos($ip, $prefix) === 0) {
                return;
            }
        }

        // Vérification safe bot
        foreach ($safeBots as $bot) {
            if (stripos($userAgent, $bot) !== false) {
                return;
            }
        }

        // Vérification bots suspects ou outils de scan
        foreach ($maliciousBots as $bad) {
            if (stripos($userAgent, $bad) !== false) {
                header('HTTP/1.1 403 Forbidden');
                exit('Access denied.');
            }
        }

        // Exemple : ralentir tous les agents inconnus non whitelistés
        if ($userAgent === '' || $userAgent === '-' || strlen($userAgent) < 10) {
            usleep(1000000); // 1 seconde
        }
    }
}
