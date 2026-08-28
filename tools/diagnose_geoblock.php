<?php
/**
 * Diagnostic du blocage géo en amont (index.php) — vérifie une par une les
 * conditions dont dépend sj4webGeoBlockIpInRange()/le bloc IIFE d'index.php,
 * pour identifier exactement pourquoi rien ne se bloque (le bloc est
 * volontairement fail-open : au moindre souci il laisse tout passer en
 * silence, donc "rien de cassé + rien de bloqué" ne dit pas OÙ ça coince).
 *
 * Usage : php diagnose_geoblock.php   (SSH uniquement, jamais via navigateur)
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit("Réservé à une exécution en ligne de commande (SSH).\n");
}

$root = dirname(__DIR__); // .../modules/sj4webfirewall
$psRoot = dirname($root, 2); // racine PrestaShop

function ok(string $label): void { echo "  [OK]   $label\n"; }
function ko(string $label): void { echo "  [KO]   $label\n"; }
function info(string $label): void { echo "         $label\n"; }

echo "=== 1. Fichiers requis ===\n";

$cacheFile = $root . '/geo/country_block_cache.php';
$mmdbFile = $root . '/geo/GeoLite2-Country.mmdb';
$autoloadFile = $root . '/vendor/autoload.php';
$indexFile = $psRoot . '/index.php';

$allFilesOk = true;

if (is_file($cacheFile)) {
    ok("country_block_cache.php présent ($cacheFile)");
} else {
    ko("country_block_cache.php ABSENT ($cacheFile)");
    info("-> Le formulaire d'admin (Pays à bloquer) n'a jamais été sauvegardé sur CET environnement,");
    info("   ou le fichier n'a pas été transféré / les droits d'écriture ont échoué.");
    $allFilesOk = false;
}

if (is_file($mmdbFile)) {
    ok("GeoLite2-Country.mmdb présent (" . round(filesize($mmdbFile) / 1024, 0) . " Ko)");
} else {
    ko("GeoLite2-Country.mmdb ABSENT ($mmdbFile)");
    info("-> Souvent exclu du déploiement (fichier binaire, .gitignore). A transférer manuellement.");
    $allFilesOk = false;
}

if (is_file($autoloadFile)) {
    ok("vendor/autoload.php présent");
} else {
    ko("vendor/autoload.php ABSENT ($autoloadFile)");
    info("-> Le dossier vendor/ du module (dépendance geoip2/geoip2) n'est pas déployé.");
    info("   Souvent exclu par .gitignore : besoin d'un 'composer install' sur ce dossier,");
    info("   ou de transférer vendor/ manuellement depuis un environnement où il existe.");
    $allFilesOk = false;
}

if (is_file($indexFile)) {
    $content = file_get_contents($indexFile);
    if (strpos($content, 'sj4webGeoBlockIpInRange') !== false) {
        ok("index.php contient bien le bloc de blocage géo");
    } else {
        ko("index.php NE CONTIENT PAS le bloc de blocage géo");
        info("-> Le fichier déployé sur cet environnement n'est pas la version modifiée.");
        $allFilesOk = false;
    }
} else {
    ko("index.php introuvable à la racine attendue ($indexFile)");
    $allFilesOk = false;
}

echo "\n=== 2. Contenu du cache pays ===\n";
if (is_file($cacheFile)) {
    $data = include $cacheFile;
    $countries = is_array($data['countries'] ?? null) ? $data['countries'] : [];
    $whitelist = is_array($data['whitelist'] ?? null) ? $data['whitelist'] : [];

    if (!empty($countries)) {
        ok('Pays bloqués : ' . implode(', ', $countries));
    } else {
        ko('Liste de pays VIDE dans le cache — rien ne peut être bloqué même si tout le reste fonctionne.');
        info('-> Vérifie que le champ "Pays à bloquer" du formulaire contient bien RU/BR/SG/TW et a été enregistré.');
    }
    info('Whitelist (' . count($whitelist) . ' entrée(s)) : ' . (empty($whitelist) ? '(vide)' : implode(', ', $whitelist)));
    info('Généré le : ' . ($data['generated_at'] ?? '?'));
} else {
    info('(ignoré, fichier absent — voir section 1)');
}

echo "\n=== 3. Résolution GeoIP réelle ===\n";
if (is_file($mmdbFile) && is_file($autoloadFile)) {
    require_once $autoloadFile;
    $testIps = [
        '62.183.17.207' => 'RU (Rostelecom, vu dans les vrais logs)',
        '131.161.1.87' => 'BR (vu dans les vrais logs)',
        '43.172.194.153' => 'SG (Tencent Cloud, vu dans les vrais logs)',
        '82.65.10.5' => 'FR (référence, ne doit jamais être bloqué)',
    ];
    try {
        $reader = new \GeoIp2\Database\Reader($mmdbFile);
        foreach ($testIps as $ip => $label) {
            try {
                $iso = $reader->country($ip)->country->isoCode;
                ok("$ip ($label) -> résolu en \"$iso\"");
            } catch (\Throwable $e) {
                ko("$ip ($label) -> échec de résolution : " . $e->getMessage());
            }
        }
    } catch (\Throwable $e) {
        ko('Impossible d\'ouvrir la base GeoIP : ' . $e->getMessage());
    }
} else {
    info('(ignoré, mmdb ou vendor absent — voir section 1)');
}

echo "\n=== 4. Horodatage / OPcache ===\n";
if (is_file($indexFile)) {
    info('index.php modifié le : ' . date('Y-m-d H:i:s', filemtime($indexFile)));
}
if (function_exists('opcache_get_status')) {
    $status = @opcache_get_status(false);
    if ($status && !empty($status['opcache_enabled'])) {
        $validate = ini_get('opcache.validate_timestamps');
        info('OPcache actif — opcache.validate_timestamps = ' . ($validate === '' ? '(défaut: 1)' : $validate));
        if ($validate === '0') {
            ko('validate_timestamps=0 : index.php modifié ne sera PAS repris tant que l\'OPcache n\'est pas vidé.');
        } else {
            ok('validate_timestamps actif : les modifications de fichiers sont prises en compte automatiquement.');
        }
    } else {
        info('OPcache non actif sur cet environnement CLI (peut différer du contexte PHP-FPM web — non vérifiable depuis ce script).');
    }
} else {
    info('Extension OPcache non chargée pour ce SAPI (normal en CLI sur certains hébergements).');
}

echo "\n=== Résumé ===\n";
echo $allFilesOk
    ? "Tous les fichiers requis sont présents — si le blocage ne fonctionne toujours pas, le souci est probablement l'OPcache web (section 4) ou la liste de pays vide (section 2).\n"
    : "Au moins un fichier requis est manquant (voir [KO] ci-dessus) — c'est très probablement la cause du \"rien ne se bloque\".\n";
