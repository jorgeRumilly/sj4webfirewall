**Cahier des charges fonctionnel**
**Module de surveillance comportementale et protection IP pour PrestaShop**

---

### ✅ **Objectif principal**

Développer un **module PrestaShop maison** nommé `sj4webfirewall` permettant de **surveiller, analyser et protéger** dynamiquement la boutique contre les comportements suspects (bots, spams, scans d'URL, abus de formulaires), sans nuire à l'expérience utilisateur ou au référencement.

---

### ⚙️ **Structure technique et fondations**

#### 📁 Arborescence du module (fondation technique solide)
```
/modules/sj4webfirewall/
├── sj4webfirewall.php                       ← module principal
├── config/
│   ├── config.xml                           ← déclaration PrestaShop
│   ├── default_config.php                   ← valeurs par défaut
├── classes/
│   ├── FirewallScanner.php                  ← analyse des requêtes
│   ├── FirewallStorage.php                  ← gestion des scores/logs
│   └── FirewallGeo.php                      ← intégration GeoIP
├── controllers/
│   └── admin/
│       └── AdminSj4webFirewallController.php ← interface BO
├── views/
│   └── templates/
│       └── admin/
│           └── configure.tpl                ← affichage config
├── geo/
│   └── GeoLite2-Country.mmdb                ← base MaxMind locale
├── logs/
│   └── firewall.log                         ← journalisation locale
├── vendor/
│   └── autoload.php                         ← pour MaxMind via Composer
```

#### 📦 Librairies et dépendances
- `geoip2/geoip2` (via Composer) : détection de pays MaxMind
- `SQLite` ou fichier `JSON` pour score et historique IP (pas de base SQL lourde)

---

### ⚖️ **Fonctionnalités attendues**

#### 1. **Filtrage intelligent des requêtes entrantes**
- Détection de :
    - User-Agents suspects (Python-requests, curl, wget, etc.)
        - ❌ Bloqués sauf si l'IP est explicitement autorisée (liste blanche technique)
    - Accès interdits (ex : /wp-admin, /wp-login, /.env, etc.)
    - Requêtes POST suspects (flood formulaire, rapidité d’envoi, honeypot rempli)
    - Requêtes anormales (sans referer, trop fréquentes, etc.)
    - Taux d’erreur 404 anormal par IP
    - Rythme suspect mais espacé ("spam doux" toutes les X minutes)
- Attribution d'un **score de confiance dynamique par IP** (positif/négatif).
- Possibilité de :
    - **Laisser passer** les IPs whitelistées
    - **Bloquer immédiatement** les IPs blacklistées
    - **Ralentir (sleep)** les IPs suspectes (sans bloquer)
    - **Appliquer des restrictions par pays** (via GeoLite2 - MaxMind)

#### 2. **Configuration back-office**
- Interface de configuration accessible depuis le menu Modules :
    - Liste blanche (IP ou pattern User-Agent, avec priorité pour les cas techniques : scripts internes, CRONs, etc.)
    - Liste noire (IP ou User-Agent à bloquer dès la première action)
    - Listes `safeBots` et `maliciousBots` modifiables
    - Liste des pays à bloquer totalement ou à surveiller de manière renforcée
    - Seuils de tolérance par type d’action (ex : 5 404/minute)
    - Durée de blocage IP temporaire (ex : 3600s)
    - Activation/désactivation des délais automatiques (sleep)
    - Activer/désactiver la surveillance formulaire de contact

#### 3. **Journalisation et statistiques**
- Journal des activités suspectes :
    - IP, date, URI, user-agent, score, action déclenchée, pays détecté
- Tableau de bord admin :
    - Liste des IPs récemment bloquées ou ralenties
    - Historique de score des IPs
    - Export CSV possible des logs
    - Affichage par pays d’origine (via MaxMind)

#### 4. **Surveillance des formulaires sensibles**
- Détection des comportements spam (formulaire contact, etc.)
- Protection invisible :
    - Honeypot (champ invisible)
    - Timer minimum de soumission (ex : > 3 secondes)
    - Token ou hash anti-bot
    - Détection de "spam doux" : soumissions espacées mais répétées sur une période (ex : 1 toutes les 10 minutes)
- Journalisation des soumissions suspectes

#### 5. **Comportement adaptatif (modulable)**
- Pas de blocage permanent : durée temporaire configurable
- Score réinitialisé après X minutes d'inactivité
- Ajout facile d'extensions futures (ex : blocage par pays, intégration GeoIP)
- Ralentissement ciblé des IPs douteuses (ex : sleep de 1 à 3s selon gravité)

---

### 🚀 **Contraintes techniques**
- Compatible **PrestaShop >= 8.0**
- Aucune dépendance à un service externe (Cloudflare, etc.)
- Doit fonctionner sans accès root au serveur
- Journalisation légère (JSON, SQLite ou flat-file optimisé)
- Aucun impact visible pour l’utilisateur lambda
- Ne pas bloquer les bots SEO connus
- Utilisation préférentielle de **hooks natifs** (ex : `displayBeforeHeader`, `actionDispatcher`, etc.) pour intercepter les requêtes sans override si possible.
    - Si besoin spécifique, fallback possible en override du `FrontController`.
- Utilisation de **MaxMind GeoLite2** (base locale .mmdb) pour détection de pays

---

### 🔧 **Pistes techniques retenues**
- Utilisation de **hooks système PrestaShop** (ex : `displayBeforeHeader`, `actionDispatcher`) pour capturer les requêtes sans perturber le coeur.
- Utilisation d'un **score IP** pour décisions (plutôt qu’un blocage brut)
- Fichier de log ou base SQLite pour journalisation
- Hook sur le formulaire de contact pour protection supplémentaire
- En cas de pic d'activité suspecte (DDoS), détection comportementale sur la zone grise (IP avec score < seuil, + requêtes rapides ou trop régulières + user-agent flou), déclenche un **ralentissement massif temporaire** (sleep global ou anti-flood plus agressif)
- Vérification pays d'origine sur chaque IP détectée grâce à MaxMind GeoLite2

---

### 📅 **Livrables attendus**
1. Module PrestaShop installable (.zip)
2. Interface de configuration back-office
3. Dashboard de surveillance (tableau de bord)
4. Mécanisme de filtrage actif (live)
5. Fichier README de déploiement et documentation technique courte

---

### 💡 **Vision à long terme (v2 ou +)**
- Intégration GeoIP pour visualiser les origines
- Envoi automatique de mails d’alerte admin
- Système de "quarantaine IP" auto-nettoyante
- Statistiques par type de menace (spam, scan, brute force)
- Blocage ciblé par continent, ASN ou pays à risque

---

Document rédigé pour servir de base à un développement modulaire clair, compréhensible et évolutif.
