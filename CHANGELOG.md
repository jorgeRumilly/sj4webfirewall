# Changelog

Tous les changements notables de ce projet seront documentés dans ce fichier.

Le format est basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/), et ce projet suit [SemVer](https://semver.org/lang/fr/).

---

## [1.3.0] - 2025-06-11
### Ajouté
- Ajout d’un tri dynamique dans la page des logs IP (`HelperList`) sur tous les champs sauf actions.
- Tri différencié selon le type de colonnes : chaînes, entiers, dates (`usort` sur `Tools::getValue()`).
- Filtrage par date (plages `first_seen` / `updated_at`) via comparaison nette des jours (`Y-m-d`) sans heuristique bancale.
- Bouton "Réinitialiser les filtres" fonctionnel, suppression ciblée des clés `firewall_logsFilter_*` dans `$_GET` et `$_POST`.
- **Création de plusieurs onglets (Tabs) dans le Back-Office** : logs IP, stats, configuration, etc.

### Amélioré
- Séparation du tri/filtrage dans `applyFilters()` pour améliorer la lisibilité.
- Renforcement de la propreté et portabilité : suppression des formats de date codés en dur.

---

## [1.2.0] - 2025-06-07
### Ajouté
- Ajout de la possibilité de bloquer/débloquer manuellement une IP depuis le Back-Office.

### Corrigé
- Correction d’un problème de gestion des logs.
- Correction d’une erreur de type dans une clé du tableau de scoring.
- Amélioration de la récupération du code pays depuis l'IP avec gestion des erreurs (`try/catch`).
- Correction de la détection et du traitement des erreurs 404 et 403.

---

## [1.1.0] - 2025-06-06
### Ajouté
- Remplacement du système de log IP par un stockage journalier pour une meilleure traçabilité.
- Amélioration de la gestion du scoring IP.
- Ajout de l’envoi d’alertes par e-mail en cas d'excès de 404 ou 403.
- Création des templates d’e-mails d’alerte.
- Début de l’internationalisation (traductions via le nouveau système PrestaShop).
- Paramétrage des seuils de déclenchement dans la configuration du module.
- Encapsulation des méthodes propres au firewall pour un code plus modulaire.
- Intégration de la librairie GeoIP pour détecter le pays d’origine des visiteurs.

---

## [1.0.0] - 2025-04-19
### Ajouté
- Mise en place initiale du module `sj4webfirewall`.
- Détection et gestion des IPs et bots par scoring.
- Système de ralentissement ou blocage selon le score IP.
- Formulaire de configuration en Back-Office PrestaShop.
- Système de whitelist (IP et bots) configurable.
- Détection des bots malveillants vs bots SEO safe.
- Logs des actions IP (`ip_scores.json`) et journalisation texte.
- Intégration GeoIP Lite pour la localisation par pays.
- Premières protections sur le hook `displayBeforeHeader`.
- Page de logs dans le Back-Office (Admin Controller dédié).

---
