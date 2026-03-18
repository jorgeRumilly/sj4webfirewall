# SJ4WEB - Firewall pour PrestaShop

Module de protection comportementale pour PrestaShop 8.1+, avec suivi des IP, protection du formulaire de contact, statistiques journalieres et persistance SQL robuste.

## Fonctionnalites principales

- Scoring des IP avec ralentissement ou blocage selon le score.
- Gestion des bots safe et des user-agents suspects.
- Protection du formulaire de contact via honeypot, temporisation et limites par IP.
- Statistiques journalieres agregees par IP.
- Journalisation detaillee facultative dans `logs/firewall.log`.
- Purge automatique des donnees anciennes pour garder un module stable dans le temps.

## Stockage

Depuis la version `1.5.0`, le module n'utilise plus `logs/ip_scores.json` comme source de verite runtime.

Le stockage principal repose sur des tables SQL dediees :

- etat courant des IPs
- evenements detailles
- tentatives du formulaire de contact
- statistiques journalieres

Le JSON legacy peut etre importe automatiquement lors de l'upgrade.

## Compatibilite

- PrestaShop : `8.1.x+`
- PHP : `>= 7.4`

## Installation / upgrade

1. Copier le module dans `modules/sj4webfirewall`.
2. Installer le module depuis le BO, ou lancer l'upgrade vers `1.5.0`.
3. Verifier que les tables SQL du module ont bien ete creees.
4. Verifier la configuration BO avant activation effective du firewall.

## Recommandations de production

- Laisser `SJ4WEB_FW_LOG_ENABLED` desactive en routine.
- Garder le firewall en mode observation avant d'activer les blocages si la configuration bots n'a pas encore ete revue.
- Verifier les whitelists IP et user-agents apres migration.
- Nettoyer ensuite les anciens fichiers `tmp_fw_*`, `ip_scores.json` et vieux logs texte une fois la bascule validee.

## Changelog

Le detail des evolutions est disponible dans [CHANGELOG.md](CHANGELOG.md).
