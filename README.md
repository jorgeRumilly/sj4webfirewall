# SJ4WEB - Firewall pour PrestaShop

**Module de protection avancée contre les bots et attaques pour PrestaShop 8+**.

---

## 🚀 Fonctionnalités principales

- **Détection et scoring des IPs** : ralentissement ou blocage automatique selon comportement.
- **Gestion des bots** :
    - Autorisation des bots SEO (Googlebot, Bingbot, etc.).
    - Blocage des bots malveillants connus.
- **Système de logs** :
    - Journalisation quotidienne des accès IP.
    - Fichier `ip_scores.json` pour le scoring.
- **Alertes par e-mail** :
    - Notifications en cas d’activités anormales (trop de 404/403).
- **Protection formulaire** :
    - Honeypots.
    - Délai minimal anti-bot.
    - Token renforcé contre les soumissions automatiques.
- **Internationalisation** :
    - Traductions via le système natif de PrestaShop 8.
- **Géolocalisation des IPs** :
    - Détection du pays d’origine via GeoIP (MaxMind GeoLite2).

---

## ⚙️ Configuration

Depuis le Back-Office de PrestaShop :
- Définir les IPs et bots autorisés (whitelist).
- Configurer les seuils de déclenchement du scoring.
- Activer ou désactiver les notifications par mail.
- Gérer les actions sur IP : reset, suppression, whitelist.

---

## ✅ Compatibilité

- **PrestaShop** : `>= 1.7.8.5` et `8.x`
- **PHP** : `>= 7.3` (recommandé : `7.4` ou `8.1`)

---

## 🧩 Installation

1. Copier le module dans le dossier `/modules/`.
2. Installer depuis le Back-Office PrestaShop (`Modules > Module Manager`).
3. Configurer le module via `Paramètres > SJ4WEB - Firewall`.

---

## 📝 Changelog

Le changelog complet est disponible dans le fichier [`CHANGELOG.md`](CHANGELOG.md).

---

## 📄 Licence

Ce module est distribué sous licence **propriétaire**.  
© 2025 [SJ4WEB.FR](https://www.sj4web.fr) – Tous droits réservés.

---

## 🙋 Support

Pour toute demande de support ou d'amélioration, contactez :  
📧 [contact@sj4web.fr](mailto:contact@sj4web.fr)
