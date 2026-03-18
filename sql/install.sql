CREATE TABLE IF NOT EXISTS `PREFIX_sj4web_firewall_ip_state` (
  `ip` VARCHAR(45) NOT NULL,
  `score` INT NOT NULL DEFAULT 0,
  `hit_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `first_seen` DATETIME NOT NULL,
  `updated_at` DATETIME NOT NULL,
  `blocked_until` DATETIME NULL DEFAULT NULL,
  `alerted` TINYINT(1) NOT NULL DEFAULT 0,
  `country` VARCHAR(2) NULL DEFAULT NULL,
  `user_agent` TEXT NULL,
  `last_event_reason` VARCHAR(255) NULL DEFAULT NULL,
  PRIMARY KEY (`ip`),
  KEY `idx_sj4web_firewall_ip_state_score` (`score`),
  KEY `idx_sj4web_firewall_ip_state_updated_at` (`updated_at`),
  KEY `idx_sj4web_firewall_ip_state_blocked_until` (`blocked_until`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `PREFIX_sj4web_firewall_ip_event` (
  `id_sj4web_firewall_ip_event` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip` VARCHAR(45) NOT NULL,
  `created_at` DATETIME NOT NULL,
  `reason` VARCHAR(255) NOT NULL,
  `event_type` VARCHAR(32) NOT NULL DEFAULT 'runtime',
  `status_code` SMALLINT UNSIGNED NULL DEFAULT NULL,
  `user_agent` TEXT NULL,
  PRIMARY KEY (`id_sj4web_firewall_ip_event`),
  KEY `idx_sj4web_firewall_ip_event_ip_created_at` (`ip`, `created_at`),
  KEY `idx_sj4web_firewall_ip_event_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `PREFIX_sj4web_firewall_contact_attempt` (
  `id_sj4web_firewall_contact_attempt` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip` VARCHAR(45) NOT NULL,
  `created_at` DATETIME NOT NULL,
  PRIMARY KEY (`id_sj4web_firewall_contact_attempt`),
  KEY `idx_sj4web_firewall_contact_attempt_ip_created_at` (`ip`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `PREFIX_sj4web_firewall_daily_stat` (
  `log_date` DATE NOT NULL,
  `ip` VARCHAR(45) NOT NULL,
  `type` VARCHAR(32) NOT NULL DEFAULT 'human',
  `bot_name` VARCHAR(191) NOT NULL DEFAULT '',
  `user_agent` TEXT NULL,
  `country` VARCHAR(2) NULL DEFAULT NULL,
  `access_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `error_404_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `error_403_count` INT UNSIGNED NOT NULL DEFAULT 0,
  `first_seen` DATETIME NOT NULL,
  `last_seen` DATETIME NOT NULL,
  `score` INT NOT NULL DEFAULT 0,
  PRIMARY KEY (`log_date`, `ip`),
  KEY `idx_sj4web_firewall_daily_stat_log_date` (`log_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `PREFIX_sj4web_firewall_daily_summary` (
  `log_date` DATE NOT NULL,
  `traffic_type` VARCHAR(32) NOT NULL,
  `bot_name` VARCHAR(191) NOT NULL DEFAULT '',
  `total_count` INT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (`log_date`, `traffic_type`, `bot_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

