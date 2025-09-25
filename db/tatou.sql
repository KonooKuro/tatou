-- Initialize Tatou (armadillo) database schema
-- Engine: MariaDB / MySQL
-- Shen 9.20: Adjusted VARCHAR lengths for indexed columns to avoid "Specified key was too long" on utf8mb4

-- Create database (safe if already provided by container env)
CREATE DATABASE IF NOT EXISTS `tatou`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `tatou`;

-- Users table
CREATE TABLE IF NOT EXISTS `Users` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `email` VARCHAR(191) NOT NULL,               -- Shen 9.20: reduced to 191 for safe unique index
  `hpassword` VARCHAR(255) NOT NULL,           -- password hash (argon2/bcrypt/etc)
  `login` VARCHAR(64) NOT NULL,                -- username/handle
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Documents table
CREATE TABLE IF NOT EXISTS `Documents` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(255) NOT NULL,
  `path` VARCHAR(191) NOT NULL,                -- Shen 9.20: reduced to 191 for safe unique index
  `ownerid` BIGINT UNSIGNED NOT NULL,          -- FK to Users(id)
  `creation` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `sha256` BINARY(32) NOT NULL,                -- raw 32-byte hash (UNHEX(hex))
  `size` BIGINT UNSIGNED NOT NULL,             -- bytes
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_documents_path` (`path`),
  KEY `ix_documents_ownerid` (`ownerid`),
  KEY `ix_documents_sha256` (`sha256`),
  CONSTRAINT `fk_documents_owner`
    FOREIGN KEY (`ownerid`) REFERENCES `Users`(`id`)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Versions table (watermarked/public Versions of a document)
CREATE TABLE IF NOT EXISTS `Versions` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `documentid` BIGINT UNSIGNED NOT NULL,       -- FK to Documents(id)
  `link` VARCHAR(191) NOT NULL,                -- Shen 9.20: reduced to 191 for safe unique index
  `intended_for` VARCHAR(320) NULL,            -- optional email/name (no index, safe to keep long)
  `secret` VARCHAR(320) NOT NULL,              -- secret (no index, safe to keep long)
  `method` VARCHAR(32) NOT NULL,               -- e.g., "text_overlay"
  `position` TEXT,                             -- e.g., "text_overlay"
  `path` VARCHAR(191) NOT NULL,                -- Shen 9.20: reduced to 191 for safety
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_Versions_link` (`link`),
  KEY `ix_Versions_documentid` (`documentid`),
  CONSTRAINT `fk_Versions_document`
    FOREIGN KEY (`documentid`) REFERENCES `Documents`(`id`)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;