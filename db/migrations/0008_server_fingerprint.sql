-- =============================================================================
-- 0008_server_fingerprint.sql — empreinte du serveur
--
-- Le cœur anticheat calcule une empreinte stable de son serveur (dérivée de la
-- clé cfx). L'agent la remonte au heartbeat. On la stocke pour LIER
-- automatiquement les licences au bon serveur (anti-partage), sans que le
-- client ait à la communiquer à la main.
-- =============================================================================

BEGIN;

ALTER TABLE servers
    ADD COLUMN server_fingerprint text
        CHECK (server_fingerprint IS NULL OR server_fingerprint ~ '^[0-9a-f]{16}$');

COMMIT;
