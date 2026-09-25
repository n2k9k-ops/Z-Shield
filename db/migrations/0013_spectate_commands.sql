-- =============================================================================
-- 0013_spectate_commands.sql — commandes d'observation serveur-autoritative
--
-- Ajoute les types de commande de la Multi-vue à l'énumération `command_type`.
-- L'agent applique `spectate_request` en plaçant une caméra d'administration
-- DANS le monde du jeu sur la cible ; `spectate_stop` y met fin. Jamais une
-- capture de l'écran ou de la machine du joueur — le serveur reconstitue la
-- scène qu'il possède déjà.
--
-- (PG autorise ADD VALUE en transaction tant que la valeur n'est pas utilisée
--  dans la même transaction : on ne fait qu'étendre le type.)
-- =============================================================================

BEGIN;

ALTER TYPE command_type ADD VALUE IF NOT EXISTS 'spectate_request';
ALTER TYPE command_type ADD VALUE IF NOT EXISTS 'spectate_stop';

COMMIT;
