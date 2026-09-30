-- =============================================================================
-- 0020_heatmap.sql — heatmap live (opt-in, agrégée)
--
-- Compteurs par case de grille (50 m), calculés côté API à partir des instantanés
-- déjà reçus par la vue live (`agent_gateway.live`). Rien n'est stocké en SQL : les
-- compteurs vivent dans Redis (buckets par minute, ~30 min glissantes) et ne sont
-- JAMAIS liés à un joueur — seulement une position arrondie, comptée. Cette colonne
-- ne fait qu'activer/désactiver l'écriture de ces compteurs pour l'organisation.
-- =============================================================================

BEGIN;

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS heatmap_enabled boolean NOT NULL DEFAULT false;

COMMIT;
