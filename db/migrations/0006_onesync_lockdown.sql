-- =============================================================================
-- 0006_onesync_lockdown.sql — réglage du verrouillage OneSync
--
-- Le mode d'entity lockdown OneSync (§21) est la protection de prévention la plus
-- forte à coût nul. On l'ajoute aux réglages anticheat par serveur, borné à trois
-- valeurs. 'inactive' par défaut : aucun changement de comportement serveur tant
-- que l'opérateur ne l'a pas choisi.
-- =============================================================================

BEGIN;

ALTER TABLE anticheat_settings
    ADD COLUMN onesync_lockdown text NOT NULL DEFAULT 'inactive'
        CHECK (onesync_lockdown IN ('inactive', 'relaxed', 'strict'));

COMMIT;
