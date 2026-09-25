-- =============================================================================
-- 0005_protections.sql — instantané des protections natives
--
-- Une seule table : le DERNIER instantané agrégé des couches de protection du
-- cœur anticheat (§08 game events, §10 state bags, §21 orchestrateur OneSync,
-- §15 preuve, §17 réputation, §29 performance), remonté par l'agent avec la
-- télémétrie. On ne conserve que le plus récent par serveur (upsert) : ce sont
-- des compteurs de santé, pas un historique.
--
-- Mêmes principes que 0001/0004 : organization_id sur la table, clé étrangère
-- COMPOSITE vers servers, RLS activée et forcée. Le snapshot est un agrégat —
-- aucun identifiant de joueur, aucune capture.
-- =============================================================================

BEGIN;

CREATE TABLE server_protections (
    organization_id text        NOT NULL,
    server_id       text        NOT NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Agrégat opaque tel que remonté par le cœur (compteurs bloqués, preuve,
    -- réputation, performance, lockdown). Validé côté application, pas en base.
    snapshot        jsonb       NOT NULL DEFAULT '{}'::jsonb,

    PRIMARY KEY (organization_id, server_id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);

ALTER TABLE server_protections ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_protections FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON server_protections
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON server_protections TO zshield_app;
    END IF;
END $$;

COMMIT;
