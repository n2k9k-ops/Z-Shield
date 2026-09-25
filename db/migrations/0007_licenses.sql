-- =============================================================================
-- 0007_licenses.sql — licences anticheat
--
-- Une licence signée est émise par la plateforme pour un serveur, avec une date
-- d'expiration (essai gratuit = 7 jours, ou fin d'abonnement). Le cœur anticheat
-- la vérifie hors-ligne et coupe la protection à l'expiration. On ne garde que la
-- licence courante par serveur (upsert).
-- =============================================================================

BEGIN;

CREATE TABLE licenses (
    organization_id text        NOT NULL,
    server_id       text        NOT NULL,
    token           text        NOT NULL,
    plan            text        NOT NULL DEFAULT 'trial'
                    CHECK (plan IN ('trial', 'starter', 'pro', 'enterprise')),
    issued_at       timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    created_by      text REFERENCES users(id) ON DELETE SET NULL,

    PRIMARY KEY (organization_id, server_id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);

ALTER TABLE licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE licenses FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON licenses
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON licenses TO zshield_app;
    END IF;
END $$;

COMMIT;
