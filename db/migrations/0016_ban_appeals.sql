-- =============================================================================
-- 0016_ban_appeals.sql — appels de ban (contestation par le joueur)
--
-- Un joueur banni conteste depuis une page PUBLIQUE (sans compte) en donnant son
-- identifiant + un message. Le serveur retrouve le ban actif correspondant (lecture
-- transversale via withPlatformAdmin) et crée un appel rattaché à l'organisation
-- propriétaire du ban. L'admin de cette org voit l'appel et tranche (accepter -> le
-- ban est levé ; rejeter). Réduit la frustration des faux positifs et aide à les repérer.
-- =============================================================================

BEGIN;

CREATE TABLE ban_appeals (
    id              text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ban_id          text,
    identifier      text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 128),
    contact         text CHECK (length(contact) <= 200),
    message         text NOT NULL CHECK (length(message) BETWEEN 1 AND 2000),
    status          text NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    ip              text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    resolved_by     text REFERENCES users(id) ON DELETE SET NULL,
    resolved_at     timestamptz
);

CREATE INDEX ban_appeals_org_status_idx ON ban_appeals (organization_id, status, created_at DESC);

ALTER TABLE ban_appeals ENABLE ROW LEVEL SECURITY;
ALTER TABLE ban_appeals FORCE ROW LEVEL SECURITY;

-- Lecture/écriture par l'organisation propriétaire (admins).
CREATE POLICY tenant_isolation ON ban_appeals
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

-- Chemin admin plateforme (utilisé par la soumission PUBLIQUE via withPlatformAdmin,
-- qui doit lire les bans de toutes les orgs et insérer l'appel dans la bonne org).
CREATE POLICY platform_admin_all ON ban_appeals
    USING (current_setting('app.platform_admin', true) = 'on')
    WITH CHECK (current_setting('app.platform_admin', true) = 'on');

-- La soumission publique doit RETROUVER le ban actif (toutes orgs confondues) pour
-- rattacher l'appel : on ajoute la politique admin plateforme sur `bans` (permissive,
-- combinée en OR avec l'isolation tenant existante — ne change rien au chemin normal).
CREATE POLICY platform_admin_all ON bans
    USING (current_setting('app.platform_admin', true) = 'on')
    WITH CHECK (current_setting('app.platform_admin', true) = 'on');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON ban_appeals TO zshield_app;
    END IF;
END $$;

COMMIT;
