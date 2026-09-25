-- =============================================================================
-- 0010_protection_settings.sql — réglages de protections choisis par le client
--
-- Une ligne par (serveur, protection) : l'état choisi depuis le dashboard
-- (activée ou non, et mode « surveiller » / « bloquer »). Le catalogue des
-- protections vit dans le code (protections/catalog.ts) ; on ne stocke ici que
-- les CHOIX du client. Une protection absente de la table prend son réglage par
-- défaut : la table ne contient que les écarts explicites.
--
-- Mêmes principes que 0001/0004/0005 : organization_id sur la table, clé
-- étrangère COMPOSITE vers servers, RLS activée et forcée.
-- =============================================================================

BEGIN;

CREATE TABLE server_protection_settings (
    organization_id text        NOT NULL,
    server_id       text        NOT NULL,
    protection_id   text        NOT NULL,
    enabled         boolean     NOT NULL,
    -- 'watch' (surveiller) ou 'block' (bloquer). Validé côté application contre
    -- le catalogue ; contrainte de garde-fou ici pour ne jamais stocker autre chose.
    mode            text        NOT NULL CHECK (mode IN ('watch', 'block')),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (organization_id, server_id, protection_id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);

ALTER TABLE server_protection_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_protection_settings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON server_protection_settings
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON server_protection_settings TO zshield_app;
    END IF;
END $$;

COMMIT;
