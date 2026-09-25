-- =============================================================================
-- 0002_password_resets_and_rls_gaps.sql
--
-- Deux corrections révélées par les tests d'intégration :
--
--   1. les réinitialisations de mot de passe étaient stockées dans
--      `invitations`, table cloisonnée par organisation. Un reset n'appartient
--      pas à une organisation — il appartient à un utilisateur, qui peut être
--      membre de plusieurs. Ce détournement échouait sous RLS et, même sans
--      RLS, aurait fait entrer un jeton d'authentification dans une table
--      visible par les administrateurs d'une organisation ;
--
--   2. `subscriptions` et `notification_preferences` portent un
--      organization_id mais n'avaient pas été incluses dans la boucle
--      d'activation de RLS de 0001. Le filtre applicatif suffisait, mais la
--      deuxième couche manquait précisément sur les données de facturation.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- Réinitialisation de mot de passe et vérification d'email
--
-- Table portée par l'utilisateur, sans organization_id, donc hors RLS de tenant.
-- Seul le hachage du jeton est stocké : un dump ne permet pas de forger un
-- lien de réinitialisation valide.
-- -----------------------------------------------------------------------------
CREATE TABLE password_resets (
    id              text PRIMARY KEY,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      bytea NOT NULL UNIQUE,
    purpose         text NOT NULL DEFAULT 'password_reset'
                    CHECK (purpose IN ('password_reset', 'email_verification')),
    requested_ip    inet,
    expires_at      timestamptz NOT NULL,
    consumed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT password_resets_expiry_after_creation CHECK (expires_at > created_at)
);

-- Un seul jeton vivant par utilisateur et par usage : demander un second lien
-- doit invalider le premier, sinon un lien intercepté reste utilisable.
CREATE UNIQUE INDEX password_resets_active_idx
    ON password_resets (user_id, purpose)
    WHERE consumed_at IS NULL;

CREATE INDEX password_resets_expiry_idx ON password_resets (expires_at)
    WHERE consumed_at IS NULL;

-- Les jetons de reset écrits dans `invitations` par la version précédente ne
-- sont plus lisibles : ils sont supprimés plutôt que migrés. Un lien de
-- réinitialisation a une durée de vie d'une heure, la perte est nulle.
DELETE FROM invitations WHERE email LIKE 'reset:%';

-- -----------------------------------------------------------------------------
-- Combler les deux tables oubliées par la boucle RLS de 0001
-- -----------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['subscriptions', 'notification_preferences']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY tenant_isolation ON %I
            USING (organization_id = app_current_org())
            WITH CHECK (organization_id = app_current_org())
        $f$, t);
    END LOOP;
END $$;

-- -----------------------------------------------------------------------------
-- Privilèges
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON password_resets TO zshield_app;
    END IF;
END $$;

COMMIT;
