-- =============================================================================
-- 0011_discord_identities.sql — liaison compte Z-Shield ↔ identité Discord
--
-- Table GLOBALE (hors tenant), comme `users` et `sessions` : l'identité Discord
-- appartient à un utilisateur, pas à une organisation. Le service d'authentifi-
-- cation la lit directement (this.pool), donc pas de RLS ici — même modèle que
-- `users`.
--
-- Règles :
--   - `discord_user_id` (snowflake Discord) est la clé : une identité Discord ne
--     peut pointer que vers un seul compte Z-Shield ;
--   - `UNIQUE (user_id)` : un compte Z-Shield est lié à au plus une identité
--     Discord — pas d'ambiguïté à la connexion ;
--   - suppression du compte -> suppression de la liaison (ON DELETE CASCADE).
-- =============================================================================

BEGIN;

CREATE TABLE discord_identities (
    discord_user_id text PRIMARY KEY CHECK (discord_user_id ~ '^[0-9]{5,32}$'),
    user_id         text        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Purement informatif (affichage / support). L'e-mail Discord n'est PAS une
    -- clé : la correspondance se fait sur le snowflake, stable et non réattribué.
    username        text,
    email           citext,
    avatar_url      text,
    linked_at       timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz,

    UNIQUE (user_id)
);

CREATE INDEX discord_identities_user_id_idx ON discord_identities (user_id);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON discord_identities TO zshield_app;
    END IF;
END $$;

COMMIT;
