-- =============================================================================
-- 0017_shared_ban_network.sql — réseau de bans partagés (opt-in)
--
-- Les organisations qui le CHOISISSENT (organizations.share_bans) contribuent à un
-- pool ANONYMISÉ : quand elles bannissent un identifiant, on stocke seulement un
-- HASH salé de cet identifiant + des compteurs agrégés. Jamais l'identifiant brut,
-- jamais quel serveur l'a banni (l'API n'expose qu'un nombre d'orgs). Une org opt-in
-- peut alors savoir qu'un identifiant est « signalé sur N serveurs du réseau » — un
-- SIGNAL (pas un ban auto : on n'impose pas la décision d'un autre serveur).
-- =============================================================================

BEGIN;

-- Opt-in par organisation (réciprocité : partager pour bénéficier du signal).
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS share_bans boolean NOT NULL DEFAULT false;

-- Agrégat public anonymisé (aucune donnée brute, aucun lien vers une org).
CREATE TABLE global_ban_signals (
    identifier_hash   text PRIMARY KEY,
    org_count         int NOT NULL DEFAULT 0,   -- nb d'organisations distinctes l'ayant banni
    report_count      int NOT NULL DEFAULT 0,   -- nb total de contributions
    first_reported_at timestamptz NOT NULL DEFAULT now(),
    last_reported_at  timestamptz NOT NULL DEFAULT now()
);

-- Déduplication interne (une org ne compte qu'une fois par identifiant). Table
-- SERVEUR-INTERNE : jamais exposée par l'API. Sert uniquement à calculer org_count.
CREATE TABLE global_ban_reporters (
    identifier_hash text NOT NULL,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (identifier_hash, organization_id)
);

-- Pool partagé inter-organisations : PAS de RLS tenant (c'est un agrégat commun,
-- sans donnée brute ni PII). Accès applicatif seulement.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON global_ban_signals TO zshield_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON global_ban_reporters TO zshield_app;
    END IF;
END $$;

COMMIT;
