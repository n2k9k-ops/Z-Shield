-- =============================================================================
-- 0019_evidence_captures.sql — captures du RENDU DE JEU, demandées par le staff
--
-- Flux : un membre du staff clique « Capturer » sur un joueur EN LIGNE ->
--   1. l'API crée une ligne PENDING (hash d'un jeton à usage unique) et une
--      commande `capture_request` pour l'agent ;
--   2. l'agent demande au cœur anticheat, qui demande au client de capturer la
--      fenêtre du jeu (screenshot-basic) ;
--   3. le client envoie l'image à l'URL d'upload signée par le jeton ;
--   4. l'API range l'image ici, le staff la voit dans le dossier du joueur.
--
-- Garde-fous :
--   - le jeton n'est stocké qu'en hachage, vaut pour UNE image, expire en 5 min ;
--   - l'image est sniffée (JPEG/PNG) et plafonnée à 1,5 Mio ;
--   - RLS forcée : une organisation ne voit jamais les captures d'une autre ;
--   - rétention : l'API purge les captures de plus de 30 jours à chaque demande.
-- Ce n'est JAMAIS une capture du bureau : uniquement le rendu de la fenêtre du jeu.
-- =============================================================================

BEGIN;

ALTER TYPE command_type ADD VALUE IF NOT EXISTS 'capture_request';

CREATE TABLE evidence_captures (
    id                text NOT NULL CHECK (id ~ '^cap_[0-9a-z]{26}$'),
    organization_id   text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    server_id         text NOT NULL,
    target_slot       integer CHECK (target_slot >= 0),
    target_identifier text CHECK (length(target_identifier) <= 128),
    target_name       text CHECK (length(target_name) <= 64),
    requested_by      text REFERENCES users(id) ON DELETE SET NULL,
    command_id        text,
    token_hash        bytea NOT NULL,
    status            text NOT NULL DEFAULT 'PENDING'
                      CHECK (status IN ('PENDING', 'RECEIVED', 'EXPIRED')),
    mime              text CHECK (mime IN ('image/jpeg', 'image/png')),
    bytes             integer CHECK (bytes BETWEEN 1 AND 2097152),
    image             bytea,
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    received_at       timestamptz,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT evidence_received_has_image
        CHECK (status <> 'RECEIVED' OR (image IS NOT NULL AND mime IS NOT NULL AND bytes IS NOT NULL))
);

CREATE INDEX evidence_captures_server_idx
    ON evidence_captures (organization_id, server_id, created_at DESC);
CREATE INDEX evidence_captures_identifier_idx
    ON evidence_captures (organization_id, target_identifier, created_at DESC);

ALTER TABLE evidence_captures ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_captures FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON evidence_captures
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_captures TO zshield_app;
    END IF;
END $$;

COMMIT;
