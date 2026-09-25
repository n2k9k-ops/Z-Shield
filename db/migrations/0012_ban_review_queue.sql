-- =============================================================================
-- 0012_ban_review_queue.sql — file de revue des sanctions + apprentissage
--
-- La détection à confiance moyenne ne bannit pas sèchement : elle crée une
-- SANCTION EN ATTENTE (bans.status = 'PENDING') qu'un humain tranche depuis le
-- tableau de bord :
--   - Confirmer  -> le ban devient ACTIVE ;
--   - Kick       -> sanction réduite (status 'KICKED'), l'agent expulse une fois ;
--   - Faux positif -> status 'DISMISSED' + retour consigné dans
--     `detection_feedback`, que l'anticheat lit pour relever le seuil du
--     détecteur concerné et cesser de re-sanctionner ce comportement.
--
-- Toujours les mêmes principes : la plateforme n'exécute rien elle-même, elle
-- tient le registre ; l'agent lit et applique. RLS déjà active sur `bans`.
-- =============================================================================

BEGIN;

-- Nouveaux états. (PG16 autorise ADD VALUE en transaction tant que la valeur
-- n'est pas utilisée dans la même transaction — on ne fait qu'étendre le type.)
ALTER TYPE ban_status ADD VALUE IF NOT EXISTS 'PENDING';
ALTER TYPE ban_status ADD VALUE IF NOT EXISTS 'KICKED';
ALTER TYPE ban_status ADD VALUE IF NOT EXISTS 'DISMISSED';

-- Contexte de décision, affiché dans la file de revue.
ALTER TABLE bans ADD COLUMN IF NOT EXISTS risk smallint
    CHECK (risk IS NULL OR (risk BETWEEN 0 AND 100));
ALTER TABLE bans ADD COLUMN IF NOT EXISTS detection_category text
    CHECK (detection_category IS NULL OR length(detection_category) <= 40);
-- Détecteur exact (ex. 'weapon.firerate') : cible d'un éventuel « faux positif ».
ALTER TABLE bans ADD COLUMN IF NOT EXISTS detector text
    CHECK (detector IS NULL OR length(detector) <= 64);
-- Nature de la preuve capturée au moment des faits : un clip du jeu (reconstitué
-- côté serveur) ou une capture unique. JAMAIS l'écran réel du joueur.
ALTER TABLE bans ADD COLUMN IF NOT EXISTS evidence_kind text
    CHECK (evidence_kind IS NULL OR evidence_kind IN ('clip', 'screenshot'));
-- Qui a tranché une sanction en attente, et comment.
ALTER TABLE bans ADD COLUMN IF NOT EXISTS reviewed_by text
    REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE bans ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;

-- NB : pas d'index partiel « WHERE status = 'PENDING' » ici. PostgreSQL interdit
-- d'utiliser une valeur d'enum ajoutée dans la même transaction, et la file de
-- revue reste petite : l'index existant (organization_id, created_at DESC) suffit,
-- le filtre sur le statut se fait à la lecture.

-- ---------------------------------------------------------------------------
-- Retour humain sur une détection : matière première de la calibration.
-- Une ligne par verdict. L'anticheat la lit pour ajuster ses seuils.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS detection_feedback (
    id                 text NOT NULL CHECK (id ~ '^det_[0-9a-z]{26}$'),
    organization_id    text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    server_id          text,
    -- Détecteur visé (ex. 'weapon.firerate'), tel que rapporté par l'agent.
    detector           text NOT NULL CHECK (length(detector) BETWEEN 1 AND 64),
    scope              ban_scope,
    identifier         text CHECK (identifier IS NULL OR length(identifier) <= 128),
    -- Verdict humain. 'false_positive' relève le seuil ; 'confirmed' le conforte.
    verdict            text NOT NULL CHECK (verdict IN ('false_positive', 'confirmed')),
    ban_id             text,
    created_by         text REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE SET NULL (server_id)
);

CREATE INDEX IF NOT EXISTS detection_feedback_detector_idx
    ON detection_feedback (organization_id, detector, created_at DESC);

ALTER TABLE detection_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE detection_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON detection_feedback;
CREATE POLICY tenant_isolation ON detection_feedback
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON detection_feedback TO zshield_app;
    END IF;
END $$;

COMMIT;
