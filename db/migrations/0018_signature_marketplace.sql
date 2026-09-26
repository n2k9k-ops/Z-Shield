-- =============================================================================
-- 0018_signature_marketplace.sql — marketplace communautaire de signatures
--
-- Les serveurs qui rencontrent un nouveau cheat peuvent PROPOSER une signature
-- (nom d'événement suspect, resource, entité, pattern…). Un admin plateforme
-- MODÈRE (approuve / rejette) : rien n'est diffusé sans validation humaine, pour
-- éviter qu'une proposition erronée devienne un faux positif chez tout le monde.
-- Les signatures APPROUVÉES forment un flux commun, distribué anonymisé (jamais
-- l'org ni l'auteur) à tous les serveurs abonnés, qui les ajoutent à leur config.
-- =============================================================================

BEGIN;

CREATE TABLE signature_submissions (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    submitted_by    text REFERENCES users(id) ON DELETE SET NULL,
    label           text NOT NULL,                    -- nom lisible « Menu Eulen — event nui »
    category        text NOT NULL,                    -- event | resource | entity | convar | pattern
    pattern         text NOT NULL,                    -- la signature effective (chaîne)
    cheat_name      text,                             -- famille de cheat visée (optionnel)
    description     text,                             -- contexte / preuve (optionnel)
    status          text NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
    reviewed_by     text REFERENCES users(id) ON DELETE SET NULL,
    review_note     text,
    reviewed_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT signature_status_chk CHECK (status IN ('pending','approved','rejected')),
    CONSTRAINT signature_category_chk CHECK (category IN ('event','resource','entity','convar','pattern'))
);

CREATE INDEX signature_submissions_org_idx    ON signature_submissions (organization_id, created_at DESC);
CREATE INDEX signature_submissions_status_idx ON signature_submissions (status, created_at DESC);
-- Empêche une même org de proposer deux fois la même signature.
CREATE UNIQUE INDEX signature_submissions_dedup_idx
    ON signature_submissions (organization_id, category, pattern);

ALTER TABLE signature_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE signature_submissions FORCE ROW LEVEL SECURITY;

-- Tenant : une org ne voit et ne gère QUE ses propres propositions.
CREATE POLICY signature_submissions_tenant ON signature_submissions
    USING (organization_id = app_current_org())
    WITH CHECK (organization_id = app_current_org());

-- Admin plateforme : accès transversal pour la modération (via app.platform_admin).
CREATE POLICY signature_submissions_platform_admin_all ON signature_submissions
    USING (current_setting('app.platform_admin', true) = 'on')
    WITH CHECK (current_setting('app.platform_admin', true) = 'on');

COMMIT;
