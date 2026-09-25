-- =============================================================================
-- 0004_anticheat.sql — couche anticheat
--
-- Trois tables pour ce que le SERVEUR observe et décide : les détections
-- produites par l'agent, les bannissements, et les règles de protection
-- d'events.
--
-- Les mêmes principes que 0001 s'appliquent, sans exception :
--   - organization_id sur chaque table ;
--   - clés étrangères COMPOSITES vers servers, pour qu'une détection ne puisse
--     jamais être rattachée au serveur d'une autre organisation ;
--   - RLS activée et forcée, filtrée sur app.organization_id.
--
-- CE QUE CES TABLES NE SONT PAS : elles ne stockent aucune capture d'écran,
-- aucun flux, aucun contenu de la machine du joueur. Une détection est un fait
-- observé côté serveur (« vitesse 148 là où le plafond est 62 »), pas une image.
-- =============================================================================

BEGIN;

-- Type de détection. Fermé : l'agent ne peut rapporter que ces catégories, et
-- le dashboard ne sait afficher que celles-ci. En ajouter une demande une
-- migration, ce qui est voulu — une catégorie inconnue serait ignorée plutôt
-- que stockée en aveugle.
CREATE TYPE detection_kind AS ENUM (
    'teleport',        -- déplacement impossible entre deux ticks
    'speed',           -- vitesse au sol hors bornes du véhicule/à pied
    'godmode',         -- santé figée au maximum malgré les dégâts
    'noclip',          -- traversée de la géométrie de collision
    'injected_event',  -- event réseau hors du contrat déclaré
    'firerate',        -- cadence de tir supérieure au maximum de l'arme
    'entity_spam',     -- création d'entités à un rythme anormal
    'resource_tamper', -- ressource attendue absente ou modifiée
    'economy',         -- valeur d'économie hors bornes
    'other'
);

CREATE TYPE detection_disposition AS ENUM (
    'OBSERVED',    -- enregistrée, aucune action (score sous le seuil)
    'FLAGGED',     -- signalée pour revue humaine
    'KICKED',      -- joueur expulsé par l'agent
    'BANNED',      -- bannissement appliqué
    'DISMISSED'    -- revue humaine : faux positif
);

CREATE TYPE ban_scope AS ENUM ('license', 'discord', 'steam', 'ip', 'fivem');
CREATE TYPE ban_status AS ENUM ('ACTIVE', 'EXPIRED', 'LIFTED');
CREATE TYPE rule_action AS ENUM ('LOG', 'BLOCK', 'FLAG', 'KICK');
CREATE TYPE rule_status AS ENUM ('ACTIVE', 'DISABLED', 'DRAFT');

-- -----------------------------------------------------------------------------
-- Détections — partitionnée par mois comme alerts : la rétention est un
-- détachement de partition, pas un DELETE de millions de lignes.
--
-- Le "score de menace" du joueur n'est pas stocké ici : il est recalculé par
-- agrégation (voir la vue plus bas), pour qu'un changement de pondération n'ait
-- pas à réécrire l'historique.
-- -----------------------------------------------------------------------------
CREATE TABLE detections (
    id                 text NOT NULL CHECK (id ~ '^det_[0-9a-z]{26}$'),
    organization_id    text NOT NULL,
    server_id          text NOT NULL,
    -- Identifiant du joueur tel que vu par le serveur. C'est une donnée que le
    -- serveur possède déjà sur ses propres joueurs ; elle n'est PAS un flux ni
    -- une capture. Stockée hachée n'aurait pas de sens ici : l'admin doit
    -- pouvoir bannir la bonne personne.
    player_identifier  text NOT NULL CHECK (length(player_identifier) BETWEEN 1 AND 128),
    player_name        text CHECK (length(player_name) <= 64),
    kind               detection_kind NOT NULL,
    disposition        detection_disposition NOT NULL DEFAULT 'OBSERVED',
    -- Score de confiance de CETTE détection, 0 à 100. Distinct du score de
    -- menace agrégé du joueur.
    confidence         integer NOT NULL DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    -- Preuve observée, en clair et bornée : « vitesse mesurée / plafond »,
    -- « distance parcourue en un tick », etc. Objet plat, jamais un arbre.
    evidence           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Règle ou détecteur qui a produit la détection.
    detector           text CHECK (length(detector) <= 64),
    occurred_at        timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    reviewed_by        text,
    reviewed_at        timestamptz,
    PRIMARY KEY (organization_id, id, created_at),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (reviewed_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT detections_evidence_is_object CHECK (jsonb_typeof(evidence) = 'object')
) PARTITION BY RANGE (created_at);

CREATE INDEX detections_org_created_idx ON detections (organization_id, created_at DESC);
CREATE INDEX detections_server_idx ON detections (organization_id, server_id, created_at DESC);
CREATE INDEX detections_player_idx ON detections (organization_id, player_identifier, created_at DESC);
CREATE INDEX detections_kind_idx ON detections (organization_id, kind, created_at DESC);
CREATE INDEX detections_disposition_idx ON detections (organization_id, disposition)
    WHERE disposition IN ('FLAGGED', 'OBSERVED');

CREATE TABLE detections_default PARTITION OF detections DEFAULT;
CREATE TABLE detections_2026_09 PARTITION OF detections FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE detections_2026_10 PARTITION OF detections FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE detections_2026_11 PARTITION OF detections FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

-- -----------------------------------------------------------------------------
-- Bannissements
--
-- L'EXÉCUTION du ban appartient au serveur, via l'anticheat installé. Cette
-- table est le registre : elle dit qui doit être banni et pourquoi. L'agent lit
-- ce registre et applique. La plateforme n'a aucun moyen d'agir directement sur
-- un joueur — cohérent avec l'absence d'endpoint d'exécution.
-- -----------------------------------------------------------------------------
CREATE TABLE bans (
    id                 text NOT NULL CHECK (id ~ '^ban_[0-9a-z]{26}$'),
    organization_id    text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Un ban peut viser toute l'organisation (server_id NULL) ou un serveur.
    server_id          text,
    scope              ban_scope NOT NULL,
    identifier         text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 128),
    player_name        text CHECK (length(player_name) <= 64),
    reason             text NOT NULL CHECK (length(reason) BETWEEN 1 AND 400),
    -- Détection ayant motivé le ban, pour la traçabilité. Peut être NULL pour
    -- un ban manuel.
    detection_id       text,
    status             ban_status NOT NULL DEFAULT 'ACTIVE',
    issued_by          text,           -- NULL = automatique
    issued_by_auto     boolean NOT NULL DEFAULT false,
    lifted_by          text,
    lifted_reason      text CHECK (length(lifted_reason) <= 400),
    expires_at         timestamptz,    -- NULL = définitif
    created_at         timestamptz NOT NULL DEFAULT now(),
    lifted_at          timestamptz,
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE SET NULL (server_id),
    FOREIGN KEY (issued_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (lifted_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX bans_id_key ON bans (id);
-- Un identifiant ne peut avoir qu'un seul ban ACTIF par périmètre : ré-bannir
-- un joueur déjà banni doit mettre à jour, pas empiler.
CREATE UNIQUE INDEX bans_active_identifier_idx
    ON bans (organization_id, scope, identifier, COALESCE(server_id, ''))
    WHERE status = 'ACTIVE';
CREATE INDEX bans_org_created_idx ON bans (organization_id, created_at DESC);
CREATE INDEX bans_lookup_idx ON bans (organization_id, scope, identifier)
    WHERE status = 'ACTIVE';
CREATE INDEX bans_expiry_idx ON bans (expires_at)
    WHERE status = 'ACTIVE' AND expires_at IS NOT NULL;

-- -----------------------------------------------------------------------------
-- Règles de sécurité — protection des events
--
-- Chaque règle décrit un event à surveiller et la validation à lui appliquer.
-- L'agent lit ces règles et les fait respecter côté serveur. La validation est
-- déclarative et bornée : il n'y a PAS de champ « code » où l'on collerait du
-- Lua, parce que l'agent n'exécute jamais de code fourni par la plateforme.
-- -----------------------------------------------------------------------------
CREATE TABLE security_rules (
    id                 text NOT NULL CHECK (id ~ '^rul_[0-9a-z]{26}$'),
    organization_id    text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    server_id          text,           -- NULL = toute la flotte
    event_name         text NOT NULL CHECK (length(event_name) BETWEEN 1 AND 128),
    event_side         text NOT NULL DEFAULT 'server' CHECK (event_side IN ('server', 'client')),
    -- Validation déclarative : un mot-clé (bounds, ownership, rate…) et ses
    -- paramètres bornés, pas du code.
    validation_kind    text NOT NULL DEFAULT 'bounds'
                       CHECK (validation_kind IN ('bounds', 'ownership', 'rate', 'allowlist', 'none')),
    validation_params  jsonb NOT NULL DEFAULT '{}'::jsonb,
    action             rule_action NOT NULL DEFAULT 'LOG',
    status             rule_status NOT NULL DEFAULT 'ACTIVE',
    hit_count          bigint NOT NULL DEFAULT 0 CHECK (hit_count >= 0),
    last_hit_at        timestamptz,
    created_by         text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT security_rules_params_is_object CHECK (jsonb_typeof(validation_params) = 'object')
);

CREATE UNIQUE INDEX security_rules_id_key ON security_rules (id);
CREATE UNIQUE INDEX security_rules_event_idx
    ON security_rules (organization_id, COALESCE(server_id, ''), event_name);
CREATE INDEX security_rules_org_idx ON security_rules (organization_id, status);

-- -----------------------------------------------------------------------------
-- Réglages anticheat par serveur — seuils et réponse automatique
--
-- Étend la configuration distante existante avec les paramètres propres à la
-- détection. Stocké à part de servers.remote_config parce que ces valeurs sont
-- consommées par le core zshield_ac, pas par l'agent de télémétrie.
-- -----------------------------------------------------------------------------
CREATE TABLE anticheat_settings (
    organization_id       text NOT NULL,
    server_id             text NOT NULL,
    -- Bascules de détecteurs
    detect_teleport       boolean NOT NULL DEFAULT true,
    detect_speed          boolean NOT NULL DEFAULT true,
    detect_godmode        boolean NOT NULL DEFAULT true,
    detect_noclip         boolean NOT NULL DEFAULT true,
    detect_injected_event boolean NOT NULL DEFAULT true,
    detect_firerate       boolean NOT NULL DEFAULT true,
    detect_entity_spam    boolean NOT NULL DEFAULT true,
    -- Seuils, bornés pour rester plausibles
    max_ground_speed_kmh  integer NOT NULL DEFAULT 62 CHECK (max_ground_speed_kmh BETWEEN 20 AND 500),
    max_tick_distance_m   integer NOT NULL DEFAULT 45 CHECK (max_tick_distance_m BETWEEN 5 AND 500),
    max_fire_rate_rps     integer NOT NULL DEFAULT 12 CHECK (max_fire_rate_rps BETWEEN 1 AND 100),
    -- Réponse automatique
    auto_ban_enabled      boolean NOT NULL DEFAULT false,
    auto_ban_threshold    integer NOT NULL DEFAULT 85 CHECK (auto_ban_threshold BETWEEN 1 AND 100),
    critical_action       text NOT NULL DEFAULT 'kick_flag'
                          CHECK (critical_action IN ('ban', 'kick_flag', 'flag')),
    default_ban_days      integer CHECK (default_ban_days IS NULL OR default_ban_days BETWEEN 1 AND 3650),
    updated_by            text REFERENCES users(id) ON DELETE SET NULL,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, server_id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- Score de menace agrégé par joueur — vue, pas table.
--
-- Recalculé à la lecture pour qu'un changement de pondération n'exige pas de
-- réécrire l'historique. Sur de gros volumes on la matérialiserait ; à ce stade
-- la vue suffit et reste juste par construction.
-- -----------------------------------------------------------------------------
CREATE VIEW player_threat AS
SELECT
    d.organization_id,
    d.player_identifier,
    max(d.player_name)                              AS player_name,
    count(*)                                        AS detection_count,
    count(*) FILTER (WHERE d.created_at > now() - interval '24 hours') AS detections_24h,
    max(d.created_at)                               AS last_seen_at,
    -- Score borné à 100. Pondéré par la confiance et amorti dans le temps :
    -- une détection ancienne pèse moins qu'une récente.
    least(100, round(sum(
        d.confidence / 100.0
        * CASE d.kind
            WHEN 'godmode' THEN 30 WHEN 'injected_event' THEN 28
            WHEN 'teleport' THEN 25 WHEN 'noclip' THEN 25
            WHEN 'speed' THEN 18 WHEN 'firerate' THEN 15
            WHEN 'entity_spam' THEN 12 ELSE 8 END
        * exp(-extract(epoch FROM (now() - d.created_at)) / (7 * 86400.0))
    )))::int                                        AS threat_score
FROM detections d
WHERE d.disposition <> 'DISMISSED'
GROUP BY d.organization_id, d.player_identifier;

-- -----------------------------------------------------------------------------
-- RLS
-- -----------------------------------------------------------------------------
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['detections', 'bans', 'security_rules', 'anticheat_settings']
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

-- La vue s'exécute avec les droits de l'appelant (security_invoker) pour que
-- RLS de detections s'applique à travers elle. Sans cela, la vue contournerait
-- l'isolation.
ALTER VIEW player_threat SET (security_invoker = true);

-- -----------------------------------------------------------------------------
-- Privilèges
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE
            ON detections, bans, security_rules, anticheat_settings TO zshield_app;
        GRANT SELECT ON player_threat TO zshield_app;
    END IF;
END $$;

COMMIT;
