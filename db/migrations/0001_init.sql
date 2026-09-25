-- =============================================================================
-- 0001_init.sql — schéma initial
--
-- Principes appliqués ici et non ailleurs :
--   1. toute table tenant porte organization_id ;
--   2. les clés étrangères sont COMPOSITES (organization_id, id) : rattacher une
--      ligne à une autre organisation est impossible, pas seulement improbable ;
--   3. RLS activée sur chaque table tenant, filtrée sur app.organization_id ;
--   4. audit_logs est append-only au niveau des privilèges.
--
-- PostgreSQL 15 minimum : la syntaxe ON DELETE SET NULL (colonne) est requise
-- pour ne pas dénuller organization_id sur les FK composites.
--
-- Rôles attendus :
--   zshield_migrator  propriétaire du schéma, exécute les migrations
--   zshield_app       rôle applicatif, NOBYPASSRLS, aucun DDL
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- -----------------------------------------------------------------------------
-- Énumérations
-- -----------------------------------------------------------------------------
CREATE TYPE member_role       AS ENUM ('OWNER', 'ADMIN', 'STAFF', 'VIEWER');
CREATE TYPE server_state      AS ENUM ('ONLINE', 'DEGRADED', 'OFFLINE', 'UNKNOWN');
CREATE TYPE health_state      AS ENUM ('HEALTHY', 'DEGRADED', 'FAILED', 'UNKNOWN');
CREATE TYPE alert_severity    AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE alert_status      AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED');
CREATE TYPE alert_category    AS ENUM ('event', 'entity', 'movement', 'economy',
                                       'weapon', 'resource', 'admin', 'agent', 'other');
CREATE TYPE incident_status   AS ENUM ('OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'CLOSED');
CREATE TYPE command_status    AS ENUM ('PENDING', 'SENT', 'ACKNOWLEDGED', 'FAILED', 'EXPIRED');
CREATE TYPE command_result    AS ENUM ('COMPLETED', 'FAILED', 'REJECTED', 'DUPLICATE');
CREATE TYPE credential_status AS ENUM ('ACTIVE', 'PENDING_ROTATION', 'SUPERSEDED', 'REVOKED');
CREATE TYPE subscription_state AS ENUM ('TRIALING', 'ACTIVE', 'PAST_DUE', 'CANCELED');

-- La liste des types de commande est fermée par le protocole. L'élargir ici ne
-- suffirait pas : l'agent rejette tout type absent de sa propre allowlist.
CREATE TYPE command_type AS ENUM (
    'ping',
    'request_status',
    'request_health_check',
    'refresh_configuration',
    'reload_safe_configuration',
    'flush_queue',
    'rotate_credential'
);

-- -----------------------------------------------------------------------------
-- Organisations et utilisateurs
-- -----------------------------------------------------------------------------
CREATE TABLE organizations (
    id              text PRIMARY KEY CHECK (id ~ '^org_[0-9a-z]{26}$'),
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    slug            citext NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,48}$'),
    data_region     text NOT NULL DEFAULT 'eu-west' CHECK (data_region IN ('eu-west', 'us-east')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    deleted_at      timestamptz
);

CREATE TABLE users (
    id                  text PRIMARY KEY CHECK (id ~ '^usr_[0-9a-z]{26}$'),
    email               citext NOT NULL UNIQUE,
    -- scrypt, encodé « scrypt$N$r$p$salt$hash ». Jamais de mot de passe en clair.
    password_hash       text NOT NULL,
    display_name        text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 80),
    email_verified_at   timestamptz,
    mfa_enforced        boolean NOT NULL DEFAULT false,
    failed_logins       integer NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until        timestamptz,
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz
);

-- Un facteur TOTP. Le secret est chiffré applicativement (AES-256-GCM), comme
-- les secrets d'agent : il doit être recalculable, donc non hachable.
CREATE TABLE mfa_factors (
    id                  text PRIMARY KEY,
    user_id             text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind                text NOT NULL DEFAULT 'totp' CHECK (kind IN ('totp')),
    secret_encrypted    bytea NOT NULL,
    confirmed_at        timestamptz,
    last_used_step      bigint,          -- anti-rejeu du code TOTP
    recovery_codes      text[] NOT NULL DEFAULT '{}',  -- hachés, un usage chacun
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (user_id, kind)
);

CREATE TABLE sessions (
    id              text PRIMARY KEY,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Seul le hachage du jeton est stocké : un dump de base ne permet pas de
    -- rejouer une session vivante.
    token_hash      bytea NOT NULL UNIQUE,
    organization_id text REFERENCES organizations(id) ON DELETE SET NULL,
    mfa_satisfied   boolean NOT NULL DEFAULT false,
    ip              inet,
    user_agent      text CHECK (length(user_agent) <= 400),
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE memberships (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role            member_role NOT NULL DEFAULT 'VIEWER',
    invited_by      text REFERENCES users(id) ON DELETE SET NULL,
    accepted_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, user_id),
    -- Cet index sert la garantie « au moins un OWNER » vérifiée en transaction.
    CONSTRAINT memberships_role_not_null CHECK (role IS NOT NULL)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);
CREATE INDEX memberships_owner_idx ON memberships (organization_id) WHERE role = 'OWNER';

CREATE TABLE invitations (
    id              text PRIMARY KEY,
    organization_id text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email           citext NOT NULL,
    role            member_role NOT NULL DEFAULT 'VIEWER',
    token_hash      bytea NOT NULL UNIQUE,
    invited_by      text REFERENCES users(id) ON DELETE SET NULL,
    expires_at      timestamptz NOT NULL,
    accepted_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, email)
);

-- -----------------------------------------------------------------------------
-- Serveurs et agents
-- -----------------------------------------------------------------------------
CREATE TABLE servers (
    id                  text NOT NULL CHECK (id ~ '^srv_[0-9a-z]{26}$'),
    organization_id     text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    environment         text NOT NULL DEFAULT 'production'
                        CHECK (environment IN ('production', 'staging', 'development')),
    state               server_state NOT NULL DEFAULT 'UNKNOWN',
    health              health_state NOT NULL DEFAULT 'UNKNOWN',
    connected_at        timestamptz,        -- premier handshake vérifié
    last_heartbeat_at   timestamptz,
    last_error          text CHECK (length(last_error) <= 1000),
    last_error_at       timestamptz,
    agent_version       text CHECK (length(agent_version) <= 32),
    protocol_version    integer CHECK (protocol_version BETWEEN 1 AND 100),
    uptime_seconds      bigint CHECK (uptime_seconds >= 0),
    players_online      integer CHECK (players_online >= 0),
    max_players         integer CHECK (max_players >= 0),
    fxserver_version    text CHECK (length(fxserver_version) <= 64),
    onesync             text CHECK (length(onesync) <= 32),
    queue_size          integer CHECK (queue_size >= 0),
    config_version      integer NOT NULL DEFAULT 0 CHECK (config_version >= 0),
    -- Configuration distante. Validée contre le schéma strict de l'agent avant
    -- écriture : un champ inconnu ferait rejeter tout le document par l'agent.
    remote_config       jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by          text REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    deleted_at          timestamptz,
    PRIMARY KEY (organization_id, id)
);
-- L'identifiant reste globalement unique : l'agent ne connaît que son server_id.
CREATE UNIQUE INDEX servers_id_key ON servers (id);
CREATE INDEX servers_org_state_idx ON servers (organization_id, state)
    WHERE deleted_at IS NULL;
CREATE INDEX servers_heartbeat_idx ON servers (last_heartbeat_at)
    WHERE deleted_at IS NULL AND state <> 'OFFLINE';

CREATE TABLE agents (
    id                  text NOT NULL CHECK (id ~ '^agt_[0-9a-z]{26}$'),
    organization_id     text NOT NULL,
    server_id           text NOT NULL,
    handshake_at        timestamptz,
    handshake_count     integer NOT NULL DEFAULT 0 CHECK (handshake_count >= 0),
    capabilities        text[] NOT NULL DEFAULT '{}',
    last_request_at     timestamptz,
    last_request_ip     inet,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX agents_id_key ON agents (id);
-- Un seul agent actif par serveur : deux agents partageant un server_id
-- produiraient des heartbeats contradictoires.
CREATE UNIQUE INDEX agents_server_key ON agents (organization_id, server_id);

CREATE TABLE api_credentials (
    key_id              text NOT NULL CHECK (key_id ~ '^key_[0-9a-z]{26}$'),
    organization_id     text NOT NULL,
    server_id           text NOT NULL,
    agent_id            text NOT NULL,
    -- AES-256-GCM. Un secret HMAC doit être recalculé à chaque requête : il ne
    -- peut pas être haché comme un mot de passe. Voir docs/ARCHITECTURE.md §2.
    secret_encrypted    bytea NOT NULL,
    secret_hint         text NOT NULL CHECK (length(secret_hint) <= 8),
    status              credential_status NOT NULL DEFAULT 'ACTIVE',
    supersedes_key_id   text,
    created_by          text REFERENCES users(id) ON DELETE SET NULL,
    revoked_by          text REFERENCES users(id) ON DELETE SET NULL,
    revoke_reason       text CHECK (length(revoke_reason) <= 400),
    last_seen_at        timestamptz,
    expires_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    PRIMARY KEY (organization_id, key_id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX api_credentials_key_id_key ON api_credentials (key_id);
-- Recherche d'authentification : agent_id + key_id, filtrée sur l'état.
CREATE INDEX api_credentials_lookup_idx ON api_credentials (agent_id, key_id)
    WHERE status IN ('ACTIVE', 'PENDING_ROTATION');
-- Deux clés au maximum peuvent être utilisables simultanément, le temps d'une
-- rotation. Fermer la fenêtre plus tôt enfermerait l'agent dehors.
CREATE UNIQUE INDEX api_credentials_one_active_idx
    ON api_credentials (organization_id, server_id)
    WHERE status = 'ACTIVE';

-- -----------------------------------------------------------------------------
-- Incidents (déclarés avant alerts : les alertes les référencent)
-- -----------------------------------------------------------------------------
CREATE TABLE incidents (
    id                  text NOT NULL CHECK (id ~ '^inc_[0-9a-z]{26}$'),
    organization_id     text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    server_id           text,
    title               text NOT NULL CHECK (length(btrim(title)) BETWEEN 1 AND 200),
    description         text CHECK (length(description) <= 20000),
    severity            alert_severity NOT NULL DEFAULT 'MEDIUM',
    status              incident_status NOT NULL DEFAULT 'OPEN',
    assigned_to         text,
    opened_by           text,
    alert_count         integer NOT NULL DEFAULT 0 CHECK (alert_count >= 0),
    first_alert_at      timestamptz,
    last_alert_at       timestamptz,
    acknowledged_at     timestamptz,
    resolved_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    -- ON DELETE SET NULL sur une FK COMPOSITE met par défaut TOUTES les colonnes
    -- référençantes à NULL, y compris organization_id qui est NOT NULL : la
    -- suppression d'un serveur échouerait dès qu'il porte un incident. La liste
    -- de colonnes (PostgreSQL 15+) ne dénull que server_id. Vérifié par
    -- db/tests/isolation.sql.
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE SET NULL (server_id),
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (opened_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT incidents_resolved_consistency
        CHECK ((status IN ('RESOLVED', 'CLOSED')) = (resolved_at IS NOT NULL))
);
CREATE UNIQUE INDEX incidents_id_key ON incidents (id);
CREATE INDEX incidents_org_status_idx ON incidents (organization_id, status, created_at DESC);
CREATE INDEX incidents_server_idx ON incidents (organization_id, server_id, created_at DESC);

CREATE TABLE incident_events (
    id              bigserial PRIMARY KEY,
    organization_id text NOT NULL,
    incident_id     text NOT NULL,
    actor_user_id   text REFERENCES users(id) ON DELETE SET NULL,
    kind            text NOT NULL CHECK (kind IN
                    ('created', 'status_changed', 'severity_changed', 'assigned',
                     'comment', 'alert_linked', 'alert_unlinked')),
    body            text CHECK (length(body) <= 8000),
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, incident_id)
        REFERENCES incidents (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX incident_events_timeline_idx
    ON incident_events (organization_id, incident_id, created_at);

-- -----------------------------------------------------------------------------
-- Alerts — partitionnée par mois : la rétention est un détachement de partition,
-- pas un DELETE de plusieurs millions de lignes.
-- -----------------------------------------------------------------------------
CREATE TABLE alerts (
    id                  text NOT NULL CHECK (id ~ '^al_[0-9a-z]{26}$'),
    organization_id     text NOT NULL,
    server_id           text NOT NULL,
    -- Identifiant fourni par l'agent. Sert de clé d'idempotence d'ingestion.
    agent_alert_id      text NOT NULL CHECK (length(agent_alert_id) BETWEEN 1 AND 64),
    severity            alert_severity NOT NULL,
    category            alert_category NOT NULL,
    status              alert_status NOT NULL DEFAULT 'OPEN',
    summary             text NOT NULL CHECK (length(summary) BETWEEN 1 AND 512),
    metadata            jsonb NOT NULL DEFAULT '{}'::jsonb,
    reference           text CHECK (length(reference) <= 64),
    origin              text CHECK (length(origin) <= 64),
    -- Déduplication faite par l'agent : 50 détections identiques en 30 s
    -- arrivent comme UNE alerte avec occurrences = 50. Afficher le compteur.
    occurrences         integer NOT NULL DEFAULT 1 CHECK (occurrences >= 1),
    occurred_at         timestamptz NOT NULL,
    last_occurrence_at  timestamptz,
    incident_id         text,
    acknowledged_by     text,
    acknowledged_at     timestamptz,
    resolved_by         text,
    resolved_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id, created_at),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE,
    -- Même raison que pour incidents : seul incident_id doit être dénullé quand
    -- un incident est supprimé, sinon l'alerte perdrait son organisation.
    FOREIGN KEY (organization_id, incident_id)
        REFERENCES incidents (organization_id, id) ON DELETE SET NULL (incident_id),
    FOREIGN KEY (acknowledged_by) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT alerts_status_consistency CHECK (
        (status = 'ACKNOWLEDGED' AND acknowledged_at IS NOT NULL) OR
        (status = 'RESOLVED' AND resolved_at IS NOT NULL) OR
        (status = 'OPEN')
    ),
    CONSTRAINT alerts_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
) PARTITION BY RANGE (created_at);

-- Idempotence d'ingestion. NOTE : une contrainte unique sur table partitionnée
-- doit inclure la clé de partition, donc l'unicité est garantie DANS une
-- partition. Un agent qui resoumettrait la même alerte à un mois d'intervalle
-- créerait deux lignes. Accepté : la file locale de l'agent a un TTL de 24 h.
CREATE UNIQUE INDEX alerts_ingest_idempotency_idx
    ON alerts (organization_id, server_id, agent_alert_id, created_at);
CREATE INDEX alerts_org_created_idx ON alerts (organization_id, created_at DESC);
CREATE INDEX alerts_org_status_severity_idx
    ON alerts (organization_id, status, severity, created_at DESC);
CREATE INDEX alerts_server_idx ON alerts (organization_id, server_id, created_at DESC);
CREATE INDEX alerts_incident_idx ON alerts (organization_id, incident_id)
    WHERE incident_id IS NOT NULL;
CREATE INDEX alerts_category_idx ON alerts (organization_id, category, created_at DESC);

-- Partitions initiales. Le job de maintenance en crée à l'avance ; DEFAULT
-- empêche une insertion d'échouer si le job est en retard.
CREATE TABLE alerts_default PARTITION OF alerts DEFAULT;
CREATE TABLE alerts_2026_09 PARTITION OF alerts
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE alerts_2026_10 PARTITION OF alerts
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');
CREATE TABLE alerts_2026_11 PARTITION OF alerts
    FOR VALUES FROM ('2026-11-01') TO ('2026-12-01');

-- -----------------------------------------------------------------------------
-- Télémétrie — partitionnée, agrégée, et jamais nominative.
-- Le protocole n'expose aucun identifiant de joueur : seul un compteur.
-- -----------------------------------------------------------------------------
CREATE TABLE telemetry_samples (
    organization_id     text NOT NULL,
    server_id           text NOT NULL,
    sampled_at          timestamptz NOT NULL,
    players_online      integer CHECK (players_online >= 0),
    uptime_seconds      bigint CHECK (uptime_seconds >= 0),
    memory_mb           numeric(10, 2) CHECK (memory_mb >= 0),
    tick_ms             numeric(10, 3) CHECK (tick_ms >= 0),
    resource_count      integer CHECK (resource_count >= 0),
    error_count         integer CHECK (error_count >= 0),
    queue_size          integer CHECK (queue_size >= 0),
    dependencies        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, server_id, sampled_at, created_at),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE
) PARTITION BY RANGE (created_at);

CREATE INDEX telemetry_series_idx
    ON telemetry_samples (organization_id, server_id, sampled_at DESC);

CREATE TABLE telemetry_samples_default PARTITION OF telemetry_samples DEFAULT;
CREATE TABLE telemetry_samples_2026_09 PARTITION OF telemetry_samples
    FOR VALUES FROM ('2026-09-01') TO ('2026-10-01');
CREATE TABLE telemetry_samples_2026_10 PARTITION OF telemetry_samples
    FOR VALUES FROM ('2026-10-01') TO ('2026-11-01');

-- -----------------------------------------------------------------------------
-- File de commandes
-- -----------------------------------------------------------------------------
CREATE TABLE agent_commands (
    id                  text NOT NULL CHECK (id ~ '^cmd_[0-9a-zA-Z_-]{8,60}$'),
    organization_id     text NOT NULL,
    server_id           text NOT NULL,
    type                command_type NOT NULL,
    -- Le payload n'est pas un vecteur d'exécution : 8 clés, scalaires, 256 car.
    -- Aucun handler agent n'accepte de code, de chemin, de native ni d'URL.
    payload             jsonb NOT NULL DEFAULT '{}'::jsonb,
    status              command_status NOT NULL DEFAULT 'PENDING',
    result              command_result,
    result_detail       jsonb,
    reason              text CHECK (length(reason) <= 400),
    issued_by           text REFERENCES users(id) ON DELETE SET NULL,
    sent_at             timestamptz,
    delivery_count      integer NOT NULL DEFAULT 0 CHECK (delivery_count >= 0),
    acknowledged_at     timestamptz,
    executed_at         timestamptz,
    duration_ms         integer CHECK (duration_ms >= 0),
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id),
    FOREIGN KEY (organization_id, server_id)
        REFERENCES servers (organization_id, id) ON DELETE CASCADE,
    CONSTRAINT agent_commands_payload_is_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT agent_commands_expiry_after_creation CHECK (expires_at > created_at)
);
CREATE UNIQUE INDEX agent_commands_id_key ON agent_commands (id);
-- Chemin chaud : ce que l'agent récupère à chaque poll.
CREATE INDEX agent_commands_pending_idx
    ON agent_commands (organization_id, server_id, created_at)
    WHERE status IN ('PENDING', 'SENT');
CREATE INDEX agent_commands_expiry_idx ON agent_commands (expires_at)
    WHERE status IN ('PENDING', 'SENT');

-- -----------------------------------------------------------------------------
-- Audit log — append-only (voir les GRANT en fin de fichier)
-- -----------------------------------------------------------------------------
CREATE TABLE audit_logs (
    id              bigserial PRIMARY KEY,
    organization_id text REFERENCES organizations(id) ON DELETE CASCADE,
    actor_user_id   text REFERENCES users(id) ON DELETE SET NULL,
    actor_kind      text NOT NULL DEFAULT 'user'
                    CHECK (actor_kind IN ('user', 'agent', 'system')),
    actor_label     text CHECK (length(actor_label) <= 200),
    action          text NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
    target_kind     text CHECK (length(target_kind) <= 40),
    target_id       text CHECK (length(target_id) <= 64),
    -- IP conservée pour les actions de sécurité. Rétention distincte, voir
    -- docs/ARCHITECTURE.md ; ne pas journaliser d'IP pour de la simple lecture.
    ip              inet,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_logs_metadata_is_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX audit_logs_org_idx ON audit_logs (organization_id, created_at DESC);
CREATE INDEX audit_logs_actor_idx ON audit_logs (actor_user_id, created_at DESC);
CREATE INDEX audit_logs_action_idx ON audit_logs (organization_id, action, created_at DESC);

-- -----------------------------------------------------------------------------
-- Facturation. Aucune intégration de paiement : la spec l'interdit sans
-- spécification du fournisseur. Seuls le modèle et les quotas existent.
-- -----------------------------------------------------------------------------
CREATE TABLE plans (
    code            text PRIMARY KEY CHECK (code ~ '^[a-z0-9_]{2,32}$'),
    name            text NOT NULL,
    monthly_cents   integer NOT NULL CHECK (monthly_cents >= 0),
    currency        text NOT NULL DEFAULT 'EUR' CHECK (currency ~ '^[A-Z]{3}$'),
    is_public       boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE subscriptions (
    id                  text PRIMARY KEY,
    organization_id     text NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    plan_code           text NOT NULL REFERENCES plans(code),
    state               subscription_state NOT NULL DEFAULT 'TRIALING',
    trial_ends_at       timestamptz,
    current_period_end  timestamptz,
    external_ref        text,   -- rempli quand un PSP sera spécifié
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Quotas effectifs. Résolus par organisation : un override commercial ne doit
-- pas obliger à créer un plan sur mesure.
CREATE TABLE entitlements (
    organization_id     text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    key                 text NOT NULL CHECK (key ~ '^[a-z0-9_.]{2,48}$'),
    int_value           bigint,
    bool_value          boolean,
    source              text NOT NULL DEFAULT 'plan' CHECK (source IN ('plan', 'override')),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, key),
    CONSTRAINT entitlements_one_value CHECK (
        (int_value IS NOT NULL AND bool_value IS NULL) OR
        (int_value IS NULL AND bool_value IS NOT NULL)
    )
);

CREATE TABLE plan_entitlements (
    plan_code   text NOT NULL REFERENCES plans(code) ON DELETE CASCADE,
    key         text NOT NULL,
    int_value   bigint,
    bool_value  boolean,
    PRIMARY KEY (plan_code, key)
);

-- -----------------------------------------------------------------------------
-- Notifications
-- -----------------------------------------------------------------------------
CREATE TABLE notification_channels (
    id                  text NOT NULL,
    organization_id     text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (kind IN ('email', 'discord_webhook', 'dashboard')),
    -- URL de webhook chiffrée : un webhook Discord est un secret porteur.
    target_encrypted    bytea,
    target_hint         text CHECK (length(target_hint) <= 80),
    min_severity        alert_severity NOT NULL DEFAULT 'HIGH',
    enabled             boolean NOT NULL DEFAULT true,
    failure_count       integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    last_failure_at     timestamptz,
    created_by          text REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id)
);

CREATE TABLE notification_preferences (
    user_id             text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id     text NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email_alerts        boolean NOT NULL DEFAULT true,
    email_incidents     boolean NOT NULL DEFAULT true,
    email_min_severity  alert_severity NOT NULL DEFAULT 'HIGH',
    PRIMARY KEY (user_id, organization_id)
);

-- -----------------------------------------------------------------------------
-- Row Level Security
--
-- Deuxième couche d'isolation. Si une requête applicative oublie son filtre
-- organization_id, la base renvoie zéro ligne plutôt que les données du voisin.
-- L'application pose « SET LOCAL app.organization_id » au début de chaque
-- transaction tenant.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION app_current_org() RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('app.organization_id', true), '')
$$;

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'servers', 'agents', 'api_credentials', 'alerts', 'incidents',
        'incident_events', 'telemetry_samples', 'agent_commands',
        'memberships', 'invitations', 'notification_channels', 'entitlements'
    ]
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

-- audit_logs : lecture filtrée par tenant, insertion libre, aucune modification.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_logs FOR SELECT
    USING (organization_id = app_current_org());
CREATE POLICY audit_append ON audit_logs FOR INSERT
    WITH CHECK (organization_id IS NULL OR organization_id = app_current_org());

-- -----------------------------------------------------------------------------
-- Privilèges du rôle applicatif
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
        GRANT USAGE ON SCHEMA public TO zshield_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO zshield_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO zshield_app;

        -- Un journal d'audit que l'application peut réécrire ne prouve rien.
        REVOKE UPDATE, DELETE ON audit_logs FROM zshield_app;
        REVOKE UPDATE, DELETE ON incident_events FROM zshield_app;

        -- Aucun DDL, et surtout pas de contournement de RLS.
        REVOKE CREATE ON SCHEMA public FROM zshield_app;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- Données de référence
-- -----------------------------------------------------------------------------
INSERT INTO plans (code, name, monthly_cents, is_public) VALUES
    ('free',       'Free',        0, true),
    ('starter',    'Starter',  1900, true),
    ('pro',        'Pro',      4900, true),
    ('enterprise', 'Enterprise',  0, false)
ON CONFLICT (code) DO NOTHING;

INSERT INTO plan_entitlements (plan_code, key, int_value, bool_value) VALUES
    ('free',       'servers.max',            1,    NULL),
    ('free',       'users.max',              2,    NULL),
    ('free',       'retention.days',         7,    NULL),
    ('free',       'feature.incidents',      NULL, false),
    ('free',       'feature.webhooks',       NULL, false),
    ('starter',    'servers.max',            3,    NULL),
    ('starter',    'users.max',              5,    NULL),
    ('starter',    'retention.days',         30,   NULL),
    ('starter',    'feature.incidents',      NULL, true),
    ('starter',    'feature.webhooks',       NULL, true),
    ('pro',        'servers.max',            15,   NULL),
    ('pro',        'users.max',              25,   NULL),
    ('pro',        'retention.days',         90,   NULL),
    ('pro',        'feature.incidents',      NULL, true),
    ('pro',        'feature.webhooks',       NULL, true),
    ('enterprise', 'servers.max',            1000, NULL),
    ('enterprise', 'users.max',              500,  NULL),
    ('enterprise', 'retention.days',         365,  NULL),
    ('enterprise', 'feature.incidents',      NULL, true),
    ('enterprise', 'feature.webhooks',       NULL, true)
ON CONFLICT (plan_code, key) DO NOTHING;

COMMIT;
