/**
 * Schémas de validation de tout ce qui entre par la passerelle agent.
 *
 * Règles appliquées partout :
 *   - `.strict()` : un champ inconnu fait rejeter la requête. Ignorer un champ
 *     inattendu, c'est accepter qu'un agent d'une version future envoie des
 *     données qu'on stocke sans les comprendre ;
 *   - toutes les bornes viennent de docs/PROTOCOL.md, pas d'une estimation ;
 *   - aucun champ ne porte d'identifiant de joueur : le protocole n'en expose
 *     aucun, et en accepter un ici créerait une obligation RGPD que le produit
 *     n'a pas assumée.
 */
import { z } from 'zod';
import { COMMAND_TYPES, MAX_COMMANDS_PER_POLL, REMOTE_CONFIG_BOUNDS } from './protocol.ts';

const unixSeconds = z.number().int().min(0).max(4_000_000_000);
const shortText = (max: number) => z.string().max(max);

export const SEVERITIES = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export const CATEGORIES = [
  'event',
  'entity',
  'movement',
  'economy',
  'weapon',
  'resource',
  'admin',
  'agent',
  'other',
] as const;

/** Enveloppe commune. Les identifiants y figurent mais l'autorité est l'en-tête signé. */
export const envelopeSchema = z
  .object({
    protocol_version: z.number().int().min(1).max(100),
    agent_version: shortText(32),
    kind: shortText(32),
    server_id: shortText(64),
    agent_id: shortText(64),
    environment: z.enum(['production', 'staging', 'development']),
    sent_at: unixSeconds,
    payload: z.record(z.unknown()),
  })
  .strict();

export type Envelope = z.infer<typeof envelopeSchema>;

// ---------------------------------------------------------------------------
// Payloads
// ---------------------------------------------------------------------------

export const handshakePayloadSchema = z
  .object({
    server: z
      .object({
        fxserver_version: shortText(64).optional(),
        onesync: shortText(32).optional(),
        max_players: z.number().int().min(0).max(2048).optional(),
        uptime_seconds: z.number().int().min(0).optional(),
        resource_count: z.number().int().min(0).max(10_000).optional(),
      })
      .strict()
      .optional(),
    capabilities: z.array(shortText(32)).max(32).optional(),
    queue: z
      .object({
        size: z.number().int().min(0).optional(),
        dropped: z.number().int().min(0).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export const heartbeatPayloadSchema = z
  .object({
    state: z.enum(['BOOTING', 'MISCONFIGURED', 'HANDSHAKING', 'ONLINE', 'DEGRADED', 'OFFLINE', 'STOPPING']),
    agent_version: shortText(32),
    protocol_version: z.number().int().min(1).max(100),
    uptime_seconds: z.number().int().min(0),
    // Absent si la métrique est désactivée par l'opérateur. Absent n'est pas 0 :
    // afficher 0 joueur pour un serveur qui a coupé la métrique serait un
    // mensonge sur le dashboard.
    players_online: z.number().int().min(0).max(2048).optional(),
    config_version: z.number().int().min(0),
    queue_size: z.number().int().min(0),
    health: z.enum(['HEALTHY', 'DEGRADED', 'FAILED', 'UNKNOWN']),
    last_error: shortText(1000).nullable().optional(),
    // Empreinte du serveur (16 hex) remontée par le cœur, pour lier les licences.
    server_fingerprint: z.string().regex(/^[0-9a-f]{16}$/).optional(),
  })
  .strict();

/**
 * Instantané agrégé des protections natives du cœur anticheat (§08/§10/§21/§15/
 * §17/§29). Compteurs seulement — aucun identifiant de joueur. Strict et borné :
 * un agent qui tenterait d'y glisser un arbre arbitraire serait rejeté.
 */
export const protectionsSnapshotSchema = z
  .object({
    version: z.string().max(32).optional(),
    layers: z
      .record(z.record(z.union([z.number(), z.string().max(32)])))
      .optional(),
    reputation: z.record(z.number().int().min(0).max(100_000)).optional(),
    evidence: z.record(z.number().int().min(0)).optional(),
    performance: z
      .object({
        critical_ms: z.number().min(0).max(60_000),
        budget_ms: z.number().min(0).max(60_000),
        overhead_pct: z.number().min(0).max(100),
      })
      .partial()
      .optional(),
    onesync_lockdown: z.enum(['inactive', 'relaxed', 'strict']).optional(),
  })
  .strict();

export const telemetryPayloadSchema = z
  .object({
    samples: z
      .array(
        z
          .object({
            sampled_at: unixSeconds,
            players_online: z.number().int().min(0).max(2048).optional(),
            uptime_seconds: z.number().int().min(0).optional(),
            memory_mb: z.number().min(0).max(1_048_576).optional(),
            tick_ms: z.number().min(0).max(60_000).optional(),
            resource_count: z.number().int().min(0).max(10_000).optional(),
            error_count: z.number().int().min(0).optional(),
            queue_size: z.number().int().min(0).optional(),
            dependencies: z.record(z.enum(['started', 'stopped', 'missing'])).optional(),
            protections: protectionsSnapshotSchema.optional(),
          })
          .strict(),
      )
      .min(1)
      .max(120),
  })
  .strict();

/**
 * Métadonnées d'alerte : 32 clés maximum, valeurs scalaires seulement.
 * Refuser les objets imbriqués n'est pas de la rigidité : un détecteur qui
 * envoie un arbre arbitraire finit par envoyer des données de joueur.
 */
const alertMetadataSchema = z
  .record(z.union([z.string().max(1024), z.number(), z.boolean(), z.null()]))
  .refine((value) => Object.keys(value).length <= 32, {
    message: 'metadata accepte 32 clés au maximum',
  });

export const alertSchema = z
  .object({
    id: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9_-]+$/, 'identifiant d’alerte non conforme'),
    category: z.enum(CATEGORIES),
    severity: z.enum(SEVERITIES),
    summary: z.string().min(1).max(512),
    metadata: alertMetadataSchema.optional(),
    reference: shortText(64).optional(),
    // Déduplication faite par l'agent : 50 détections identiques en 30 s
    // arrivent comme une seule alerte avec occurrences = 50.
    occurrences: z.number().int().min(1).max(1_000_000).optional(),
    occurred_at: unixSeconds,
    last_occurrence_at: unixSeconds.optional(),
    origin: shortText(64).optional(),
    // Proposition de sanction attachée à l'alerte. Quand elle est présente, la
    // plateforme crée un ban : ACTIVE si l'alerte est CRITICAL (le cœur a une
    // certitude, ex. traces d'injection), sinon PENDING (revue humaine avant
    // application). L'exécution reste à l'agent ; la plateforme tient le registre.
    sanction: z
      .object({
        scope: z.enum(['license', 'discord', 'steam', 'ip', 'fivem']),
        identifier: z.string().min(1).max(128),
        player_name: z.string().max(64).optional(),
        detector: z.string().min(1).max(64),
        risk: z.number().int().min(0).max(100).optional(),
        evidence_kind: z.enum(['clip', 'screenshot']).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export const alertsPayloadSchema = z
  .object({
    alerts: z.array(alertSchema).min(1).max(200),
  })
  .strict();

export const commandResultsPayloadSchema = z
  .object({
    results: z
      .array(
        z
          .object({
            id: z.string().min(1).max(64),
            status: z.enum(['COMPLETED', 'FAILED', 'REJECTED', 'DUPLICATE']),
            result: z.record(z.unknown()).optional(),
            reason: shortText(400).optional(),
            executed_at: unixSeconds,
            duration_ms: z.number().int().min(0).max(600_000).optional(),
          })
          .strict(),
      )
      .min(1)
      .max(50),
  })
  .strict();

export const rotatePayloadSchema = z
  .object({
    reason: shortText(200).optional(),
    current_key_id: z.string().min(1).max(64),
  })
  .strict();

// ---------------------------------------------------------------------------
// Configuration distante
//
// Ce schéma est le contrat inverse : ce que la plateforme est autorisée à
// pousser. L'agent rejette le document ENTIER sur un seul champ inconnu, donc
// une validation laxiste ici produit un agent qui ignore toute configuration.
// ---------------------------------------------------------------------------

export const remoteConfigSchema = z
  .object({
    telemetry_enabled: z.boolean().optional(),
    heartbeat_interval: z
      .number()
      .int()
      .min(REMOTE_CONFIG_BOUNDS.heartbeat_interval.min)
      .max(REMOTE_CONFIG_BOUNDS.heartbeat_interval.max)
      .optional(),
    telemetry_interval: z
      .number()
      .int()
      .min(REMOTE_CONFIG_BOUNDS.telemetry_interval.min)
      .max(REMOTE_CONFIG_BOUNDS.telemetry_interval.max)
      .optional(),
    alert_batch_size: z
      .number()
      .int()
      .min(REMOTE_CONFIG_BOUNDS.alert_batch_size.min)
      .max(REMOTE_CONFIG_BOUNDS.alert_batch_size.max)
      .optional(),
    alert_flush_interval: z
      .number()
      .int()
      .min(REMOTE_CONFIG_BOUNDS.alert_flush_interval.min)
      .max(REMOTE_CONFIG_BOUNDS.alert_flush_interval.max)
      .optional(),
    log_level: z.enum(['DEBUG', 'INFO', 'WARN', 'ERROR']).optional(),
    metrics: z
      .object({
        players: z.boolean().optional(),
        performance: z.boolean().optional(),
        errors: z.boolean().optional(),
        dependencies: z.boolean().optional(),
        resources: z.boolean().optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type RemoteConfig = z.infer<typeof remoteConfigSchema>;

/**
 * Commande émise vers un agent. Le payload n'est pas un vecteur d'exécution :
 * 8 clés, scalaires, 256 caractères. Aucun handler de l'agent n'accepte de
 * code, de chemin de fichier, de nom de native, de ligne de commande ni d'URL —
 * et en ajouter ici ne changerait rien, l'agent rejetterait.
 */
export const commandPayloadSchema = z
  .record(z.union([z.string().max(256), z.number(), z.boolean()]))
  .refine((value) => Object.keys(value).length <= 8, {
    message: 'le payload de commande accepte 8 clés au maximum',
  });

export const issueCommandSchema = z
  .object({
    type: z.enum(COMMAND_TYPES),
    payload: commandPayloadSchema.optional(),
    ttl_seconds: z.number().int().min(30).max(86_400).default(300),
  })
  .strict();

export const commandPollQuerySchema = z
  .object({
    limit: z.coerce.number().int().min(1).max(MAX_COMMANDS_PER_POLL).default(MAX_COMMANDS_PER_POLL),
  })
  .strict();

export const configQuerySchema = z
  .object({
    version: z.coerce.number().int().min(0).optional(),
  })
  .strict();
