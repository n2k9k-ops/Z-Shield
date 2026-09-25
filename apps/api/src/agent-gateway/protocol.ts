/**
 * Contrat de fil Agent <-> plateforme.
 *
 * Ce fichier est le miroir exact de `zshield-agent/shared/protocol.lua`. Toute
 * divergence casse l'authentification d'agents déjà déployés, sans message
 * d'erreur exploitable côté opérateur : la signature ne correspond simplement
 * plus. Le test `test/conformance.test.ts` compare les deux implémentations en
 * exécutant réellement le Lua de l'agent.
 *
 * Ne pas « améliorer » l'ordre des champs ni le préfixe : ils sont figés.
 */
import { sha256Hex } from '../lib/crypto.ts';

export const PROTOCOL_VERSION = 1;
export const MIN_AGENT_PROTOCOL = 1;

/** Empreinte du corps vide, utilisée par les requêtes GET. */
export const EMPTY_BODY_HASH = sha256Hex('');

export const HEADER = {
  AGENT_ID: 'x-zshield-agent-id',
  SERVER_ID: 'x-zshield-server-id',
  KEY_ID: 'x-zshield-key-id',
  TIMESTAMP: 'x-zshield-timestamp',
  NONCE: 'x-zshield-nonce',
  SIGNATURE: 'x-zshield-signature',
  PROTOCOL: 'x-zshield-protocol',
  AGENT_VERSION: 'x-zshield-agent-version',
  REQUEST_ID: 'x-zshield-request-id',
} as const;

/** Casse d'origine, pour les en-têtes que la plateforme émet. */
export const RESPONSE_HEADER = {
  TIMESTAMP: 'X-ZShield-Timestamp',
  NONCE: 'X-ZShield-Nonce',
  SIGNATURE: 'X-ZShield-Signature',
} as const;

export const ENDPOINT = {
  HANDSHAKE: '/v1/agents/handshake',
  HEARTBEAT: '/v1/agents/heartbeat',
  TELEMETRY: '/v1/agents/telemetry',
  ALERTS: '/v1/agents/alerts',
  CONFIG: '/v1/agents/config',
  COMMANDS: '/v1/agents/commands',
  COMMAND_RESULT: '/v1/agents/commands/results',
  ROTATE: '/v1/agents/credentials/rotate',
} as const;

// ---------------------------------------------------------------------------
// Chaînes canoniques
// ---------------------------------------------------------------------------

export interface CanonicalRequestParts {
  method: string;
  /** Chemin sans query string. */
  path: string;
  /** Query string brute telle que reçue, ou chaîne vide. */
  query: string;
  agentId: string;
  serverId: string;
  keyId: string;
  timestamp: number | string;
  nonce: string;
  /** sha256 hex minuscule du corps BRUT, jamais d'une ré-sérialisation. */
  bodyHash: string;
}

/**
 * Séparateur LF, aucun saut de ligne final.
 *
 * La méthode, le chemin et la query sont signés : une requête capturée ne peut
 * pas être rejouée contre un autre endpoint.
 */
export function canonicalRequest(parts: CanonicalRequestParts): string {
  return [
    `ZSHIELD-AGENT-V${PROTOCOL_VERSION}`,
    parts.method.toUpperCase(),
    parts.path,
    parts.query,
    parts.agentId,
    parts.serverId,
    parts.keyId,
    String(parts.timestamp),
    parts.nonce,
    parts.bodyHash,
  ].join('\n');
}

export interface CanonicalResponseParts {
  status: number | string;
  /** request_id repris de la requête de l'agent. */
  requestId: string;
  timestamp: number | string;
  nonce: string;
  bodyHash: string;
}

export function canonicalResponse(parts: CanonicalResponseParts): string {
  return [
    `ZSHIELD-PLATFORM-V${PROTOCOL_VERSION}`,
    String(parts.status),
    parts.requestId,
    String(parts.timestamp),
    parts.nonce,
    parts.bodyHash,
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Taxonomie d'erreurs
// ---------------------------------------------------------------------------

/**
 * Codes reconnus par l'agent. Le code renvoyé peut *préciser* l'erreur, jamais
 * l'élargir : un statut HTTP fatal reste fatal côté agent même si le corps
 * annonce un code réessayable. Inutile donc d'espérer qu'un agent réessaie un
 * 401 parce qu'on lui aurait mis `retry_after`.
 */
export const AGENT_ERROR = {
  VALIDATION: 'E_VALIDATION',
  AUTH_CLOCK_SKEW: 'E_AUTH_CLOCK_SKEW',
  AUTH_REPLAY: 'E_AUTH_REPLAY',
  AUTH_INVALID_SIGNATURE: 'E_AUTH_INVALID_SIGNATURE',
  AUTH_CREDENTIAL_REVOKED: 'E_AUTH_CREDENTIAL_REVOKED',
  PROTOCOL_UNSUPPORTED: 'E_PROTOCOL_UNSUPPORTED',
  PAYLOAD_TOO_LARGE: 'E_PAYLOAD_TOO_LARGE',
  RATE_LIMITED: 'E_RATE_LIMITED',
  INTERNAL: 'E_INTERNAL',
} as const;

export type AgentErrorCode = (typeof AGENT_ERROR)[keyof typeof AGENT_ERROR];

/** Corps maximal accepté : 256 KiB, identique à la limite d'émission de l'agent. */
export const MAX_BODY_BYTES = 262_144;

/** Bornes de la configuration distante. L'agent rejette tout document hors bornes. */
export const REMOTE_CONFIG_BOUNDS = {
  heartbeat_interval: { min: 15, max: 900 },
  telemetry_interval: { min: 30, max: 3600 },
  alert_batch_size: { min: 1, max: 200 },
  alert_flush_interval: { min: 1, max: 300 },
} as const;

/** Allowlist figée. L'agent rejette tout le lot si un type inconnu apparaît. */
export const COMMAND_TYPES = [
  'ping',
  'request_status',
  'request_health_check',
  'refresh_configuration',
  'reload_safe_configuration',
  'flush_queue',
  'rotate_credential',
  // Observation serveur-autoritative (Multi-vue). L'agent met en place une
  // caméra d'administration DANS le monde du jeu sur la cible : le serveur
  // reconstitue la scène. Ce n'est JAMAIS une capture de l'écran ou de la
  // machine du joueur. `spectate_stop` met fin à l'observation.
  'spectate_request',
  'spectate_stop',
] as const;

export type CommandType = (typeof COMMAND_TYPES)[number];

/** Nombre maximal de commandes par lot, imposé par le schéma de l'agent. */
export const MAX_COMMANDS_PER_POLL = 25;
