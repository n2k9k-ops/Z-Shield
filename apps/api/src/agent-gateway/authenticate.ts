/**
 * Pipeline d'authentification des requêtes d'agent.
 *
 * L'ORDRE EST NORMATIF (docs/PROTOCOL.md §3) :
 *
 *   1. en-têtes présents et bien formés ;
 *   2. secret retrouvé par agent_id + key_id ;
 *   3. écart d'horloge dans la fenêtre (±300 s) ;
 *   4. nonce jamais vu ;
 *   5. signature recalculée et comparée en temps constant ;
 *   6. SEULEMENT ENSUITE, parsing du corps.
 *
 * Parser avant l'étape 5 exposerait le parser JSON à du trafic non authentifié,
 * et ferait dépendre le coût d'une requête forgée de la taille de son corps.
 *
 * Le corps est hachée sous sa forme BRUTE. Toute couche qui parse puis
 * re-sérialise avant cette vérification casse la signature — voir le test
 * `test/conformance.test.ts`, section « le corps brut est obligatoire ».
 */
import type { FastifyRequest } from 'fastify';
import { constantTimeEqual, hmacSha256Hex, sha256Hex } from '../lib/crypto.ts';
import { AGENT_ERROR, HEADER, canonicalRequest, type AgentErrorCode } from './protocol.ts';
import type { CredentialStore, ResolvedCredential } from './credentials.ts';
import { ReplayCheckUnavailable, type AgentRateLimiter, type ReplayGuard } from './replay.ts';

export interface AgentAuthContext {
  credential: ResolvedCredential;
  agentId: string;
  serverId: string;
  keyId: string;
  requestId: string;
  nonce: string;
  timestamp: number;
  agentVersion: string;
  protocolVersion: number;
  rawBody: Buffer;
}

export class AgentAuthError extends Error {
  readonly status: number;
  readonly code: AgentErrorCode;
  readonly retryAfter?: number;
  /** Détail journalisé côté plateforme, jamais renvoyé à l'agent. */
  readonly internalDetail?: string;

  constructor(
    status: number,
    code: AgentErrorCode,
    message: string,
    options?: { retryAfter?: number; internalDetail?: string },
  ) {
    super(message);
    this.name = 'AgentAuthError';
    this.status = status;
    this.code = code;
    this.retryAfter = options?.retryAfter;
    this.internalDetail = options?.internalDetail;
  }
}

function header(request: FastifyRequest, name: string): string | null {
  const value = request.headers[name];
  if (typeof value === 'string') return value;
  // Un en-tête répété est une anomalie, pas une valeur à choisir au hasard.
  if (Array.isArray(value)) return null;
  return null;
}

/** Format des identifiants. Rejeter tôt évite une requête inutile en base. */
const ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const NONCE_PATTERN = /^[0-9a-f]{16,128}$/;
const SIGNATURE_PATTERN = /^[0-9a-f]{64}$/;

export interface AuthenticatorDeps {
  credentials: CredentialStore;
  replay: ReplayGuard;
  rateLimiter: AgentRateLimiter;
  clockSkewSeconds: number;
  now?: () => number;
}

export class AgentAuthenticator {
  private readonly deps: AuthenticatorDeps;

  constructor(deps: AuthenticatorDeps) {
    this.deps = deps;
  }

  private now(): number {
    return this.deps.now ? this.deps.now() : Math.floor(Date.now() / 1000);
  }

  /**
   * Authentifie la requête ou lève une AgentAuthError.
   *
   * `rawBody` doit être le buffer exact reçu sur le socket.
   */
  async authenticate(request: FastifyRequest, rawBody: Buffer): Promise<AgentAuthContext> {
    // --- 1. en-têtes -------------------------------------------------------
    const agentId = header(request, HEADER.AGENT_ID);
    const serverId = header(request, HEADER.SERVER_ID);
    const keyId = header(request, HEADER.KEY_ID);
    const timestampRaw = header(request, HEADER.TIMESTAMP);
    const nonce = header(request, HEADER.NONCE);
    const signature = header(request, HEADER.SIGNATURE);
    const protocolRaw = header(request, HEADER.PROTOCOL);
    const agentVersion = header(request, HEADER.AGENT_VERSION) ?? 'unknown';
    const requestId = header(request, HEADER.REQUEST_ID) ?? '';

    if (!agentId || !serverId || !keyId || !timestampRaw || !nonce || !signature) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_INVALID_SIGNATURE, 'signed headers missing');
    }
    if (!ID_PATTERN.test(agentId) || !ID_PATTERN.test(serverId) || !ID_PATTERN.test(keyId)) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_INVALID_SIGNATURE, 'malformed identifiers');
    }
    if (!NONCE_PATTERN.test(nonce) || !SIGNATURE_PATTERN.test(signature)) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_INVALID_SIGNATURE, 'malformed nonce or signature');
    }

    const timestamp = Number(timestampRaw);
    if (!Number.isInteger(timestamp) || timestamp <= 0) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_CLOCK_SKEW, 'malformed timestamp');
    }

    const protocolVersion = Number(protocolRaw ?? '0');
    if (!Number.isInteger(protocolVersion) || protocolVersion < 1) {
      throw new AgentAuthError(400, AGENT_ERROR.VALIDATION, 'malformed protocol version');
    }

    // Limitation de débit avant la lecture en base : un agent en boucle ne doit
    // pas coûter une requête SQL par tentative.
    const rate = await this.deps.rateLimiter.consume(agentId);
    if (!rate.allowed) {
      throw new AgentAuthError(429, AGENT_ERROR.RATE_LIMITED, 'rate limit exceeded', {
        retryAfter: rate.retryAfterSeconds,
      });
    }

    // --- 2. secret ---------------------------------------------------------
    const credential = await this.deps.credentials.resolve(agentId, keyId);
    if (!credential) {
      // Message identique à celui d'une signature invalide : l'agent n'apprend
      // pas si la clé existe.
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_CREDENTIAL_REVOKED, 'credential not usable', {
        internalDetail: `unknown or revoked key_id=${keyId} agent_id=${agentId}`,
      });
    }

    // L'agent affirme un server_id dans son en-tête ; la credential dit lequel
    // il est réellement. Si les deux diffèrent, la requête est rejetée : sans
    // ce contrôle, un agent légitime pourrait écrire sur un autre serveur de la
    // même organisation.
    if (credential.serverId !== serverId) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_INVALID_SIGNATURE, 'identity mismatch', {
        internalDetail: `header server_id=${serverId} but credential binds ${credential.serverId}`,
      });
    }

    // --- 3. horloge --------------------------------------------------------
    const skew = Math.abs(this.now() - timestamp);
    if (skew > this.deps.clockSkewSeconds) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_CLOCK_SKEW, 'timestamp outside accepted window', {
        internalDetail: `skew=${skew}s limit=${this.deps.clockSkewSeconds}s`,
      });
    }

    // --- 4. nonce ----------------------------------------------------------
    let fresh: boolean;
    try {
      fresh = await this.deps.replay.claim(agentId, keyId, nonce);
    } catch (error) {
      if (error instanceof ReplayCheckUnavailable) {
        // Échec fermé : sans cache, l'unicité n'est pas vérifiable.
        throw new AgentAuthError(503, AGENT_ERROR.INTERNAL, 'replay protection unavailable', {
          retryAfter: 15,
          internalDetail: String(error.cause),
        });
      }
      throw error;
    }
    if (!fresh) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_REPLAY, 'nonce already used');
    }

    // --- 5. signature ------------------------------------------------------
    const path = request.raw.url?.split('?')[0] ?? request.url.split('?')[0] ?? '';
    const queryIndex = (request.raw.url ?? '').indexOf('?');
    // Query string brute, telle que signée par l'agent. Ne pas passer par un
    // URLSearchParams : il réordonne et ré-encode.
    const query = queryIndex >= 0 ? (request.raw.url ?? '').slice(queryIndex + 1) : '';

    const canonical = canonicalRequest({
      method: request.method,
      path,
      query,
      agentId,
      serverId,
      keyId,
      timestamp,
      nonce,
      bodyHash: sha256Hex(rawBody),
    });

    const expected = hmacSha256Hex(credential.secret, canonical);
    if (!constantTimeEqual(signature, expected)) {
      throw new AgentAuthError(401, AGENT_ERROR.AUTH_INVALID_SIGNATURE, 'signature mismatch', {
        internalDetail: `canonical path=${path} query=${query} bodyBytes=${rawBody.length}`,
      });
    }

    return {
      credential,
      agentId,
      serverId,
      keyId,
      requestId,
      nonce,
      timestamp,
      agentVersion,
      protocolVersion,
      rawBody,
    };
  }
}
