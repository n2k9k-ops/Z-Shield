/**
 * Routes de la passerelle agent.
 *
 * Enregistrées dans un plugin isolé pour que le parseur de corps brut et le
 * gestionnaire d'erreurs signé ne s'appliquent QU'ICI. Les routes utilisateur
 * ont des besoins opposés (parsing JSON normal, erreurs non signées, CSRF) ;
 * les faire cohabiter dans la même portée est la voie la plus courte vers une
 * confusion de surface d'authentification.
 */
import type { FastifyInstance, FastifyPluginOptions, FastifyReply, FastifyRequest } from 'fastify';
import type { ZodSchema } from 'zod';
import { AGENT_ERROR, ENDPOINT, MAX_BODY_BYTES, MAX_COMMANDS_PER_POLL } from './protocol.ts';
import { AgentAuthError, type AgentAuthContext, type AgentAuthenticator } from './authenticate.ts';
import { sendSignedError, sendSignedOk, sendUnsignableError } from './respond.ts';
import {
  alertsPayloadSchema,
  commandResultsPayloadSchema,
  configQuerySchema,
  envelopeSchema,
  handshakePayloadSchema,
  heartbeatPayloadSchema,
  rotatePayloadSchema,
  telemetryPayloadSchema,
} from './schemas.ts';
import type { AgentGatewayService } from './service.ts';
import type { CredentialStore } from './credentials.ts';
import type { Logger } from '../lib/logger.ts';

export interface GatewayOptions extends FastifyPluginOptions {
  authenticator: AgentAuthenticator;
  service: AgentGatewayService;
  credentials: CredentialStore;
  logger: Logger;
}

/** Corps brut mémorisé par le parseur, relu par la vérification de signature. */
const RAW_BODY = Symbol('rawBody');

interface WithRawBody {
  [RAW_BODY]?: Buffer;
}

export async function agentGatewayRoutes(
  app: FastifyInstance,
  options: GatewayOptions,
): Promise<void> {
  const { authenticator, service, logger } = options;

  // Le corps est conservé tel quel. Aucun parsing avant vérification de la
  // signature : c'est l'exigence centrale du protocole.
  app.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer', bodyLimit: MAX_BODY_BYTES },
    (request, body, done) => {
      (request as FastifyRequest & WithRawBody)[RAW_BODY] = body as Buffer;
      done(null, undefined);
    },
  );

  /**
   * Authentifie puis valide. Retourne null si une réponse a déjà été envoyée.
   */
  async function guard(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<AgentAuthContext | null> {
    const rawBody = (request as FastifyRequest & WithRawBody)[RAW_BODY] ?? Buffer.alloc(0);

    try {
      const ctx = await authenticator.authenticate(request, rawBody);
      void options.credentials.touch(ctx.credential.organizationId, ctx.keyId);
      return ctx;
    } catch (error) {
      if (error instanceof AgentAuthError) {
        // Le détail interne est journalisé, jamais renvoyé : un attaquant ne
        // doit pas apprendre laquelle des cinq vérifications a échoué.
        logger.warn('requête agent rejetée', {
          code: error.code,
          status: error.status,
          detail: error.internalDetail,
          agent_id: request.headers['x-zshield-agent-id'],
          path: request.url,
        });

        // Sans credential résolue, pas de secret, donc pas de signature
        // possible. Voir respond.ts pour pourquoi c'est le bon comportement.
        sendUnsignableError(reply, error.status, error.code, error.message, error.retryAfter);
        return null;
      }

      logger.error("erreur interne pendant l'authentification agent", {
        detail: error instanceof Error ? error.message : String(error),
      });
      sendUnsignableError(reply, 500, AGENT_ERROR.INTERNAL, 'internal error', 30);
      return null;
    }
  }

  /** Valide l'enveloppe, vérifie la cohérence avec les en-têtes signés, extrait le payload. */
  function parseEnvelope<T>(
    ctx: AgentAuthContext,
    reply: FastifyReply,
    kind: string,
    payloadSchema: ZodSchema<T>,
  ): T | null {
    const signable = { secret: ctx.credential.secret, requestId: ctx.requestId };

    let decoded: unknown;
    try {
      decoded = JSON.parse(ctx.rawBody.toString('utf8'));
    } catch {
      sendSignedError(reply, 400, AGENT_ERROR.VALIDATION, 'body is not valid JSON', signable);
      return null;
    }

    const envelope = envelopeSchema.safeParse(decoded);
    if (!envelope.success) {
      sendSignedError(
        reply,
        400,
        AGENT_ERROR.VALIDATION,
        `invalid envelope: ${envelope.error.issues[0]?.path.join('.') ?? 'unknown field'}`,
        signable,
      );
      return null;
    }

    // L'autorité est l'en-tête signé, jamais l'enveloppe. Un écart signifie
    // soit un bug d'agent, soit une tentative d'écrire chez le voisin.
    if (
      envelope.data.server_id !== ctx.serverId ||
      envelope.data.agent_id !== ctx.agentId
    ) {
      logger.warn('enveloppe incohérente avec les en-têtes signés', {
        header_server_id: ctx.serverId,
        envelope_server_id: envelope.data.server_id,
      });
      sendSignedError(
        reply,
        400,
        AGENT_ERROR.VALIDATION,
        'envelope identity does not match signed headers',
        signable,
      );
      return null;
    }

    if (envelope.data.kind !== kind) {
      sendSignedError(reply, 400, AGENT_ERROR.VALIDATION, 'envelope kind mismatch', signable);
      return null;
    }

    const payload = payloadSchema.safeParse(envelope.data.payload);
    if (!payload.success) {
      sendSignedError(
        reply,
        400,
        AGENT_ERROR.VALIDATION,
        `invalid payload: ${payload.error.issues[0]?.path.join('.') ?? 'unknown field'}`,
        signable,
      );
      return null;
    }

    return payload.data;
  }

  const signableOf = (ctx: AgentAuthContext) => ({
    secret: ctx.credential.secret,
    requestId: ctx.requestId,
  });

  /** Enveloppe commune : capture les exceptions et répond en signé. */
  async function handle(
    reply: FastifyReply,
    ctx: AgentAuthContext,
    work: () => Promise<Record<string, unknown> | null>,
  ): Promise<void> {
    try {
      const data = await work();
      if (data === null) {
        sendSignedError(
          reply,
          404,
          AGENT_ERROR.AUTH_CREDENTIAL_REVOKED,
          'server no longer exists',
          signableOf(ctx),
        );
        return;
      }
      sendSignedOk(reply, data, signableOf(ctx));
    } catch (error) {
      logger.error('échec du traitement agent', {
        server_id: ctx.serverId,
        detail: error instanceof Error ? error.message : String(error),
      });
      sendSignedError(reply, 500, AGENT_ERROR.INTERNAL, 'internal error', signableOf(ctx), 30);
    }
  }

  // -------------------------------------------------------------------------
  app.post(ENDPOINT.HANDSHAKE, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'handshake', handshakePayloadSchema);
    if (!payload) return;

    await handle(reply, ctx, () => service.handshake(ctx, payload));
  });

  app.post(ENDPOINT.HEARTBEAT, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'heartbeat', heartbeatPayloadSchema);
    if (!payload) return;

    await handle(reply, ctx, () => service.heartbeat(ctx, payload));
  });

  app.post(ENDPOINT.TELEMETRY, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'telemetry', telemetryPayloadSchema);
    if (!payload) return;

    await handle(reply, ctx, () => service.telemetry(ctx, payload));
  });

  app.post(ENDPOINT.ALERTS, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'alerts', alertsPayloadSchema);
    if (!payload) return;

    await handle(reply, ctx, () => service.alerts(ctx, payload));
  });

  app.get(ENDPOINT.CONFIG, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const query = configQuerySchema.safeParse(request.query);
    if (!query.success) {
      sendSignedError(reply, 400, AGENT_ERROR.VALIDATION, 'invalid query', signableOf(ctx));
      return;
    }

    await handle(reply, ctx, async () => {
      const result = await service.config(ctx);
      if (!result) return null;

      if (result.invalid) {
        // Renvoyer un document que l'agent rejettera intégralement serait pire
        // qu'une erreur franche : il garderait sa configuration précédente sans
        // que l'incident soit visible côté plateforme.
        logger.error('configuration distante stockée invalide', {
          server_id: ctx.serverId,
          fields: result.issues,
        });
        throw new Error('stored remote configuration is invalid');
      }

      return { config: result.config };
    });
  });

  app.get(ENDPOINT.COMMANDS, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const raw = (request.query as { limit?: string }).limit;
    const limit = Math.min(Number(raw ?? MAX_COMMANDS_PER_POLL) || MAX_COMMANDS_PER_POLL, MAX_COMMANDS_PER_POLL);

    await handle(reply, ctx, () => service.claimCommands(ctx, limit));
  });

  app.post(ENDPOINT.COMMAND_RESULT, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'command.results', commandResultsPayloadSchema);
    if (!payload) return;

    await handle(reply, ctx, () => service.commandResults(ctx, payload));
  });

  app.post(ENDPOINT.ROTATE, async (request, reply) => {
    const ctx = await guard(request, reply);
    if (!ctx) return;

    const payload = parseEnvelope(ctx, reply, 'credential.rotate', rotatePayloadSchema);
    if (!payload) return;

    // L'agent doit signer avec la clé qu'il déclare vouloir remplacer.
    if (payload.current_key_id !== ctx.keyId) {
      sendSignedError(
        reply,
        400,
        AGENT_ERROR.VALIDATION,
        'current_key_id does not match the signing key',
        signableOf(ctx),
      );
      return;
    }

    await handle(reply, ctx, () => service.rotate(ctx, payload.reason));
  });
}
