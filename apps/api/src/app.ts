/**
 * Construction de l'application.
 *
 * Séparée de `server.ts` pour que les tests puissent instancier l'API complète
 * et l'interroger via `app.inject()`, sans ouvrir de port. Un test d'isolation
 * qui court-circuite le routage et appelle directement les fonctions internes
 * ne prouve rien sur ce que voit un vrai client HTTP.
 */
import Fastify, { type FastifyInstance } from 'fastify';
import cookie from '@fastify/cookie';
import websocket from '@fastify/websocket';
import type { Pool } from 'pg';
import type { RedisBundle } from './lib/redis.ts';
import { isReachable as dbReachable } from './lib/db.ts';
import { isReachable as redisReachable } from './lib/redis.ts';
import { createLogger, type Logger } from './lib/logger.ts';
import { CredentialStore } from './agent-gateway/credentials.ts';
import { AgentRateLimiter, ReplayGuard } from './agent-gateway/replay.ts';
import { AgentAuthenticator } from './agent-gateway/authenticate.ts';
import { AgentGatewayService } from './agent-gateway/service.ts';
import { agentGatewayRoutes } from './agent-gateway/routes.ts';
import { AuthService } from './auth/sessions.ts';
import { Guard } from './api/middleware.ts';
import { apiRoutes } from './api/routes.ts';
import { registerRealtime } from './realtime/websocket.ts';

export interface DiscordOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface AppConfig {
  credentialKey: Buffer;
  sessionSecret: string;
  clockSkewSeconds: number;
  nonceTtlSeconds: number;
  agentRateLimitPerMinute: number;
  corsOrigins: string[];
  isProduction: boolean;
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  /** Origine publique du front (redirections OAuth). Vide = déduite de la requête. */
  webOrigin?: string | null;
  /** Config Discord ; null/absente = connexion Discord désactivée. */
  discord?: DiscordOAuthConfig | null;
}

export interface AppDeps {
  pool: Pool;
  redis: RedisBundle;
  config: AppConfig;
  logger?: Logger;
}

export async function buildApp(deps: AppDeps): Promise<FastifyInstance> {
  const { pool, redis, config } = deps;
  const logger = deps.logger ?? createLogger(config.logLevel, { service: 'zshield-api' });

  const app = Fastify({
    // Le logger de Fastify est désactivé : la journalisation passe par le nôtre,
    // qui rédige les secrets par nom de clé. Avec logger: false, il n'y a pas
    // de journalisation de requête à désactiver séparément.
    logger: false,
    trustProxy: true,
    bodyLimit: 262_144,
  });

  await app.register(cookie, { secret: config.sessionSecret });
  await app.register(websocket, { options: { maxPayload: 4096 } });

  // En-têtes de sécurité sur toutes les réponses.
  app.addHook('onSend', async (_request, reply, payload) => {
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    if (config.isProduction) {
      reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    return payload;
  });

  // CORS : allowlist explicite. Jamais `*` avec credentials — le navigateur le
  // refuserait, et un `*` reflété depuis l'en-tête Origin revient à tout ouvrir.
  app.addHook('onRequest', async (request, reply) => {
    const origin = request.headers.origin;
    if (typeof origin === 'string' && config.corsOrigins.includes(origin)) {
      reply.header('Access-Control-Allow-Origin', origin);
      reply.header('Access-Control-Allow-Credentials', 'true');
      reply.header('Vary', 'Origin');
      reply.header('Access-Control-Allow-Headers', 'content-type,x-csrf-token');
      reply.header('Access-Control-Allow-Methods', 'GET,POST,PATCH,PUT,DELETE,OPTIONS');
    }
    if (request.method === 'OPTIONS') {
      reply.status(204).send();
    }
  });

  const credentials = new CredentialStore(pool, config.credentialKey);
  const auth = new AuthService(pool);
  const guard = new Guard(auth, config.isProduction);

  // --- surface agent : portée isolée, corps brut, réponses signées ----------
  await app.register(async (instance) => {
    await agentGatewayRoutes(instance, {
      authenticator: new AgentAuthenticator({
        credentials,
        replay: new ReplayGuard({ redis: redis.commands, ttlSeconds: config.nonceTtlSeconds }),
        rateLimiter: new AgentRateLimiter(redis.commands, config.agentRateLimitPerMinute),
        clockSkewSeconds: config.clockSkewSeconds,
      }),
      service: new AgentGatewayService(pool, redis.publisher, credentials),
      credentials,
      logger: logger.child({ surface: 'agent' }),
    });
  });

  // --- surface utilisateur --------------------------------------------------
  await app.register(async (instance) => {
    await apiRoutes(instance, {
      pool,
      publisher: redis.publisher,
      auth,
      credentials,
      guard,
      logger: logger.child({ surface: 'api' }),
      isProduction: config.isProduction,
      webOrigin: config.webOrigin ?? null,
      discord: config.discord ?? null,
    });
  });

  await registerRealtime(app, { subscriber: redis.subscriber, auth, logger });

  // Liveness : aucune dépendance. Un health check qui interroge la base fait
  // tuer le conteneur quand c'est la base qui est lente.
  app.get('/healthz', async () => ({ status: 'ok' }));

  app.get('/readyz', async (_request, reply) => {
    const [database, cache] = await Promise.all([
      dbReachable(pool),
      redisReachable(redis.commands),
    ]);
    const ready = database && cache;
    reply.status(ready ? 200 : 503);
    return { ready, database, cache };
  });

  return app;
}
