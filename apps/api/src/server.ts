/**
 * Point d'entrée du processus. Toute la construction est dans app.ts.
 */
import { env } from './config/env.ts';
import { createLogger } from './lib/logger.ts';
import { createPool } from './lib/db.ts';
import { createRedis } from './lib/redis.ts';
import { buildApp } from './app.ts';

const config = env();
const logger = createLogger(config.LOG_LEVEL, { service: 'zshield-api' });

const pool = createPool({ connectionString: config.DATABASE_URL, max: config.DATABASE_POOL_MAX });
const redis = createRedis(config.REDIS_URL);

const app = await buildApp({
  pool,
  redis,
  logger,
  config: {
    credentialKey: config.credentialKey,
    sessionSecret: config.SESSION_SECRET,
    clockSkewSeconds: config.AGENT_CLOCK_SKEW_SECONDS,
    nonceTtlSeconds: config.AGENT_NONCE_TTL_SECONDS,
    agentRateLimitPerMinute: config.AGENT_RATE_LIMIT_PER_MINUTE,
    corsOrigins: config.corsOrigins,
    isProduction: config.isProduction,
    logLevel: config.LOG_LEVEL,
    webOrigin: config.WEB_ORIGIN ?? null,
    // Discord n'est branché que si explicitement activé avec ses trois secrets.
    // La validation d'environnement garantit déjà leur présence dans ce cas.
    discord:
      config.DISCORD_LOGIN_ENABLED &&
      config.DISCORD_CLIENT_ID &&
      config.DISCORD_CLIENT_SECRET &&
      config.DISCORD_REDIRECT_URI
        ? {
            clientId: config.DISCORD_CLIENT_ID,
            clientSecret: config.DISCORD_CLIENT_SECRET,
            redirectUri: config.DISCORD_REDIRECT_URI,
          }
        : null,
  },
});

async function shutdown(signal: string): Promise<void> {
  logger.info('arrêt demandé', { signal });
  try {
    await app.close();
    await pool.end();
    await redis.close();
    process.exit(0);
  } catch (error) {
    logger.error("échec de l'arrêt propre", {
      detail: error instanceof Error ? error.message : String(error),
    });
    process.exit(1);
  }
}

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

await app.listen({ port: config.PORT, host: '0.0.0.0' });
logger.info('API démarrée', { port: config.PORT, env: config.NODE_ENV });
