/**
 * Protection anti-rejeu et limitation de débit des agents.
 *
 * ARBITRAGE EXPLICITE, à connaître avant de lire le code :
 *
 *   - le cache de nonces échoue **fermé** : si Redis est indisponible, on ne
 *     peut pas garantir qu'une requête n'est pas un rejeu, donc on refuse. Une
 *     panne de Redis coupe l'ingestion — c'est voulu, l'alternative serait
 *     d'accepter des rejeux pendant la panne ;
 *
 *   - la limitation de débit échoue **ouvert** : si Redis est indisponible, on
 *     laisse passer. Elle protège d'un agent bavard, pas d'un attaquant
 *     authentifié ; transformer une panne de cache en panne totale pour cette
 *     raison serait disproportionné.
 *
 * Ces deux choix vont dans des directions opposées, volontairement. Les rendre
 * identiques « par cohérence » dégraderait l'un des deux.
 */
import type { Redis } from 'ioredis';

export class ReplayCheckUnavailable extends Error {
  constructor(cause: unknown) {
    super("le cache anti-rejeu est indisponible : la requête ne peut pas être authentifiée");
    this.name = 'ReplayCheckUnavailable';
    this.cause = cause;
  }
}

export interface ReplayGuardOptions {
  redis: Redis;
  /** Doit valoir au moins deux fois la tolérance d'écart d'horloge. */
  ttlSeconds: number;
}

export class ReplayGuard {
  private readonly redis: Redis;
  private readonly ttlSeconds: number;

  constructor(options: ReplayGuardOptions) {
    this.redis = options.redis;
    this.ttlSeconds = options.ttlSeconds;
  }

  /**
   * Enregistre le nonce et indique s'il est neuf.
   *
   * Le nonce est isolé par agent : deux agents distincts peuvent tirer le même
   * nonce sans se bloquer mutuellement. La clé inclut aussi le key_id, pour
   * qu'une rotation ne puisse pas servir à rejouer une requête signée avec
   * l'ancienne clé.
   */
  async claim(agentId: string, keyId: string, nonce: string): Promise<boolean> {
    const key = `agent:nonce:${agentId}:${keyId}:${nonce}`;
    try {
      // SET NX EX est atomique : pas de fenêtre entre le test et l'écriture,
      // contrairement à un EXISTS suivi d'un SET.
      const result = await this.redis.set(key, '1', 'EX', this.ttlSeconds, 'NX');
      return result === 'OK';
    } catch (cause) {
      throw new ReplayCheckUnavailable(cause);
    }
  }
}

export interface RateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export class AgentRateLimiter {
  private readonly redis: Redis;
  private readonly perMinute: number;

  constructor(redis: Redis, perMinute: number) {
    this.redis = redis;
    this.perMinute = perMinute;
  }

  /** Fenêtre fixe d'une minute. Suffisant pour un agent qui bat à 15-900 s. */
  async consume(agentId: string): Promise<RateLimitDecision> {
    const window = Math.floor(Date.now() / 60_000);
    const key = `agent:rate:${agentId}:${window}`;

    try {
      const pipeline = this.redis.multi();
      pipeline.incr(key);
      pipeline.expire(key, 120);
      const results = await pipeline.exec();

      const count = Number(results?.[0]?.[1] ?? 0);
      const remaining = Math.max(0, this.perMinute - count);

      return {
        allowed: count <= this.perMinute,
        remaining,
        retryAfterSeconds: 60 - Math.floor((Date.now() % 60_000) / 1000),
      };
    } catch {
      // Échec ouvert, voir l'en-tête de fichier.
      return { allowed: true, remaining: this.perMinute, retryAfterSeconds: 0 };
    }
  }
}
