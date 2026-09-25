/**
 * Clients Redis.
 *
 * Trois connexions distinctes, et ce n'est pas du gaspillage : une connexion
 * passée en mode abonnement n'accepte plus de commandes ordinaires. Partager
 * une seule connexion entre le cache de nonces et le pub/sub casse le cache
 * dès le premier abonnement.
 */
import { Redis } from 'ioredis';

export interface RedisBundle {
  /** Commandes : nonces, limitation de débit, verrous. */
  commands: Redis;
  /** Publication d'événements temps réel. */
  publisher: Redis;
  /** Abonnement (ne peut pas servir à autre chose). */
  subscriber: Redis;
  close(): Promise<void>;
}

function connect(url: string, role: string): Redis {
  const client = new Redis(url, {
    // Ne pas empiler indéfiniment les commandes pendant une coupure : les
    // appelants ont chacun leur stratégie de repli (voir replay.ts).
    enableOfflineQueue: false,
    maxRetriesPerRequest: 2,
    connectTimeout: 3_000,
    retryStrategy: (attempt: number) => Math.min(attempt * 200, 5_000),
  });

  client.on('error', (error: Error) => {
    process.stderr.write(
      `${JSON.stringify({
        time: new Date().toISOString(),
        level: 'warn',
        message: 'erreur de connexion Redis',
        role,
        detail: error.message,
      })}\n`,
    );
  });

  return client;
}

export function createRedis(url: string): RedisBundle {
  const commands = connect(url, 'commands');
  const publisher = connect(url, 'publisher');
  const subscriber = connect(url, 'subscriber');

  return {
    commands,
    publisher,
    subscriber,
    async close() {
      await Promise.allSettled([commands.quit(), publisher.quit(), subscriber.quit()]);
    },
  };
}

export async function isReachable(client: Redis): Promise<boolean> {
  try {
    const reply = await client.ping();
    return reply === 'PONG';
  } catch {
    return false;
  }
}

/** Canal par organisation. Le filtrage se fait à l'abonnement, pas à l'émission. */
export function organizationChannel(organizationId: string): string {
  return `org:${organizationId}`;
}
