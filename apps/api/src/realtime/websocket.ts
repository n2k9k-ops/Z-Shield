/**
 * Temps réel.
 *
 * Décision structurante : **le filtrage se fait à l'abonnement, pas à
 * l'émission.** Une socket est abonnée au canal de l'organisation présente dans
 * sa session au moment de la connexion, et à rien d'autre. L'alternative —
 * diffuser à tout le monde puis filtrer par un `if` avant d'écrire — marche
 * jusqu'au jour où une condition est inversée, et ce jour-là un client reçoit
 * les alertes d'un autre.
 *
 * Authentification par le cookie de session. Pas de jeton en query string :
 * cela finit dans les logs d'accès des proxys, et un log d'accès n'est pas un
 * endroit pour un jeton de session.
 */
import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import type { WebSocket } from 'ws';
import { organizationChannel } from '../lib/redis.ts';
import type { AuthService } from '../auth/sessions.ts';
import { SESSION_COOKIE } from '../api/middleware.ts';
import type { Logger } from '../lib/logger.ts';

export interface RealtimeDeps {
  subscriber: Redis;
  auth: AuthService;
  logger: Logger;
}

interface Client {
  socket: WebSocket;
  organizationId: string;
  userId: string;
}

export class RealtimeHub {
  private readonly clients = new Set<Client>();
  private readonly subscribed = new Set<string>();

  private readonly deps: RealtimeDeps;

  constructor(deps: RealtimeDeps) {
    this.deps = deps;
    this.deps.subscriber.on('message', (channel: string, message: string) => {
      this.fanOut(channel, message);
    });
  }

  private fanOut(channel: string, message: string): void {
    for (const client of this.clients) {
      if (organizationChannel(client.organizationId) !== channel) continue;
      // OPEN vaut 1 dans la spécification WebSocket.
      if (client.socket.readyState !== 1) continue;
      try {
        client.socket.send(message);
      } catch {
        this.clients.delete(client);
      }
    }
  }

  private async ensureSubscribed(organizationId: string): Promise<void> {
    const channel = organizationChannel(organizationId);
    if (this.subscribed.has(channel)) return;
    await this.deps.subscriber.subscribe(channel);
    this.subscribed.add(channel);
  }

  async add(socket: WebSocket, organizationId: string, userId: string): Promise<void> {
    await this.ensureSubscribed(organizationId);
    const client: Client = { socket, organizationId, userId };
    this.clients.add(client);

    socket.on('close', () => {
      this.clients.delete(client);
    });
    socket.on('error', () => {
      this.clients.delete(client);
    });
  }

  get connectionCount(): number {
    return this.clients.size;
  }
}

export async function registerRealtime(app: FastifyInstance, deps: RealtimeDeps): Promise<void> {
  const hub = new RealtimeHub(deps);

  app.get('/ws', { websocket: true }, async (connection, request) => {
    const token = request.cookies[SESSION_COOKIE];
    if (typeof token !== 'string') {
      connection.close(4401, 'unauthorized');
      return;
    }

    const context = await deps.auth.resolveSession(token);
    if (!context || !context.session.mfaSatisfied || !context.session.organizationId) {
      connection.close(4401, 'unauthorized');
      return;
    }

    // L'adhésion est revérifiée ici : une socket ouverte avant un retrait
    // d'adhésion ne doit pas continuer à recevoir les événements. Pour les
    // sockets déjà ouvertes, la révocation de session s'en charge côté API.
    const role = await deps.auth.resolveRole(
      context.session.userId,
      context.session.organizationId,
    );
    if (!role) {
      connection.close(4403, 'forbidden');
      return;
    }

    await hub.add(connection, context.session.organizationId, context.session.userId);

    connection.send(
      JSON.stringify({
        type: 'connection.ready',
        payload: { organization_id: context.session.organizationId, role },
      }),
    );

    // Le client ne pilote rien : les seuls messages acceptés sont des pings.
    // Un canal temps réel qui accepte des commandes est une seconde API sans
    // les contrôles de la première.
    connection.on('message', (raw: Buffer) => {
      if (raw.length > 256) return;
      try {
        const parsed = JSON.parse(raw.toString('utf8')) as { type?: string };
        if (parsed.type === 'ping') {
          connection.send(JSON.stringify({ type: 'pong', payload: { at: Date.now() } }));
        }
      } catch {
        // Message illisible : ignoré, pas de réponse d'erreur exploitable.
      }
    });
  });

  app.get('/internal/realtime-stats', async () => ({ connections: hub.connectionCount }));
}
