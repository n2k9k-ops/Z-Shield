/**
 * Logique métier de l'ingestion agent.
 *
 * Toutes les écritures passent par `withTenant`, donc sous RLS cadrée sur
 * l'organisation de la credential — jamais sur une organisation fournie par la
 * requête. Un agent authentifié ne peut écrire que chez lui, même s'il mentait
 * dans son enveloppe.
 *
 * Les événements temps réel sont publiés APRÈS le COMMIT. Publier dans la
 * transaction afficherait dans l'interface une alerte que le `GET` suivant ne
 * trouverait pas, et qui disparaîtrait au rechargement.
 */
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { withTenant } from '../lib/db.ts';
import { organizationChannel } from '../lib/redis.ts';
import { newId } from '../lib/crypto.ts';
import { MIN_AGENT_PROTOCOL, PROTOCOL_VERSION } from './protocol.ts';
import type { AgentAuthContext } from './authenticate.ts';
import type { CredentialStore } from './credentials.ts';
import { remoteConfigSchema, type RemoteConfig } from './schemas.ts';
import { PROTECTION_CATALOG } from '../protections/catalog.ts';
import type { z } from 'zod';
import type {
  alertsPayloadSchema,
  commandResultsPayloadSchema,
  handshakePayloadSchema,
  heartbeatPayloadSchema,
  telemetryPayloadSchema,
} from './schemas.ts';

type HandshakePayload = z.infer<typeof handshakePayloadSchema>;
type HeartbeatPayload = z.infer<typeof heartbeatPayloadSchema>;
type TelemetryPayload = z.infer<typeof telemetryPayloadSchema>;
type AlertsPayload = z.infer<typeof alertsPayloadSchema>;
type CommandResultsPayload = z.infer<typeof commandResultsPayloadSchema>;

export interface GatewayEvent {
  type: string;
  payload: Record<string, unknown>;
}

export class AgentGatewayService {
  private readonly pool: Pool;
  private readonly publisher: Redis;
  private readonly credentials: CredentialStore;

  constructor(pool: Pool, publisher: Redis, credentials: CredentialStore) {
    this.pool = pool;
    this.publisher = publisher;
    this.credentials = credentials;
  }

  /** Publication best-effort : un échec de Redis ne doit pas annuler une écriture. */
  private async publish(organizationId: string, event: GatewayEvent): Promise<void> {
    try {
      await this.publisher.publish(
        organizationChannel(organizationId),
        JSON.stringify({ ...event, at: new Date().toISOString() }),
      );
    } catch {
      // L'interface se rattrapera à son prochain polling de secours.
    }
  }

  // -------------------------------------------------------------------------
  // handshake
  // -------------------------------------------------------------------------
  async handshake(ctx: AgentAuthContext, payload: HandshakePayload) {
    const { organizationId, serverId, agentId, keyId, status } = ctx.credential;

    const result = await withTenant(this.pool, organizationId, async (client) => {
      await client.query(
        `INSERT INTO agents (id, organization_id, server_id, handshake_at, handshake_count,
                             capabilities, last_request_at)
              VALUES ($1, $2, $3, now(), 1, $4, now())
         ON CONFLICT (organization_id, id) DO UPDATE
                SET handshake_at = now(),
                    handshake_count = agents.handshake_count + 1,
                    capabilities = EXCLUDED.capabilities,
                    last_request_at = now()`,
        [agentId, organizationId, serverId, payload.capabilities ?? []],
      );

      const { rows } = await client.query<{
        name: string;
        config_version: number;
        remote_config: RemoteConfig;
        connected_at: Date | null;
        organization_name: string;
      }>(
        `UPDATE servers
             SET connected_at = COALESCE(connected_at, now()),
                 state = 'ONLINE',
                 agent_version = $3,
                 protocol_version = $4,
                 fxserver_version = COALESCE($5, fxserver_version),
                 onesync = COALESCE($6, onesync),
                 max_players = COALESCE($7, max_players),
                 uptime_seconds = COALESCE($8, uptime_seconds),
                 last_heartbeat_at = now(),
                 updated_at = now()
           WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
       RETURNING name, config_version, remote_config, connected_at,
                 (SELECT o.name FROM organizations o WHERE o.id = $1) AS organization_name`,
        [
          organizationId,
          serverId,
          ctx.agentVersion,
          ctx.protocolVersion,
          payload.server?.fxserver_version ?? null,
          payload.server?.onesync ?? null,
          payload.server?.max_players ?? null,
          payload.server?.uptime_seconds ?? null,
        ],
      );

      const server = rows[0];
      if (!server) return null;

      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_kind, actor_label, action,
                                 target_kind, target_id, metadata)
              VALUES ($1, 'agent', $2, 'agent.handshake', 'server', $3, $4)`,
        [
          organizationId,
          agentId,
          serverId,
          JSON.stringify({ agent_version: ctx.agentVersion, key_id: keyId }),
        ],
      );

      return server;
    });

    if (!result) return null;

    // Un handshake signé avec la clé en attente prouve que l'agent détient le
    // nouveau matériel : c'est l'étape 4 de la rotation, on peut commiter.
    if (status === 'PENDING_ROTATION') {
      await this.credentials.commitRotation(organizationId, keyId);
    }

    await this.publish(organizationId, {
      type: 'agent.connected',
      payload: { server_id: serverId, agent_id: agentId, agent_version: ctx.agentVersion },
    });

    return {
      api_version: PROTOCOL_VERSION,
      min_agent_protocol: MIN_AGENT_PROTOCOL,
      organization: result.organization_name,
      server_name: result.name,
      key_id: keyId,
      config: { config_version: result.config_version, ...(result.remote_config ?? {}) },
    };
  }

  // -------------------------------------------------------------------------
  // heartbeat
  // -------------------------------------------------------------------------
  async heartbeat(ctx: AgentAuthContext, payload: HeartbeatPayload) {
    const { organizationId, serverId } = ctx.credential;

    return withTenant(this.pool, organizationId, async (client) => {
      // L'état affiché est déduit de la santé rapportée, pas recopié : un agent
      // qui se dit ONLINE avec health FAILED est DEGRADED pour l'exploitant.
      const state =
        payload.health === 'FAILED'
          ? 'DEGRADED'
          : payload.state === 'ONLINE'
            ? payload.health === 'DEGRADED'
              ? 'DEGRADED'
              : 'ONLINE'
            : payload.state === 'DEGRADED'
              ? 'DEGRADED'
              : payload.state === 'STOPPING' || payload.state === 'OFFLINE'
                ? 'OFFLINE'
                : 'UNKNOWN';

      const { rows } = await client.query<{ previous_state: string; config_version: number }>(
        `UPDATE servers
             SET state = $3,
                 health = $4,
                 last_heartbeat_at = now(),
                 agent_version = $5,
                 protocol_version = $6,
                 uptime_seconds = $7,
                 players_online = COALESCE($8, players_online),
                 queue_size = $9,
                 last_error = COALESCE($10, last_error),
                 last_error_at = CASE WHEN $10 IS NULL THEN last_error_at ELSE now() END,
                 updated_at = now()
           WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
       RETURNING (SELECT s.state FROM servers s
                   WHERE s.organization_id = $1 AND s.id = $2) AS previous_state,
                 config_version`,
        [
          organizationId,
          serverId,
          state,
          payload.health,
          payload.agent_version,
          payload.protocol_version,
          payload.uptime_seconds,
          payload.players_online ?? null,
          payload.queue_size,
          payload.last_error ?? null,
        ],
      );

      const server = rows[0];
      if (!server) return null;

      // Empreinte du serveur : enregistrée quand elle change. Sert à lier
      // automatiquement les futures licences à ce serveur (anti-partage).
      if (payload.server_fingerprint) {
        await client.query(
          `UPDATE servers SET server_fingerprint = $3
            WHERE organization_id = $1 AND id = $2
              AND server_fingerprint IS DISTINCT FROM $3`,
          [organizationId, serverId, payload.server_fingerprint],
        );
      }

      await client.query(
        `UPDATE agents SET last_request_at = now()
          WHERE organization_id = $1 AND id = $2`,
        [organizationId, ctx.agentId],
      );

      const { rows: pending } = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count
           FROM agent_commands
          WHERE organization_id = $1 AND server_id = $2
            AND status IN ('PENDING', 'SENT')
            AND expires_at > now()`,
        [organizationId, serverId],
      );

      void this.publish(organizationId, {
        type: 'server.health_changed',
        payload: {
          server_id: serverId,
          state,
          health: payload.health,
          players_online: payload.players_online ?? null,
          queue_size: payload.queue_size,
        },
      });

      return {
        commands_pending: Number(pending[0]?.count ?? '0'),
        config_version: server.config_version,
      };
    });
  }

  // -------------------------------------------------------------------------
  // telemetry
  // -------------------------------------------------------------------------
  async telemetry(ctx: AgentAuthContext, payload: TelemetryPayload) {
    const { organizationId, serverId } = ctx.credential;

    return withTenant(this.pool, organizationId, async (client) => {
      let accepted = 0;
      for (const sample of payload.samples) {
        const { rowCount } = await client.query(
          `INSERT INTO telemetry_samples
             (organization_id, server_id, sampled_at, players_online, uptime_seconds,
              memory_mb, tick_ms, resource_count, error_count, queue_size, dependencies)
           VALUES ($1, $2, to_timestamp($3), $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT DO NOTHING`,
          [
            organizationId,
            serverId,
            sample.sampled_at,
            sample.players_online ?? null,
            sample.uptime_seconds ?? null,
            sample.memory_mb ?? null,
            sample.tick_ms ?? null,
            sample.resource_count ?? null,
            sample.error_count ?? null,
            sample.queue_size ?? null,
            JSON.stringify(sample.dependencies ?? {}),
          ],
        );
        accepted += rowCount ?? 0;

        // Instantané des protections natives : on ne garde que le plus récent
        // par serveur (upsert). Optionnel — absent si le cœur anticheat n'est
        // pas installé ou si la métrique est désactivée.
        if (sample.protections) {
          await client.query(
            `INSERT INTO server_protections (organization_id, server_id, updated_at, snapshot)
               VALUES ($1, $2, to_timestamp($3), $4)
             ON CONFLICT (organization_id, server_id)
               DO UPDATE SET snapshot = EXCLUDED.snapshot, updated_at = EXCLUDED.updated_at`,
            [organizationId, serverId, sample.sampled_at, JSON.stringify(sample.protections)],
          );
        }
      }
      return { accepted };
    });
  }

  // -------------------------------------------------------------------------
  // alerts
  // -------------------------------------------------------------------------
  async alerts(ctx: AgentAuthContext, payload: AlertsPayload) {
    const { organizationId, serverId } = ctx.credential;

    const outcome = await withTenant(this.pool, organizationId, async (client) => {
      const rejected: Array<{ id: string; reason: string }> = [];
      const created: Array<{ id: string; severity: string; category: string }> = [];
      const sanctions: Array<{ id: string; status: string; identifier: string }> = [];
      let accepted = 0;

      for (const alert of payload.alerts) {
        // `ON CONFLICT DO NOTHING` sur la clé d'idempotence : une alerte
        // resoumise après un flush interrompu ne crée pas de doublon, et
        // l'agent reçoit tout de même un accusé.
        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO alerts
             (id, organization_id, server_id, agent_alert_id, severity, category,
              summary, metadata, reference, origin, occurrences, occurred_at,
              last_occurrence_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                   to_timestamp($12), CASE WHEN $13::bigint IS NULL
                                           THEN NULL ELSE to_timestamp($13) END)
           ON CONFLICT DO NOTHING
           RETURNING id`,
          [
            newId('al'),
            organizationId,
            serverId,
            alert.id,
            alert.severity,
            alert.category,
            alert.summary,
            JSON.stringify(alert.metadata ?? {}),
            alert.reference ?? null,
            alert.origin ?? null,
            alert.occurrences ?? 1,
            alert.occurred_at,
            alert.last_occurrence_at ?? null,
          ],
        );

        accepted += 1;
        const inserted = rows[0];
        if (inserted) {
          created.push({ id: inserted.id, severity: alert.severity, category: alert.category });
        }

        // --- Proposition de sanction attachée à l'alerte -------------------
        // CRITICAL -> ban ACTIVE immédiat (le cœur a une certitude) ; sinon
        // sanction PENDING mise en file de revue. issued_by_auto = true,
        // issued_by = NULL : c'est l'anticheat, pas un administrateur.
        if (alert.sanction) {
          const s = alert.sanction;
          const banId = newId('ban');
          if (alert.severity === 'CRITICAL') {
            const banRows = await client.query<{ id: string }>(
              `INSERT INTO bans (id, organization_id, server_id, scope, identifier,
                                 player_name, reason, issued_by, issued_by_auto, status,
                                 risk, detection_category, detector, evidence_kind)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,true,'ACTIVE',$8,$9,$10,$11)
               ON CONFLICT (organization_id, scope, identifier, COALESCE(server_id, ''))
                           WHERE status = 'ACTIVE'
               DO NOTHING
               RETURNING id`,
              [
                banId, organizationId, serverId, s.scope, s.identifier,
                s.player_name ?? null, alert.summary.slice(0, 400),
                s.risk ?? null, alert.category, s.detector, s.evidence_kind ?? null,
              ],
            );
            if (banRows.rows[0]) {
              sanctions.push({ id: banRows.rows[0].id, status: 'ACTIVE', identifier: s.identifier });
            }
          } else {
            // Pas de doublon de sanction en attente pour le même (identifiant,
            // détecteur) tant qu'une décision n'a pas été prise.
            const banRows = await client.query<{ id: string }>(
              `INSERT INTO bans (id, organization_id, server_id, scope, identifier,
                                 player_name, reason, issued_by, issued_by_auto, status,
                                 risk, detection_category, detector, evidence_kind)
                   SELECT $1,$2,$3,$4,$5,$6,$7,NULL,true,'PENDING',$8,$9,$10,$11
                    WHERE NOT EXISTS (
                            SELECT 1 FROM bans
                             WHERE organization_id = $2 AND scope = $4 AND identifier = $5
                               AND detector = $10 AND status = 'PENDING')
               RETURNING id`,
              [
                banId, organizationId, serverId, s.scope, s.identifier,
                s.player_name ?? null, alert.summary.slice(0, 400),
                s.risk ?? null, alert.category, s.detector, s.evidence_kind ?? null,
              ],
            );
            if (banRows.rows[0]) {
              sanctions.push({ id: banRows.rows[0].id, status: 'PENDING', identifier: s.identifier });
            }
          }
        }
      }

      return { accepted, rejected, created, sanctions };
    });

    for (const alert of outcome.created) {
      await this.publish(organizationId, {
        type: 'alert.created',
        payload: { ...alert, server_id: serverId },
      });
    }
    for (const sanction of outcome.sanctions) {
      await this.publish(organizationId, {
        type: sanction.status === 'PENDING' ? 'sanction.pending' : 'ban.created',
        payload: { ...sanction, server_id: serverId },
      });
    }

    return {
      accepted: outcome.accepted,
      ...(outcome.sanctions.length > 0 ? { sanctions: outcome.sanctions.length } : {}),
      ...(outcome.rejected.length > 0 ? { rejected: outcome.rejected } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // configuration
  // -------------------------------------------------------------------------
  async config(ctx: AgentAuthContext) {
    const { organizationId, serverId } = ctx.credential;

    return withTenant(this.pool, organizationId, async (client) => {
      const { rows } = await client.query<{ config_version: number; remote_config: unknown }>(
        `SELECT config_version, remote_config
           FROM servers
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [organizationId, serverId],
      );

      const server = rows[0];
      if (!server) return null;

      // Deuxième validation, à la sortie. La première a lieu à l'écriture par
      // un administrateur. Celle-ci protège du cas où une ligne aurait été
      // modifiée hors application : envoyer un champ inconnu ferait rejeter
      // TOUT le document par l'agent, qui garderait sa configuration locale
      // sans que personne ne comprenne pourquoi.
      const parsed = remoteConfigSchema.safeParse(server.remote_config ?? {});
      if (!parsed.success) {
        return {
          invalid: true as const,
          issues: parsed.error.issues.map((issue) => issue.path.join('.')),
        };
      }

      // Licence du serveur : livrée automatiquement à l'agent (qui la transmet au
      // cœur). Le client n'a rien à coller. Injectée APRÈS validation stricte du
      // remote_config — ce n'est pas un réglage tunable, c'est une donnée délivrée.
      const licRes = await client.query<{ token: string }>(
        `SELECT token FROM licenses WHERE organization_id = $1 AND server_id = $2`,
        [organizationId, serverId],
      );
      const licenseToken = licRes.rows[0]?.token ?? null;

      // Réglages de protections choisis par le client. On envoie l'état EFFECTIF
      // complet (défauts du catalogue fusionnés avec les choix enregistrés), pour
      // que le cœur ait une image complète. Injecté hors du schéma strict, comme
      // la licence — ce n'est pas un réglage tunable côté agent, c'est une donnée.
      const setRes = await client.query<{ protection_id: string; enabled: boolean; mode: 'watch' | 'block' }>(
        `SELECT protection_id, enabled, mode FROM server_protection_settings
          WHERE organization_id = $1 AND server_id = $2`,
        [organizationId, serverId],
      );
      const saved = new Map(setRes.rows.map((r) => [r.protection_id, r]));
      const protections = PROTECTION_CATALOG.flatMap((cat) =>
        cat.items.map((it) => {
          const s = saved.get(it.id);
          return {
            id: it.id,
            enabled: s ? s.enabled : it.defaultEnabled,
            mode: s ? s.mode : it.defaultMode,
          };
        }),
      );

      return {
        invalid: false as const,
        config: {
          config_version: server.config_version,
          ...parsed.data,
          ...(licenseToken ? { license: licenseToken } : {}),
          protections,
        },
      };
    });
  }

  // -------------------------------------------------------------------------
  // commandes
  // -------------------------------------------------------------------------
  async claimCommands(ctx: AgentAuthContext, limit: number) {
    const { organizationId, serverId } = ctx.credential;

    return withTenant(this.pool, organizationId, async (client) => {
      // Les commandes expirées sont marquées avant la sélection : envoyer une
      // commande déjà périmée ferait juste travailler l'agent pour rien.
      await client.query(
        `UPDATE agent_commands
             SET status = 'EXPIRED'
           WHERE organization_id = $1 AND server_id = $2
             AND status IN ('PENDING', 'SENT') AND expires_at <= now()`,
        [organizationId, serverId],
      );

      const { rows } = await client.query<{
        id: string;
        type: string;
        payload: Record<string, unknown>;
        issued_at: string;
        expires_at: string;
      }>(
        `UPDATE agent_commands
             SET status = 'SENT',
                 sent_at = COALESCE(sent_at, now()),
                 delivery_count = delivery_count + 1
           WHERE (organization_id, id) IN (
                 SELECT organization_id, id FROM agent_commands
                  WHERE organization_id = $1 AND server_id = $2
                    AND status IN ('PENDING', 'SENT')
                    AND expires_at > now()
                  ORDER BY created_at
                  LIMIT $3
                  FOR UPDATE SKIP LOCKED)
       RETURNING id, type, payload,
                 extract(epoch FROM created_at)::bigint::text AS issued_at,
                 extract(epoch FROM expires_at)::bigint::text AS expires_at`,
        [organizationId, serverId, limit],
      );

      return {
        commands: rows.map((row) => ({
          id: row.id,
          type: row.type,
          issued_at: Number(row.issued_at),
          expires_at: Number(row.expires_at),
          payload: row.payload ?? {},
        })),
      };
    });
  }

  async commandResults(ctx: AgentAuthContext, payload: CommandResultsPayload) {
    const { organizationId, serverId } = ctx.credential;

    const acknowledged = await withTenant(this.pool, organizationId, async (client) => {
      const ids: string[] = [];

      for (const result of payload.results) {
        const status = result.status === 'FAILED' ? 'FAILED' : 'ACKNOWLEDGED';

        const { rowCount } = await client.query(
          `UPDATE agent_commands
               SET status = $4,
                   result = $5,
                   result_detail = $6,
                   reason = $7,
                   acknowledged_at = now(),
                   executed_at = to_timestamp($8),
                   duration_ms = $9
             WHERE organization_id = $1 AND server_id = $2 AND id = $3
               AND status IN ('PENDING', 'SENT')`,
          [
            organizationId,
            serverId,
            result.id,
            status,
            result.status,
            JSON.stringify(result.result ?? {}),
            result.reason ?? null,
            result.executed_at,
            result.duration_ms ?? null,
          ],
        );

        if ((rowCount ?? 0) > 0) ids.push(result.id);
      }

      return ids;
    });

    for (const id of acknowledged) {
      const reported = payload.results.find((candidate) => candidate.id === id);
      await this.publish(organizationId, {
        type: 'command.acknowledged',
        payload: { command_id: id, server_id: serverId, result: reported?.status },
      });
    }

    return { acknowledged };
  }

  // -------------------------------------------------------------------------
  // rotation
  // -------------------------------------------------------------------------
  async rotate(ctx: AgentAuthContext, reason: string | undefined) {
    // Étape 1 : la nouvelle clé est émise en attente. L'ancienne reste valable
    // jusqu'à ce que l'agent prouve, par un handshake signé avec la nouvelle,
    // qu'il l'a bien reçue et persistée.
    const issued = await this.credentials.beginRotation(ctx.credential);

    await withTenant(this.pool, ctx.credential.organizationId, async (client) => {
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_kind, actor_label, action,
                                 target_kind, target_id, metadata)
              VALUES ($1, 'agent', $2, 'credential.rotation_started', 'server', $3, $4)`,
        [
          ctx.credential.organizationId,
          ctx.agentId,
          ctx.credential.serverId,
          JSON.stringify({
            previous_key_id: ctx.credential.keyId,
            new_key_id: issued.keyId,
            reason: reason ?? null,
          }),
        ],
      );
    });

    // Le secret en clair ne quitte le système qu'ici, dans une réponse signée
    // avec l'ancienne clé, sur un canal TLS. Il n'est jamais journalisé.
    return { key_id: issued.keyId, secret: issued.secret };
  }
}
