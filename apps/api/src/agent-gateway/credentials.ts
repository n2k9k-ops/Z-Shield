/**
 * Recherche et rotation des credentials d'agent.
 *
 * Point délicat : pendant une rotation, DEUX clés doivent être acceptées, de la
 * demande de rotation jusqu'au handshake de vérification signé avec la nouvelle
 * clé. L'agent ne bascule qu'après ce handshake réussi. Fermer la fenêtre plus
 * tôt enferme l'agent dehors, et il n'existe aucun moyen de le récupérer à
 * distance : il faut qu'un humain se connecte au serveur FiveM.
 *
 * Voir docs/PROTOCOL.md §7, endpoint /v1/agents/credentials/rotate.
 */
import type { Pool } from 'pg';
import { decryptSecret, encryptSecret, newAgentSecret, newId } from '../lib/crypto.ts';
import { withAgentLookup, withTenant } from '../lib/db.ts';

export interface ResolvedCredential {
  keyId: string;
  organizationId: string;
  serverId: string;
  agentId: string;
  secret: string;
  status: 'ACTIVE' | 'PENDING_ROTATION' | 'SUPERSEDED' | 'REVOKED';
}

export class CredentialStore {
  private readonly pool: Pool;
  private readonly key: Buffer;

  constructor(pool: Pool, key: Buffer) {
    this.pool = pool;
    this.key = key;
  }

  /**
   * Résout une credential par agent_id + key_id.
   *
   * Requête volontairement hors RLS : à ce stade on ne connaît pas encore
   * l'organisation, c'est justement ce qu'on cherche. C'est le seul accès du
   * code applicatif qui ne soit pas filtré par tenant, et il est limité à cette
   * méthode, sur une clé primaire, sans donnée métier retournée.
   */
  async resolve(agentId: string, keyId: string): Promise<ResolvedCredential | null> {
    const { rows } = await withAgentLookup(this.pool, (client) => client.query<{
      key_id: string;
      organization_id: string;
      server_id: string;
      agent_id: string;
      secret_encrypted: Buffer;
      status: ResolvedCredential['status'];
      expires_at: Date | null;
    }>(
      `SELECT key_id, organization_id, server_id, agent_id, secret_encrypted, status, expires_at
         FROM api_credentials
        WHERE agent_id = $1
          AND key_id = $2
          AND status IN ('ACTIVE', 'PENDING_ROTATION')
        LIMIT 1`,
      [agentId, keyId],
    ));

    const row = rows[0];
    if (!row) return null;

    // Une clé expirée est traitée comme absente, pas comme invalide : l'agent
    // reçoit le même 401 dans les deux cas et n'apprend rien sur l'existence
    // de la clé.
    if (row.expires_at && row.expires_at.getTime() <= Date.now()) return null;

    let secret: string;
    try {
      secret = decryptSecret(row.secret_encrypted, this.key);
    } catch {
      // Tag GCM invalide ou mauvaise clé applicative. Ne jamais traiter cela
      // comme « credential inconnue » : c'est un incident d'exploitation.
      throw new Error(
        `credential ${row.key_id} illisible : ZSHIELD_CREDENTIAL_KEY est incorrecte ou la ligne a été altérée`,
      );
    }

    return {
      keyId: row.key_id,
      organizationId: row.organization_id,
      serverId: row.server_id,
      agentId: row.agent_id,
      secret,
      status: row.status,
    };
  }

  /**
   * Trace de dernière utilisation. Sert à repérer une clé jamais employée.
   *
   * Cadrée sur l'organisation : l'écriture sur api_credentials passe par la
   * politique de tenant, pas par la politique de lecture d'authentification.
   */
  async touch(organizationId: string, keyId: string): Promise<void> {
    await withTenant(this.pool, organizationId, async (client) => {
      await client.query(
        `UPDATE api_credentials SET last_seen_at = now()
          WHERE organization_id = $1 AND key_id = $2`,
        [organizationId, keyId],
      );
    });
  }

  /**
   * Émet une credential. Le secret en clair n'est retourné qu'ici, une seule
   * fois : il n'est stocké que chiffré et aucun endpoint ne le relit.
   */
  async issue(input: {
    organizationId: string;
    serverId: string;
    agentId: string;
    createdBy?: string | null;
    supersedesKeyId?: string | null;
    status?: 'ACTIVE' | 'PENDING_ROTATION';
  }): Promise<{ keyId: string; secret: string }> {
    const keyId = newId('key');
    const secret = newAgentSecret();

    await withTenant(this.pool, input.organizationId, async (client) => {
      await client.query(
        `INSERT INTO api_credentials
           (key_id, organization_id, server_id, agent_id, secret_encrypted,
            secret_hint, status, supersedes_key_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          keyId,
          input.organizationId,
          input.serverId,
          input.agentId,
          encryptSecret(secret, this.key),
          secret.slice(-4),
          input.status ?? 'ACTIVE',
          input.supersedesKeyId ?? null,
          input.createdBy ?? null,
        ],
      );
    });

    return { keyId, secret };
  }

  /**
   * Étape 1 de la rotation : émet la nouvelle clé en PENDING_ROTATION et laisse
   * l'ancienne ACTIVE. Les deux signent valablement à partir d'ici.
   */
  async beginRotation(current: ResolvedCredential): Promise<{ keyId: string; secret: string }> {
    return this.issue({
      organizationId: current.organizationId,
      serverId: current.serverId,
      agentId: current.agentId,
      supersedesKeyId: current.keyId,
      status: 'PENDING_ROTATION',
    });
  }

  /**
   * Étape 4 : l'agent a réussi un handshake signé avec la nouvelle clé. On
   * promeut la nouvelle et on retire l'ancienne, dans une transaction — un état
   * intermédiaire avec deux clés ACTIVE violerait l'index unique partiel.
   */
  async commitRotation(organizationId: string, newKeyId: string): Promise<void> {
    await withTenant(this.pool, organizationId, async (client) => {
      const { rows } = await client.query<{ supersedes_key_id: string | null }>(
        `SELECT supersedes_key_id FROM api_credentials
          WHERE organization_id = $1 AND key_id = $2 AND status = 'PENDING_ROTATION'
          FOR UPDATE`,
        [organizationId, newKeyId],
      );
      const pending = rows[0];
      if (!pending) return;

      // L'ancienne clé est retirée AVANT que la nouvelle devienne ACTIVE :
      // l'index unique partiel n'autorise qu'une seule ACTIVE par serveur, et
      // l'ordre inverse violerait la contrainte au milieu de la transaction.
      if (pending.supersedes_key_id) {
        await client.query(
          `UPDATE api_credentials
              SET status = 'SUPERSEDED', revoked_at = now()
            WHERE organization_id = $1 AND key_id = $2`,
          [organizationId, pending.supersedes_key_id],
        );
      }

      await client.query(
        `UPDATE api_credentials SET status = 'ACTIVE'
          WHERE organization_id = $1 AND key_id = $2`,
        [organizationId, newKeyId],
      );
    });
  }

  /**
   * Révocation explicite par un administrateur. Irréversible côté plateforme :
   * l'opérateur devra installer une nouvelle credential sur le serveur.
   */
  async revoke(
    organizationId: string,
    keyId: string,
    revokedBy: string | null,
    reason: string,
  ): Promise<void> {
    await withTenant(this.pool, organizationId, async (client) => {
      await client.query(
        `UPDATE api_credentials
            SET status = 'REVOKED', revoked_at = now(), revoked_by = $3, revoke_reason = $4
          WHERE organization_id = $1 AND key_id = $2 AND status <> 'REVOKED'`,
        [organizationId, keyId, revokedBy, reason.slice(0, 400)],
      );
    });
  }
}
