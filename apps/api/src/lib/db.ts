/**
 * Accès PostgreSQL.
 *
 * Deux façons d'obtenir une connexion, et une seule est correcte pour des
 * données de tenant :
 *
 *   - `pool` : brut. Réservé aux requêtes qui n'ont pas encore d'organisation
 *     (résolution d'une credential, lecture d'un plan, health check) ;
 *   - `withTenant(orgId, fn)` : ouvre une transaction, pose
 *     `app.organization_id`, et laisse RLS filtrer. C'est la voie normale.
 *
 * `SET LOCAL` est indispensable : un `SET` simple resterait sur la connexion
 * après son retour au pool, et la requête suivante — celle d'un autre client —
 * hériterait de l'organisation précédente. C'est le bug qui transforme un pool
 * de connexions en fuite inter-tenant.
 */
import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from 'pg';

export interface DbOptions {
  connectionString: string;
  max: number;
}

export function createPool(options: DbOptions): Pool {
  const pool = new Pool({
    connectionString: options.connectionString,
    max: options.max,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    // Une requête qui dure plus longtemps est un incident, pas une attente.
    statement_timeout: 15_000,
    query_timeout: 15_000,
  });

  // Une erreur sur une connexion au repos ne doit pas terminer le processus.
  pool.on('error', (error) => {
    process.stderr.write(
      `${JSON.stringify({
        time: new Date().toISOString(),
        level: 'error',
        message: 'erreur sur une connexion Postgres inactive',
        detail: error.message,
      })}\n`,
    );
  });

  return pool;
}

const ORG_ID_PATTERN = /^org_[0-9a-z]{26}$/;

export interface TenantClient {
  query<R extends QueryResultRow = QueryResultRow>(
    sql: string,
    params?: unknown[],
  ): Promise<QueryResult<R>>;
}

/**
 * Exécute `fn` dans une transaction dont RLS est cadrée sur `organizationId`.
 *
 * Le format de l'identifiant est vérifié avant interpolation. `SET LOCAL`
 * n'accepte pas de paramètre lié, donc c'est le seul endroit du code où une
 * valeur est interpolée dans du SQL — et elle est contrainte par une expression
 * régulière stricte, pas par la confiance accordée à l'appelant.
 */
export async function withTenant<T>(
  pool: Pool,
  organizationId: string,
  fn: (client: TenantClient) => Promise<T>,
): Promise<T> {
  if (!ORG_ID_PATTERN.test(organizationId)) {
    throw new Error(`identifiant d'organisation non conforme : refus d'ouvrir une transaction`);
  }

  const client: PoolClient = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.organization_id = '${organizationId}'`);

    const result = await fn({
      query: <R extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]) =>
        client.query<R>(sql, params),
    });

    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Le ROLLBACK peut échouer si la connexion est déjà tombée : l'erreur
      // d'origine est plus informative, on ne la masque pas.
    }
    throw error;
  } finally {
    client.release();
  }
}

const USER_ID_PATTERN = /^usr_[0-9a-z]{26}$/;

/**
 * Transaction cadrée sur un UTILISATEUR et non sur une organisation.
 *
 * Réservée aux lectures légitimement antérieures à la connaissance de
 * l'organisation : « de quelles organisations suis-je membre ? ». La politique
 * `membership_self_read` (migration 0003) n'ouvre que le SELECT de ses propres
 * adhésions ; tout le reste demeure cadré par le tenant.
 */
export async function withUser<T>(
  pool: Pool,
  userId: string,
  fn: (client: TenantClient) => Promise<T>,
): Promise<T> {
  if (!USER_ID_PATTERN.test(userId)) {
    throw new Error("identifiant d'utilisateur non conforme : refus d'ouvrir une transaction");
  }

  const client: PoolClient = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL app.user_id = '${userId}'`);

    const result = await fn({
      query: <R extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]) =>
        client.query<R>(sql, params),
    });

    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // L'erreur d'origine est plus informative.
    }
    throw error;
  } finally {
    client.release();
  }
}

/**
 * Transaction dédiée à la résolution d'une credential d'agent.
 *
 * Seul chemin du code qui lit sans contexte de tenant, et c'est inévitable :
 * c'est la credential elle-même qui révèle l'organisation. La politique
 * `agent_credential_lookup` n'autorise que le SELECT de api_credentials, et
 * seulement quand aucun contexte d'organisation n'est posé.
 */
export async function withAgentLookup<T>(
  pool: Pool,
  fn: (client: TenantClient) => Promise<T>,
): Promise<T> {
  const client: PoolClient = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL app.agent_lookup = 'on'");

    const result = await fn({
      query: <R extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]) =>
        client.query<R>(sql, params),
    });

    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // idem
    }
    throw error;
  } finally {
    client.release();
  }
}

export async function isReachable(pool: Pool): Promise<boolean> {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch {
    return false;
  }
}

/**
 * Contexte ADMIN PLATEFORME (console vendeur). Pose le drapeau `app.platform_admin`
 * qui active la politique permissive `platform_admin_all` sur servers/licenses,
 * donnant une vue transversale à TOUTES les organisations.
 *
 * À n'appeler QU'APRÈS avoir vérifié que l'utilisateur est platform admin.
 * Comme withAgentLookup, tout tient dans une transaction et le drapeau est SET LOCAL.
 */
export async function withPlatformAdmin<T>(
  pool: Pool,
  fn: (client: TenantClient) => Promise<T>,
): Promise<T> {
  const client: PoolClient = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL app.platform_admin = 'on'");

    const result = await fn({
      query: <R extends QueryResultRow = QueryResultRow>(sql: string, params?: unknown[]) =>
        client.query<R>(sql, params),
    });

    await client.query('COMMIT');
    return result;
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // idem
    }
    throw error;
  } finally {
    client.release();
  }
}
