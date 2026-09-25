/**
 * Sessions et authentification utilisateur.
 *
 * Choix structurants :
 *
 *   - **sessions opaques en base**, pas de JWT. Le produit doit pouvoir révoquer
 *     une session instantanément (« déconnecter cet appareil ») et refléter
 *     immédiatement une rétrogradation de rôle. Un JWT autoporteur oblige à
 *     maintenir une liste de révocation, c'est-à-dire à reconstruire une session
 *     en base tout en gardant les inconvénients du JWT ;
 *   - **seul le hachage du jeton est stocké** : un dump de base ne permet pas de
 *     rejouer une session vivante ;
 *   - **le rôle n'est jamais dans la session.** Il est résolu en base à chaque
 *     requête ;
 *   - **réponses uniformes** sur les chemins d'inscription et de reset, pour ne
 *     pas révéler quels emails existent.
 */
import type { Pool } from 'pg';
import {
  hashPassword,
  hashToken,
  newId,
  newOpaqueToken,
  verifyPassword,
} from '../lib/crypto.ts';
import type { Role } from '../rbac/permissions.ts';
import { withUser } from '../lib/db.ts';

const SESSION_TTL_SECONDS = 60 * 60 * 12;
const MAX_FAILED_LOGINS = 8;
const LOCKOUT_SECONDS = 15 * 60;

export interface SessionRecord {
  id: string;
  userId: string;
  organizationId: string | null;
  mfaSatisfied: boolean;
  expiresAt: Date;
}

export interface AuthenticatedUser {
  userId: string;
  email: string;
  displayName: string;
  emailVerified: boolean;
  mfaEnforced: boolean;
}

export interface SessionContext {
  session: SessionRecord;
  user: AuthenticatedUser;
}

export type LoginOutcome =
  | { status: 'ok'; token: string; session: SessionRecord }
  | { status: 'mfa_required'; token: string; session: SessionRecord }
  | { status: 'invalid' }
  | { status: 'locked'; retryAfterSeconds: number };

export type DiscordLoginOutcome =
  | { status: 'ok'; token: string; session: SessionRecord }
  | { status: 'mfa_required'; token: string; session: SessionRecord }
  | {
      status: 'error';
      reason: 'no_email' | 'email_taken' | 'already_linked' | 'account_disabled';
    };

export class AuthService {
  // Champ déclaré explicitement : les propriétés de constructeur TypeScript ne
  // sont pas supportées par le mode strip-only de Node (--experimental-strip-types).
  private readonly pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  // -------------------------------------------------------------------------
  // Inscription
  // -------------------------------------------------------------------------

  /**
   * Crée un utilisateur, son organisation et son adhésion OWNER, dans une seule
   * transaction : un utilisateur sans organisation ne pourrait rien faire et
   * une organisation sans OWNER serait ingérable.
   *
   * Retourne toujours la même forme, que l'email existe ou non.
   */
  async register(input: {
    email: string;
    password: string;
    displayName: string;
    organizationName: string;
  }): Promise<{ created: boolean; userId?: string; organizationId?: string }> {
    const passwordHash = await hashPassword(input.password);
    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      const existing = await client.query('SELECT 1 FROM users WHERE email = $1', [input.email]);
      if (existing.rowCount && existing.rowCount > 0) {
        await client.query('ROLLBACK');
        // Pas d'erreur : l'appelant renvoie la même réponse dans les deux cas.
        return { created: false };
      }

      const userId = newId('usr');
      const organizationId = newId('org');
      const slug = await this.uniqueSlug(client, input.organizationName);

      await client.query(
        `INSERT INTO users (id, email, password_hash, display_name) VALUES ($1, $2, $3, $4)`,
        [userId, input.email, passwordHash, input.displayName],
      );
      await client.query(
        `INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
        [organizationId, input.organizationName, slug],
      );

      // L'inscription CRÉE l'organisation : il n'existe donc aucun contexte de
      // tenant avant cette ligne, et les écritures suivantes (memberships,
      // subscriptions, audit_logs) sont toutes soumises à RLS. Le contexte est
      // posé ici, après la création, avec SET LOCAL pour qu'il meure avec la
      // transaction et ne fuite pas sur la connexion rendue au pool.
      // Le format de l'identifiant vient de newId(), pas d'une entrée client.
      await client.query(`SET LOCAL app.organization_id = '${organizationId}'`);

      await client.query(
        `INSERT INTO memberships (id, organization_id, user_id, role, accepted_at)
              VALUES ($1, $2, $3, 'OWNER', now())`,
        [newId('usr').replace('usr_', 'mem_'), organizationId, userId],
      );
      await client.query(
        `INSERT INTO subscriptions (id, organization_id, plan_code, state, trial_ends_at)
              VALUES ($1, $2, 'free', 'TRIALING', now() + interval '14 days')`,
        [newId('sub'), organizationId],
      );
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action,
                                 target_kind, target_id)
              VALUES ($1, $2, 'user', 'organization.created', 'organization', $1)`,
        [organizationId, userId],
      );

      await client.query('COMMIT');
      return { created: true, userId, organizationId };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async uniqueSlug(
    client: { query: (sql: string, params?: unknown[]) => Promise<{ rowCount: number | null }> },
    name: string,
  ): Promise<string> {
    const base =
      name
        .toLowerCase()
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 40) || 'org';

    for (let attempt = 0; attempt < 20; attempt += 1) {
      const candidate = attempt === 0 ? base : `${base}-${attempt}`;
      if (candidate.length < 2) continue;
      const taken = await client.query('SELECT 1 FROM organizations WHERE slug = $1', [candidate]);
      if (!taken.rowCount) return candidate;
    }
    return `${base}-${Date.now().toString(36)}`;
  }

  // -------------------------------------------------------------------------
  // Connexion
  // -------------------------------------------------------------------------

  async login(input: {
    email: string;
    password: string;
    ip?: string | null;
    userAgent?: string | null;
  }): Promise<LoginOutcome> {
    const { rows } = await this.pool.query<{
      id: string;
      password_hash: string;
      locked_until: Date | null;
      failed_logins: number;
      mfa_enforced: boolean;
      deleted_at: Date | null;
      has_mfa: boolean;
    }>(
      `SELECT u.id, u.password_hash, u.locked_until, u.failed_logins, u.mfa_enforced,
              u.deleted_at,
              EXISTS (SELECT 1 FROM mfa_factors f
                       WHERE f.user_id = u.id AND f.confirmed_at IS NOT NULL) AS has_mfa
         FROM users u WHERE u.email = $1`,
      [input.email],
    );

    const user = rows[0];

    if (!user || user.deleted_at) {
      // Coût de vérification comparable à celui d'un compte existant, pour ne
      // pas révéler l'existence d'un email par le temps de réponse.
      await verifyPassword(input.password, 'scrypt$32768$8$1$AAAA$AAAA');
      return { status: 'invalid' };
    }

    if (user.locked_until && user.locked_until.getTime() > Date.now()) {
      return {
        status: 'locked',
        retryAfterSeconds: Math.ceil((user.locked_until.getTime() - Date.now()) / 1000),
      };
    }

    const passwordOk = await verifyPassword(input.password, user.password_hash);

    if (!passwordOk) {
      const failures = user.failed_logins + 1;
      await this.pool.query(
        // Casts explicites : sans eux, PostgreSQL déduit deux types
        // incompatibles pour $2 (affectation entière d'un côté, comparaison de
        // l'autre) et la requête échoue. Chemin emprunté uniquement quand le
        // compte existe ET que le mot de passe est faux, donc jamais atteint
        // par un test de connexion réussie.
        `UPDATE users
            SET failed_logins = $2::int,
                locked_until = CASE WHEN $2::int >= $3::int
                                    THEN now() + make_interval(secs => $4::double precision)
                                    ELSE locked_until END
          WHERE id = $1`,
        [user.id, failures, MAX_FAILED_LOGINS, LOCKOUT_SECONDS],
      );
      return { status: 'invalid' };
    }

    await this.pool.query(
      `UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now()
        WHERE id = $1`,
      [user.id],
    );

    // La session est créée même quand la MFA est requise, mais avec
    // mfa_satisfied = false : elle ne donne accès à rien d'autre qu'à la
    // vérification du second facteur. C'est plus simple à raisonner qu'un jeton
    // intermédiaire d'un type différent, qu'on oublie ensuite d'expirer.
    const mfaRequired = user.has_mfa || user.mfa_enforced;
    const created = await this.createSession({
      userId: user.id,
      mfaSatisfied: !mfaRequired,
      ip: input.ip ?? null,
      userAgent: input.userAgent ?? null,
    });

    await this.audit(user.id, null, mfaRequired ? 'auth.login_mfa_pending' : 'auth.login', input.ip);

    return mfaRequired
      ? { status: 'mfa_required', token: created.token, session: created.session }
      : { status: 'ok', token: created.token, session: created.session };
  }

  async createSession(input: {
    userId: string;
    mfaSatisfied: boolean;
    organizationId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
  }): Promise<{ token: string; session: SessionRecord }> {
    const token = newOpaqueToken();
    const id = newId('ses');
    const expiresAt = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);

    // Si aucune organisation n'est demandée, on sélectionne la première
    // adhésion : un utilisateur mono-organisation ne doit pas avoir à choisir.
    //
    // withUser est indispensable : la sous-requête lit `memberships`, table
    // sous RLS. Sans contexte, elle renvoyait zéro ligne et la session
    // naissait sans organisation — échec silencieux, puis 401 à la requête
    // suivante sans rien d'exploitable dans les logs.
    const { rows } = await withUser(this.pool, input.userId, (client) =>
      client.query<{ organization_id: string }>(
      `INSERT INTO sessions (id, user_id, token_hash, organization_id, mfa_satisfied,
                             ip, user_agent, expires_at)
            VALUES ($1, $2, $3,
                    COALESCE($4, (SELECT organization_id FROM memberships
                                   WHERE user_id = $2 AND accepted_at IS NOT NULL
                                   ORDER BY created_at LIMIT 1)),
                    $5, $6, $7, $8)
       RETURNING organization_id`,
        [
          id,
          input.userId,
          hashToken(token),
          input.organizationId ?? null,
          input.mfaSatisfied,
          input.ip,
          input.userAgent?.slice(0, 400) ?? null,
          expiresAt,
        ],
      ),
    );

    return {
      token,
      session: {
        id,
        userId: input.userId,
        organizationId: rows[0]?.organization_id ?? null,
        mfaSatisfied: input.mfaSatisfied,
        expiresAt,
      },
    };
  }

  /** Résout une session à partir du jeton de cookie. Retourne null si inutilisable. */
  async resolveSession(token: string): Promise<SessionContext | null> {
    const { rows } = await this.pool.query<{
      id: string;
      user_id: string;
      organization_id: string | null;
      mfa_satisfied: boolean;
      expires_at: Date;
      email: string;
      display_name: string;
      email_verified_at: Date | null;
      mfa_enforced: boolean;
    }>(
      `SELECT s.id, s.user_id, s.organization_id, s.mfa_satisfied, s.expires_at,
              u.email, u.display_name, u.email_verified_at, u.mfa_enforced
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1
          AND s.revoked_at IS NULL
          AND s.expires_at > now()
          AND u.deleted_at IS NULL`,
      [hashToken(token)],
    );

    const row = rows[0];
    if (!row) return null;

    // Trace de dernière activité, hors chemin critique.
    void this.pool.query('UPDATE sessions SET last_seen_at = now() WHERE id = $1', [row.id]);

    return {
      session: {
        id: row.id,
        userId: row.user_id,
        organizationId: row.organization_id,
        mfaSatisfied: row.mfa_satisfied,
        expiresAt: row.expires_at,
      },
      user: {
        userId: row.user_id,
        email: row.email,
        displayName: row.display_name,
        emailVerified: row.email_verified_at != null,
        mfaEnforced: row.mfa_enforced,
      },
    };
  }

  /**
   * Résout le rôle de l'utilisateur dans l'organisation de la session.
   *
   * Appelé à chaque requête protégée : c'est ce qui rend une rétrogradation
   * immédiate au lieu d'attendre l'expiration de la session.
   */
  async resolveRole(userId: string, organizationId: string): Promise<Role | null> {
    const { rows } = await withUser(this.pool, userId, (client) =>
      client.query<{ role: Role }>(
        `SELECT role FROM memberships
          WHERE user_id = $1 AND organization_id = $2 AND accepted_at IS NOT NULL`,
        [userId, organizationId],
      ),
    );
    return rows[0]?.role ?? null;
  }

  async markMfaSatisfied(sessionId: string): Promise<void> {
    await this.pool.query('UPDATE sessions SET mfa_satisfied = true WHERE id = $1', [sessionId]);
  }

  /** Rotation du jeton après élévation de privilège, contre la fixation de session. */
  async rotateSession(context: SessionContext): Promise<{ token: string; session: SessionRecord }> {
    await this.revokeSession(context.session.id);
    return this.createSession({
      userId: context.session.userId,
      mfaSatisfied: true,
      organizationId: context.session.organizationId,
    });
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.pool.query(
      'UPDATE sessions SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL',
      [sessionId],
    );
  }

  async revokeAllSessions(userId: string, exceptSessionId?: string): Promise<number> {
    const { rowCount } = await this.pool.query(
      `UPDATE sessions SET revoked_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL AND ($2::text IS NULL OR id <> $2)`,
      [userId, exceptSessionId ?? null],
    );
    return rowCount ?? 0;
  }

  /** Bascule d'organisation, autorisée seulement vers une adhésion existante. */
  async switchOrganization(sessionId: string, userId: string, organizationId: string): Promise<boolean> {
    const { rowCount } = await withUser(this.pool, userId, (client) =>
      client.query(
        `UPDATE sessions SET organization_id = $3
          WHERE id = $1
            AND EXISTS (SELECT 1 FROM memberships
                         WHERE user_id = $2 AND organization_id = $3
                           AND accepted_at IS NOT NULL)`,
        [sessionId, userId, organizationId],
      ),
    );
    return (rowCount ?? 0) > 0;
  }

  // -------------------------------------------------------------------------
  // Réinitialisation de mot de passe
  // -------------------------------------------------------------------------

  /**
   * Retourne le jeton à envoyer par email, ou null si l'email est inconnu.
   * L'appelant répond la même chose dans les deux cas.
   *
   * Le jeton vit dans `password_resets`, table portée par l'utilisateur : un
   * reset n'appartient pas à une organisation, et le stocker dans une table
   * cloisonnée le rendrait visible aux administrateurs d'une organisation.
   */
  async createPasswordReset(email: string, ip?: string | null): Promise<string | null> {
    const { rows } = await this.pool.query<{ id: string }>(
      'SELECT id FROM users WHERE email = $1 AND deleted_at IS NULL',
      [email],
    );
    const user = rows[0];
    if (!user) return null;

    const token = newOpaqueToken();

    // Demander un nouveau lien invalide le précédent : sinon un lien
    // intercepté reste utilisable en parallèle du nouveau.
    await this.pool.query(
      `UPDATE password_resets SET consumed_at = now()
        WHERE user_id = $1 AND purpose = 'password_reset' AND consumed_at IS NULL`,
      [user.id],
    );

    await this.pool.query(
      `INSERT INTO password_resets (id, user_id, token_hash, purpose, requested_ip, expires_at)
            VALUES ($1, $2, $3, 'password_reset', $4, now() + interval '1 hour')`,
      [newId('inv'), user.id, hashToken(token), ip ?? null],
    );

    return token;
  }

  /**
   * Applique un nouveau mot de passe et révoque toutes les sessions : après un
   * reset, un attaquant encore connecté doit perdre son accès.
   *
   * Le jeton est marqué consommé dans la même transaction que le changement de
   * mot de passe, ce qui interdit deux resets avec le même lien.
   */
  async completePasswordReset(token: string, newPassword: string): Promise<boolean> {
    const passwordHash = await hashPassword(newPassword);
    const client = await this.pool.connect();

    try {
      await client.query('BEGIN');

      const { rows } = await client.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM password_resets
          WHERE token_hash = $1 AND purpose = 'password_reset'
            AND consumed_at IS NULL AND expires_at > now()
          FOR UPDATE`,
        [hashToken(token)],
      );

      const reset = rows[0];
      if (!reset) {
        await client.query('ROLLBACK');
        return false;
      }

      await client.query('UPDATE password_resets SET consumed_at = now() WHERE id = $1', [reset.id]);
      await client.query(
        `UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL
          WHERE id = $1`,
        [reset.user_id, passwordHash],
      );
      await client.query(
        `UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
        [reset.user_id],
      );
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action)
              VALUES (NULL, $1, 'user', 'auth.password_reset')`,
        [reset.user_id],
      );

      await client.query('COMMIT');
      return true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // -------------------------------------------------------------------------
  // Connexion Discord (OAuth2)
  //
  // Trois chemins, dans cet ordre :
  //   1. identité déjà liée -> on ouvre la session de l'utilisateur lié ;
  //   2. e-mail Discord VÉRIFIÉ correspondant à un compte existant -> on lie et
  //      on ouvre la session (l'e-mail vérifié par Discord fait foi) ;
  //   3. aucun compte -> on provisionne un nouvel utilisateur + organisation
  //      (comme une inscription), e-mail marqué vérifié.
  //
  // On ne lie JAMAIS sur un e-mail non vérifié : sinon un compte Discord au
  // même e-mail (non prouvé) prendrait le contrôle d'un compte mot de passe.
  // La MFA est respectée : si le compte lié l'exige, la session naît non
  // satisfaite (mfa_required) exactement comme la connexion par e-mail.
  // -------------------------------------------------------------------------
  async loginWithDiscord(input: {
    discordUserId: string;
    email: string | null;
    emailVerified: boolean;
    username: string | null;
    avatarUrl: string | null;
    displayName: string;
    ip?: string | null;
    userAgent?: string | null;
  }): Promise<DiscordLoginOutcome> {
    const finalize = async (
      userId: string,
      hasMfa: boolean,
      mfaEnforced: boolean,
      action: string,
    ): Promise<DiscordLoginOutcome> => {
      const mfaRequired = hasMfa || mfaEnforced;
      const created = await this.createSession({
        userId,
        mfaSatisfied: !mfaRequired,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
      });
      await this.pool.query(
        `UPDATE discord_identities SET last_login_at = now(), username = $2, avatar_url = $3
          WHERE discord_user_id = $1`,
        [input.discordUserId, input.username, input.avatarUrl],
      );
      await this.pool.query(
        `UPDATE users SET last_login_at = now() WHERE id = $1`,
        [userId],
      );
      await this.audit(userId, null, mfaRequired ? action + '_mfa_pending' : action, input.ip);
      return mfaRequired
        ? { status: 'mfa_required', token: created.token, session: created.session }
        : { status: 'ok', token: created.token, session: created.session };
    };

    // --- 1. Identité déjà liée ---
    const linked = await this.pool.query<{
      user_id: string;
      deleted_at: Date | null;
      mfa_enforced: boolean;
      has_mfa: boolean;
    }>(
      `SELECT di.user_id, u.deleted_at, u.mfa_enforced,
              EXISTS (SELECT 1 FROM mfa_factors f
                       WHERE f.user_id = u.id AND f.confirmed_at IS NOT NULL) AS has_mfa
         FROM discord_identities di
         JOIN users u ON u.id = di.user_id
        WHERE di.discord_user_id = $1`,
      [input.discordUserId],
    );
    if (linked.rows[0]) {
      if (linked.rows[0].deleted_at) return { status: 'error', reason: 'account_disabled' };
      return finalize(
        linked.rows[0].user_id,
        linked.rows[0].has_mfa,
        linked.rows[0].mfa_enforced,
        'auth.login_discord',
      );
    }

    // --- 2. Rattachement par e-mail Discord vérifié ---
    if (input.email && input.emailVerified) {
      const existing = await this.pool.query<{
        id: string;
        deleted_at: Date | null;
        mfa_enforced: boolean;
        has_mfa: boolean;
      }>(
        `SELECT u.id, u.deleted_at, u.mfa_enforced,
                EXISTS (SELECT 1 FROM mfa_factors f
                         WHERE f.user_id = u.id AND f.confirmed_at IS NOT NULL) AS has_mfa
           FROM users u WHERE u.email = $1`,
        [input.email],
      );
      const u = existing.rows[0];
      if (u) {
        if (u.deleted_at) return { status: 'error', reason: 'account_disabled' };
        try {
          await this.pool.query(
            `INSERT INTO discord_identities (discord_user_id, user_id, username, email, avatar_url)
                  VALUES ($1, $2, $3, $4, $5)`,
            [input.discordUserId, u.id, input.username, input.email, input.avatarUrl],
          );
        } catch {
          // UNIQUE(user_id) : le compte est déjà lié à une autre identité Discord.
          return { status: 'error', reason: 'already_linked' };
        }
        return finalize(u.id, u.has_mfa, u.mfa_enforced, 'auth.login_discord_linked');
      }
    }

    // --- 3. Provisionnement d'un nouveau compte + organisation ---
    // Un e-mail est obligatoire (colonne NOT NULL UNIQUE) : sans le scope
    // `email` accordé, on ne peut pas créer de compte.
    if (!input.email) return { status: 'error', reason: 'no_email' };

    // E-mail non vérifié mais déjà pris : on refuse plutôt que de risquer un
    // rattachement à l'aveugle. L'utilisateur doit se connecter par e-mail.
    const clash = await this.pool.query('SELECT 1 FROM users WHERE email = $1', [input.email]);
    if (clash.rowCount && clash.rowCount > 0) {
      return { status: 'error', reason: 'email_taken' };
    }

    const client = await this.pool.connect();
    let newUserId: string;
    try {
      await client.query('BEGIN');

      const userId = newId('usr');
      const organizationId = newId('org');
      const orgName = `Organisation de ${input.displayName}`.slice(0, 120);
      const slug = await this.uniqueSlug(client, orgName);
      // Mot de passe aléatoire inutilisable : la connexion se fait par Discord.
      // L'utilisateur peut définir un mot de passe plus tard via « mot de passe
      // oublié ». E-mail marqué vérifié seulement si Discord l'a vérifié.
      const passwordHash = await hashPassword(newOpaqueToken());

      await client.query(
        `INSERT INTO users (id, email, password_hash, display_name, email_verified_at)
              VALUES ($1, $2, $3, $4, CASE WHEN $5 THEN now() ELSE NULL END)`,
        [userId, input.email, passwordHash, input.displayName.slice(0, 80), input.emailVerified],
      );
      await client.query(
        `INSERT INTO organizations (id, name, slug) VALUES ($1, $2, $3)`,
        [organizationId, orgName, slug],
      );
      await client.query(`SET LOCAL app.organization_id = '${organizationId}'`);
      await client.query(
        `INSERT INTO memberships (id, organization_id, user_id, role, accepted_at)
              VALUES ($1, $2, $3, 'OWNER', now())`,
        [newId('usr').replace('usr_', 'mem_'), organizationId, userId],
      );
      await client.query(
        `INSERT INTO subscriptions (id, organization_id, plan_code, state, trial_ends_at)
              VALUES ($1, $2, 'free', 'TRIALING', now() + interval '14 days')`,
        [newId('sub'), organizationId],
      );
      await client.query(
        `INSERT INTO discord_identities (discord_user_id, user_id, username, email, avatar_url)
              VALUES ($1, $2, $3, $4, $5)`,
        [input.discordUserId, userId, input.username, input.email, input.avatarUrl],
      );
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action,
                                 target_kind, target_id)
              VALUES ($1, $2, 'user', 'organization.created_discord', 'organization', $1)`,
        [organizationId, userId],
      );

      await client.query('COMMIT');
      newUserId = userId;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    // Un compte neuf n'a jamais de MFA : session ouverte directement.
    return finalize(newUserId, false, false, 'auth.register_discord');
  }

  private async audit(
    userId: string | null,
    organizationId: string | null,
    action: string,
    ip?: string | null,
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action, ip)
            VALUES ($1, $2, 'user', $3, $4)`,
      [organizationId, userId, action, ip ?? null],
    );
  }
}
