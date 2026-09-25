/**
 * Surface utilisateur `/api/*`.
 *
 * Règle appliquée sans exception : **l'organisation vient de la session**,
 * jamais d'un paramètre de requête. Il n'existe donc aucun endpoint où passer
 * `organization_id` change ce qu'on lit. Toutes les requêtes de données passent
 * par `withTenant`, donc sous RLS — deuxième filet si une clause `WHERE` était
 * oubliée ici.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type { Redis } from 'ioredis';
import { z } from 'zod';
import { withTenant, withUser, withPlatformAdmin } from '../lib/db.ts';
import { newId, newOpaqueToken, hmacSha256Hex } from '../lib/crypto.ts';
import { env } from '../config/env.ts';
import { organizationChannel } from '../lib/redis.ts';
import type { AuthService } from '../auth/sessions.ts';
import type { CredentialStore } from '../agent-gateway/credentials.ts';
import { remoteConfigSchema, issueCommandSchema } from '../agent-gateway/schemas.ts';
import { PROTECTION_CATALOG, PROTECTION_BY_ID, PROTECTION_COUNT } from '../protections/catalog.ts';
import { checkMemberRemoval, checkRoleChange, permissionsOf, PERMISSIONS, ROLES } from '../rbac/permissions.ts';
import type { Role } from '../rbac/permissions.ts';
import {
  CSRF_HEADER,
  Guard,
  SESSION_COOKIE,
  cookieOptions,
  issueCsrfToken,
  toHttpError,
  verifyCsrf,
  type RequestActor,
} from './middleware.ts';
import type { Logger } from '../lib/logger.ts';

export interface DiscordDeps {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface ApiDeps {
  pool: Pool;
  publisher: Redis;
  auth: AuthService;
  credentials: CredentialStore;
  guard: Guard;
  logger: Logger;
  isProduction: boolean;
  webOrigin?: string | null;
  discord?: DiscordDeps | null;
}

const SESSION_TTL = 60 * 60 * 12;

const registerSchema = z
  .object({
    email: z.string().email().max(254),
    password: z.string().min(12).max(256),
    display_name: z.string().min(1).max(80),
    organization_name: z.string().min(1).max(120),
  })
  .strict();

const loginSchema = z
  .object({ email: z.string().email().max(254), password: z.string().min(1).max(256) })
  .strict();

const createServerSchema = z
  .object({
    name: z.string().min(1).max(120),
    environment: z.enum(['production', 'staging', 'development']).default('production'),
  })
  .strict();

const alertPatchSchema = z
  .object({
    status: z.enum(['OPEN', 'ACKNOWLEDGED', 'RESOLVED']),
    incident_id: z.string().max(64).nullable().optional(),
  })
  .strict();

const incidentCreateSchema = z
  .object({
    title: z.string().min(1).max(200),
    description: z.string().max(20_000).optional(),
    severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).default('MEDIUM'),
    server_id: z.string().max(64).optional(),
    alert_ids: z.array(z.string().max(64)).max(200).optional(),
  })
  .strict();

const incidentPatchSchema = z
  .object({
    title: z.string().min(1).max(200).optional(),
    description: z.string().max(20_000).optional(),
    severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    status: z.enum(['OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'CLOSED']).optional(),
    assigned_to: z.string().max(64).nullable().optional(),
  })
  .strict();

const alertQuerySchema = z
  .object({
    server_id: z.string().max(64).optional(),
    severity: z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional(),
    category: z.string().max(32).optional(),
    status: z.enum(['OPEN', 'ACKNOWLEDGED', 'RESOLVED']).optional(),
    since: z.coerce.number().int().min(0).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    cursor: z.string().max(64).optional(),
  })
  .strict();

export async function apiRoutes(app: FastifyInstance, deps: ApiDeps): Promise<void> {
  const { pool, auth, guard, credentials, logger } = deps;

  /** Enveloppe commune : traduit les erreurs de garde en réponses HTTP. */
  const handle = (
    work: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>,
  ) => async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      return await work(request, reply);
    } catch (error) {
      const mapped = toHttpError(error);
      if (mapped.status === 500) {
        logger.error('erreur non gérée sur /api', {
          path: request.url,
          detail: error instanceof Error ? error.message : String(error),
        });
      }
      reply.status(mapped.status);
      return mapped.body;
    }
  };

  const audit = async (
    actor: RequestActor,
    action: string,
    target: { kind: string; id: string },
    metadata: Record<string, unknown> = {},
    ip?: string,
  ) => {
    await withTenant(pool, actor.organizationId, async (client) => {
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, actor_label,
                                 action, target_kind, target_id, ip, metadata)
              VALUES ($1, $2, 'user', $3, $4, $5, $6, $7, $8)`,
        [
          actor.organizationId,
          actor.user.userId,
          actor.user.email,
          action,
          target.kind,
          target.id,
          ip ?? null,
          JSON.stringify(metadata),
        ],
      );
    });
  };

  // =========================================================================
  // Authentification
  // =========================================================================

  app.post('/api/auth/register', handle(async (request, reply) => {
    // Inscription publique DÉSACTIVÉE par défaut (dashboard sur invitation / compte démo).
    // Pour créer le compte admin initial : mettre ALLOW_REGISTRATION=true le temps d'une
    // inscription, puis repasser à false.
    if (process.env.ALLOW_REGISTRATION !== 'true') {
      reply.status(403);
      return { error: 'registration_disabled' };
    }
    const body = registerSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', field: body.error.issues[0]?.path.join('.') };
    }

    const result = await auth.register({
      email: body.data.email,
      password: body.data.password,
      displayName: body.data.display_name,
      organizationName: body.data.organization_name,
    });

    // Réponse identique que l'email existe ou non : sinon le formulaire
    // d'inscription devient un oracle d'énumération de comptes.
    reply.status(202);
    return { status: 'pending_verification' };
  }));

  app.post('/api/auth/login', handle(async (request, reply) => {
    const body = loginSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    const outcome = await auth.login({
      email: body.data.email,
      password: body.data.password,
      ip: request.ip,
      userAgent: request.headers['user-agent'] ?? null,
    });

    if (outcome.status === 'locked') {
      reply.status(429).header('Retry-After', String(outcome.retryAfterSeconds));
      return { error: 'account_locked', retry_after: outcome.retryAfterSeconds };
    }
    if (outcome.status === 'invalid') {
      reply.status(401);
      return { error: 'invalid_credentials' };
    }

    reply.setCookie(SESSION_COOKIE, outcome.token, cookieOptions(deps.isProduction, SESSION_TTL));
    const csrf = issueCsrfToken(reply, deps.isProduction);

    return {
      status: outcome.status === 'mfa_required' ? 'mfa_required' : 'ok',
      csrf_token: csrf,
      organization_id: outcome.session.organizationId,
    };
  }));

  app.post('/api/auth/logout', handle(async (request, reply) => {
    verifyCsrf(request);
    const context = await guard.pendingActor(request);
    await auth.revokeSession(context.session.id);
    reply.clearCookie(SESSION_COOKIE, { path: '/' });
    return { status: 'ok' };
  }));

  // -------------------------------------------------------------------------
  // Connexion Discord (OAuth2)
  //
  // Tant que DISCORD_LOGIN_ENABLED n'est pas activé avec ses trois secrets, on
  // ne lance PAS de demi-parcours : le bouton renvoie honnêtement vers l'écran
  // de connexion avec un message « bientôt disponible », plutôt qu'un aller
  // Discord qui retomberait sur une redirection cassée. On n'annonce jamais une
  // fonctionnalité qui ne marche pas.
  // -------------------------------------------------------------------------
  const DISCORD_STATE_COOKIE = 'zshield_discord_state';

  const webOrigin = (request: FastifyRequest): string => {
    const configured = deps.webOrigin;
    if (configured) return configured.replace(/\/$/, '');
    // À défaut, on déduit l'origine du front depuis la requête (utile en dev).
    const origin = request.headers.origin;
    if (typeof origin === 'string' && origin.length > 0) return origin.replace(/\/$/, '');
    const referer = request.headers.referer;
    if (typeof referer === 'string' && referer.length > 0) {
      try {
        return new URL(referer).origin;
      } catch {
        /* ignore */
      }
    }
    return '';
  };

  app.get('/api/auth/discord/start', async (request, reply) => {
    const cfg = deps.discord;
    const back = `${webOrigin(request)}/login`;

    if (!cfg || !cfg.clientId || !cfg.redirectUri) {
      return reply.redirect(`${back}?e=discord_unavailable`);
    }

    // État anti-CSRF : cookie court, comparé au retour.
    const state = newOpaqueToken();
    reply.setCookie(DISCORD_STATE_COOKIE, state, {
      httpOnly: true,
      sameSite: 'lax',
      secure: deps.isProduction,
      path: '/api/auth/discord',
      maxAge: 600,
    });

    const authorize = new URL('https://discord.com/api/oauth2/authorize');
    authorize.searchParams.set('client_id', cfg.clientId);
    authorize.searchParams.set('redirect_uri', cfg.redirectUri);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('scope', 'identify email');
    authorize.searchParams.set('state', state);
    authorize.searchParams.set('prompt', 'consent');
    return reply.redirect(authorize.toString());
  });

  app.get('/api/auth/discord/callback', async (request, reply) => {
    const cfg = deps.discord;
    const back = `${webOrigin(request)}/login`;
    const query = z
      .object({ code: z.string().max(512).optional(), state: z.string().max(128).optional() })
      .safeParse(request.query);
    const sent = request.cookies[DISCORD_STATE_COOKIE];
    reply.clearCookie(DISCORD_STATE_COOKIE, { path: '/api/auth/discord' });

    if (!cfg || !cfg.clientId || !cfg.clientSecret || !cfg.redirectUri) {
      return reply.redirect(`${back}?e=discord_unavailable`);
    }
    // Rejet strict : état manquant ou différent = on ne va pas plus loin.
    if (!query.success || !query.data.code || !query.data.state || !sent || query.data.state !== sent) {
      return reply.redirect(`${back}?e=discord_failed`);
    }

    try {
      // 1. Échange du code contre un jeton d'accès.
      const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: cfg.clientId,
          client_secret: cfg.clientSecret,
          grant_type: 'authorization_code',
          code: query.data.code,
          redirect_uri: cfg.redirectUri,
        }),
      });
      if (!tokenRes.ok) return reply.redirect(`${back}?e=discord_failed`);
      const token = (await tokenRes.json()) as { access_token?: string; token_type?: string };
      if (!token.access_token) return reply.redirect(`${back}?e=discord_failed`);

      // 2. Récupération de l'identité (scope identify + email).
      const meRes = await fetch('https://discord.com/api/users/@me', {
        headers: { Authorization: `${token.token_type ?? 'Bearer'} ${token.access_token}` },
      });
      if (!meRes.ok) return reply.redirect(`${back}?e=discord_failed`);
      const me = (await meRes.json()) as {
        id: string;
        username?: string;
        global_name?: string | null;
        email?: string | null;
        verified?: boolean;
        avatar?: string | null;
      };
      if (!me.id) return reply.redirect(`${back}?e=discord_failed`);

      const avatarUrl = me.avatar
        ? `https://cdn.discordapp.com/avatars/${me.id}/${me.avatar}.png`
        : null;

      // 3. Ouverture / création de session côté produit.
      const outcome = await auth.loginWithDiscord({
        discordUserId: me.id,
        email: me.email ?? null,
        emailVerified: me.verified === true,
        username: me.username ?? null,
        avatarUrl,
        displayName: me.global_name || me.username || 'Membre Discord',
        ip: request.ip,
        userAgent: request.headers['user-agent'] ?? null,
      });

      if (outcome.status === 'error') {
        return reply.redirect(`${back}?e=discord_${outcome.reason}`);
      }

      reply.setCookie(SESSION_COOKIE, outcome.token, cookieOptions(deps.isProduction, SESSION_TTL));
      issueCsrfToken(reply, deps.isProduction);

      if (outcome.status === 'mfa_required') {
        // La session existe mais attend le second facteur, dont l'écran n'est pas
        // encore ouvert : on le dit honnêtement plutôt que d'ouvrir l'accès.
        return reply.redirect(`${back}?e=discord_mfa`);
      }
      return reply.redirect(webOrigin(request) || '/');
    } catch {
      return reply.redirect(`${back}?e=discord_failed`);
    }
  });

  app.get('/api/auth/me', handle(async (request) => {
    const actor = await guard.actor(request);
    // Le flag admin plateforme vit sur l'utilisateur (table users, hors RLS).
    const adminRow = await pool.query<{ is_platform_admin: boolean }>(
      `SELECT is_platform_admin FROM users WHERE id = $1`,
      [actor.user.userId],
    );
    return {
      user: {
        id: actor.user.userId,
        email: actor.user.email,
        display_name: actor.user.displayName,
        email_verified: actor.user.emailVerified,
      },
      organization_id: actor.organizationId,
      role: actor.role,
      permissions: permissionsOf(actor.role),
      is_platform_admin: adminRow.rows[0]?.is_platform_admin === true,
    };
  }));

  app.post('/api/auth/switch-organization', handle(async (request, reply) => {
    verifyCsrf(request);
    const actor = await guard.actor(request);
    const body = z.object({ organization_id: z.string().max(64) }).strict().safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    // `switchOrganization` vérifie l'adhésion en SQL : fournir l'identifiant
    // d'une organisation dont on n'est pas membre ne fait rien.
    const switched = await auth.switchOrganization(
      actor.session.id,
      actor.user.userId,
      body.data.organization_id,
    );
    if (!switched) {
      reply.status(404);
      return { error: 'not_found' };
    }
    return { status: 'ok' };
  }));

  app.get('/api/auth/sessions', handle(async (request) => {
    const actor = await guard.actor(request);
    const { rows } = await pool.query(
      `SELECT id, ip, user_agent, created_at, last_seen_at, expires_at,
              (id = $2) AS current
         FROM sessions
        WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
        ORDER BY last_seen_at DESC`,
      [actor.user.userId, actor.session.id],
    );
    return { sessions: rows };
  }));

  app.delete('/api/auth/sessions/:id', handle(async (request, reply) => {
    verifyCsrf(request);
    const actor = await guard.actor(request);
    const sessionId = (request.params as { id: string }).id;

    // Cadré sur l'utilisateur courant : fournir l'identifiant de session d'un
    // autre utilisateur ne révoque rien, et renvoie le même 404 qu'une session
    // inexistante.
    const { rowCount } = await pool.query(
      `UPDATE sessions SET revoked_at = now()
        WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
      [sessionId, actor.user.userId],
    );

    if (!rowCount) {
      reply.status(404);
      return { error: 'not_found' };
    }

    return { status: 'ok' };
  }));

  // =========================================================================
  // Organisation et membres
  // =========================================================================

  app.get('/api/organizations', handle(async (request) => {
    const actor = await guard.actor(request);
    // Lecture multi-organisations : il n'y a pas de tenant unique ici, d'où
    // withUser et la politique `membership_self_read` (migration 0003).
    const { rows } = await withUser(pool, actor.user.userId, (client) =>
      client.query(
        `SELECT o.id, o.name, o.slug, m.role
           FROM memberships m
           JOIN organizations o ON o.id = m.organization_id
          WHERE m.user_id = $1 AND m.accepted_at IS NOT NULL AND o.deleted_at IS NULL
          ORDER BY o.name`,
        [actor.user.userId],
      ),
    );
    return { organizations: rows };
  }));

  app.get('/api/members', handle(async (request) => {
    const actor = await guard.requireRead(request, 'member.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT m.id, m.role, m.created_at, m.accepted_at,
                u.id AS user_id, u.email, u.display_name, u.last_login_at
           FROM memberships m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = $1
          ORDER BY m.role, u.email`,
        [actor.organizationId],
      );
      return { members: rows };
    });
  }));

  // Matrice « qui accède à quoi » : la source de vérité RBAC, exposée en
  // lecture pour l'onglet Comptes & accès. C'est la même matrice qui autorise
  // réellement côté serveur — l'interface ne fait que la montrer.
  app.get('/api/rbac/matrix', handle(async (request) => {
    await guard.requireRead(request, 'member.read');
    const grants: Record<string, string[]> = {};
    for (const role of ROLES) grants[role] = permissionsOf(role);
    return { roles: ROLES, permissions: PERMISSIONS, grants };
  }));

  app.patch('/api/memberships/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'member.manage');
    const body = z.object({ role: z.enum(ROLES) }).strict().safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const membershipId = (request.params as { id: string }).id;

    const result = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ user_id: string; role: Role }>(
        `SELECT user_id, role FROM memberships
          WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [membershipId, actor.organizationId],
      );
      const target = rows[0];
      if (!target) return { status: 404 as const };

      const { rows: counts } = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM memberships
          WHERE organization_id = $1 AND role = 'OWNER'`,
        [actor.organizationId],
      );

      // L'invariant « au moins un OWNER » est vérifié DANS la transaction, avec
      // la ligne verrouillée : deux rétrogradations simultanées ne peuvent pas
      // vider l'organisation de ses OWNER.
      const refusal = checkRoleChange({
        actorRole: actor.role,
        actorUserId: actor.user.userId,
        targetUserId: target.user_id,
        targetCurrentRole: target.role,
        targetNewRole: body.data.role,
        ownerCount: Number(counts[0]?.count ?? '0'),
      });
      if (refusal) return { status: 403 as const, refusal };

      await client.query(
        `UPDATE memberships SET role = $3, updated_at = now()
          WHERE id = $1 AND organization_id = $2`,
        [membershipId, actor.organizationId, body.data.role],
      );

      return { status: 200 as const, previous: target.role, userId: target.user_id };
    });

    if (result.status === 404) {
      reply.status(404);
      return { error: 'not_found' };
    }
    if (result.status === 403) {
      reply.status(403);
      return { error: 'forbidden', reason: result.refusal };
    }

    await audit(actor, 'member.role_changed', { kind: 'membership', id: membershipId }, {
      from: result.previous,
      to: body.data.role,
    }, request.ip);

    return { status: 'ok' };
  }));

  app.delete('/api/memberships/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'member.manage');
    const membershipId = (request.params as { id: string }).id;

    const result = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ user_id: string; role: Role }>(
        `SELECT user_id, role FROM memberships
          WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [membershipId, actor.organizationId],
      );
      const target = rows[0];
      if (!target) return { status: 404 as const };

      const { rows: counts } = await client.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM memberships
          WHERE organization_id = $1 AND role = 'OWNER'`,
        [actor.organizationId],
      );

      const refusal = checkMemberRemoval({
        actorRole: actor.role,
        actorUserId: actor.user.userId,
        targetUserId: target.user_id,
        targetRole: target.role,
        ownerCount: Number(counts[0]?.count ?? '0'),
      });
      if (refusal) return { status: 403 as const, refusal };

      await client.query(`DELETE FROM memberships WHERE id = $1 AND organization_id = $2`, [
        membershipId,
        actor.organizationId,
      ]);
      return { status: 200 as const, userId: target.user_id };
    });

    if (result.status === 404) {
      reply.status(404);
      return { error: 'not_found' };
    }
    if (result.status === 403) {
      reply.status(403);
      return { error: 'forbidden', reason: result.refusal };
    }

    // Retirer l'adhésion ne suffit pas : les sessions pointant sur cette
    // organisation doivent être coupées, sinon l'utilisateur garde un accès
    // jusqu'à expiration.
    await pool.query(
      `UPDATE sessions SET revoked_at = now()
        WHERE user_id = $1 AND organization_id = $2 AND revoked_at IS NULL`,
      [result.userId, actor.organizationId],
    );

    await audit(actor, 'member.removed', { kind: 'membership', id: membershipId }, {}, request.ip);
    return { status: 'ok' };
  }));

  // =========================================================================
  // Serveurs
  // =========================================================================

  app.get('/api/servers', handle(async (request) => {
    const actor = await guard.requireRead(request, 'server.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT s.id, s.name, s.environment, s.state, s.health, s.agent_version,
                s.protocol_version, s.last_heartbeat_at, s.connected_at,
                s.uptime_seconds, s.players_online, s.max_players, s.queue_size,
                s.last_error, s.last_error_at, s.config_version,
                (SELECT count(*) FROM alerts a
                  WHERE a.organization_id = s.organization_id
                    AND a.server_id = s.id AND a.status = 'OPEN') AS open_alerts
           FROM servers s
          WHERE s.organization_id = $1 AND s.deleted_at IS NULL
          ORDER BY s.name`,
        [actor.organizationId],
      );
      return { servers: rows };
    });
  }));

  app.post('/api/servers', handle(async (request, reply) => {
    const actor = await guard.require(request, 'server.write');
    const body = createServerSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    const serverId = newId('srv');

    const quota = await withTenant(pool, actor.organizationId, async (client) => {
      // Le quota est vérifié dans la transaction, pas avant : deux créations
      // simultanées ne doivent pas franchir la limite ensemble.
      const { rows } = await client.query<{ used: string; allowed: string | null }>(
        `SELECT (SELECT count(*)::text FROM servers
                  WHERE organization_id = $1 AND deleted_at IS NULL) AS used,
                (SELECT COALESCE(
                          (SELECT int_value FROM entitlements
                            WHERE organization_id = $1 AND key = 'servers.max'),
                          (SELECT pe.int_value FROM subscriptions sub
                             JOIN plan_entitlements pe ON pe.plan_code = sub.plan_code
                            WHERE sub.organization_id = $1 AND pe.key = 'servers.max')
                        )::text) AS allowed`,
        [actor.organizationId],
      );

      const used = Number(rows[0]?.used ?? '0');
      const allowed = rows[0]?.allowed == null ? 1 : Number(rows[0].allowed);
      if (used >= allowed) return { exceeded: true as const, used, allowed };

      await client.query(
        `INSERT INTO servers (id, organization_id, name, environment, created_by)
              VALUES ($1, $2, $3, $4, $5)`,
        [serverId, actor.organizationId, body.data.name, body.data.environment, actor.user.userId],
      );
      return { exceeded: false as const };
    });

    if (quota.exceeded) {
      reply.status(402);
      return { error: 'entitlement_exceeded', limit: quota.allowed, used: quota.used };
    }

    await audit(actor, 'server.created', { kind: 'server', id: serverId }, {
      name: body.data.name,
    }, request.ip);

    reply.status(201);
    return { server: { id: serverId, name: body.data.name, state: 'UNKNOWN' } };
  }));

  app.delete('/api/servers/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'server.delete');
    const serverId = (request.params as { id: string }).id;

    const deleted = await withTenant(pool, actor.organizationId, async (client) => {
      // Suppression logique : les alertes et incidents historiques restent
      // consultables. Une suppression dure ferait disparaître des preuves
      // d'incident au moment où on en a le plus besoin.
      const { rowCount } = await client.query(
        `UPDATE servers SET deleted_at = now(), state = 'OFFLINE'
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if (!rowCount) return false;

      // Les credentials sont révoquées immédiatement : un agent encore en
      // fonction sur un serveur supprimé ne doit plus être accepté.
      await client.query(
        `UPDATE api_credentials
            SET status = 'REVOKED', revoked_at = now(), revoke_reason = 'server deleted'
          WHERE organization_id = $1 AND server_id = $2 AND status <> 'REVOKED'`,
        [actor.organizationId, serverId],
      );
      return true;
    });

    if (!deleted) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'server.deleted', { kind: 'server', id: serverId }, {}, request.ip);
    return { status: 'ok' };
  }));

  // -------------------------------------------------------------------------
  // Credentials : étapes 2 et 3 du wizard d'ajout de serveur
  // -------------------------------------------------------------------------

  app.post('/api/servers/:id/credentials', handle(async (request, reply) => {
    const actor = await guard.require(request, 'credential.manage');
    const serverId = (request.params as { id: string }).id;

    const server = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ id: string }>(
        `SELECT id FROM servers
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      return rows[0] ?? null;
    });

    if (!server) {
      reply.status(404);
      return { error: 'not_found' };
    }

    const agentId = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ id: string }>(
        `SELECT id FROM agents WHERE organization_id = $1 AND server_id = $2`,
        [actor.organizationId, serverId],
      );
      if (rows[0]) return rows[0].id;

      const created = newId('agt');
      await client.query(
        `INSERT INTO agents (id, organization_id, server_id) VALUES ($1, $2, $3)`,
        [created, actor.organizationId, serverId],
      );
      return created;
    });

    // Toute credential active précédente est révoquée : l'index unique partiel
    // n'autorise qu'une seule ACTIVE par serveur, et surtout un opérateur qui
    // régénère une clé s'attend à ce que l'ancienne cesse de fonctionner.
    await withTenant(pool, actor.organizationId, async (client) => {
      await client.query(
        `UPDATE api_credentials
            SET status = 'REVOKED', revoked_at = now(), revoked_by = $3,
                revoke_reason = 'replaced by a newly generated credential'
          WHERE organization_id = $1 AND server_id = $2 AND status <> 'REVOKED'`,
        [actor.organizationId, serverId, actor.user.userId],
      );
    });

    const issued = await credentials.issue({
      organizationId: actor.organizationId,
      serverId,
      agentId,
      createdBy: actor.user.userId,
    });

    await audit(actor, 'credential.created', { kind: 'server', id: serverId }, {
      key_id: issued.keyId,
    }, request.ip);

    reply.status(201);
    // Le secret n'est retourné QU'ICI, une seule fois. Il n'est stocké que
    // chiffré et aucun endpoint ne permet de le relire.
    return {
      key_id: issued.keyId,
      secret: issued.secret,
      agent_id: agentId,
      server_id: serverId,
      installation: {
        note: 'À placer dans server.cfg. Utiliser set et non sets : sets réplique la valeur à tous les clients connectés.',
        lines: [
          `set zshield_agent_id "${agentId}"`,
          `set zshield_server_id "${serverId}"`,
          `set zshield_key_id "${issued.keyId}"`,
          `set zshield_agent_secret "${issued.secret}"`,
        ],
      },
    };
  }));

  app.delete('/api/servers/:id/credentials/:keyId', handle(async (request, reply) => {
    const actor = await guard.require(request, 'credential.manage');
    const { id: serverId, keyId } = request.params as { id: string; keyId: string };

    const found = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE api_credentials
            SET status = 'REVOKED', revoked_at = now(), revoked_by = $4,
                revoke_reason = 'revoked by an administrator'
          WHERE organization_id = $1 AND server_id = $2 AND key_id = $3
            AND status <> 'REVOKED'`,
        [actor.organizationId, serverId, keyId, actor.user.userId],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!found) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'credential.revoked', { kind: 'server', id: serverId }, { key_id: keyId }, request.ip);
    return { status: 'ok' };
  }));

  // -------------------------------------------------------------------------
  // Configuration distante
  // -------------------------------------------------------------------------

  app.put('/api/servers/:id/configuration', handle(async (request, reply) => {
    const actor = await guard.require(request, 'configuration.write');
    const serverId = (request.params as { id: string }).id;

    // Validation contre le schéma STRICT de l'agent, à l'écriture. L'agent
    // rejette tout le document sur un seul champ inconnu : accepter ici un
    // réglage qu'il refusera produirait un serveur qui ignore silencieusement
    // sa configuration.
    const body = remoteConfigSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return {
        error: 'validation',
        field: body.error.issues[0]?.path.join('.'),
        message: body.error.issues[0]?.message,
      };
    }

    const updated = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ config_version: number }>(
        `UPDATE servers
            SET remote_config = $3, config_version = config_version + 1, updated_at = now()
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL
      RETURNING config_version`,
        [actor.organizationId, serverId, JSON.stringify(body.data)],
      );
      return rows[0] ?? null;
    });

    if (!updated) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'configuration.updated', { kind: 'server', id: serverId }, {
      config_version: updated.config_version,
      keys: Object.keys(body.data),
    }, request.ip);

    // L'agent découvrira le changement à son prochain heartbeat : il n'y a pas
    // de push, donc pas de connexion entrante à sécuriser côté serveur FiveM.
    return { config_version: updated.config_version };
  }));

  // =========================================================================
  // Alertes
  // =========================================================================

  app.get('/api/alerts', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'alert.read');
    const query = alertQuerySchema.safeParse(request.query);
    if (!query.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const filters = query.data;

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, server_id, severity, category, status, summary, metadata,
                occurrences, occurred_at, last_occurrence_at, incident_id,
                acknowledged_at, resolved_at, created_at, origin
           FROM alerts
          WHERE organization_id = $1
            AND ($2::text IS NULL OR server_id = $2)
            AND ($3::alert_severity IS NULL OR severity = $3)
            AND ($4::alert_status IS NULL OR status = $4)
            AND ($5::alert_category IS NULL OR category = $5)
            AND ($6::bigint IS NULL OR created_at >= to_timestamp($6))
            AND ($7::text IS NULL OR id < $7)
          ORDER BY created_at DESC, id DESC
          LIMIT $8`,
        [
          actor.organizationId,
          filters.server_id ?? null,
          filters.severity ?? null,
          filters.status ?? null,
          filters.category ?? null,
          filters.since ?? null,
          filters.cursor ?? null,
          filters.limit,
        ],
      );
      return { alerts: rows, next_cursor: rows.length === filters.limit ? rows.at(-1)?.id : null };
    });
  }));

  app.patch('/api/alerts/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'alert.triage');
    const body = alertPatchSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const alertId = (request.params as { id: string }).id;

    const updated = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE alerts
            SET status = $3,
                acknowledged_by = CASE WHEN $3 = 'ACKNOWLEDGED' THEN $4 ELSE acknowledged_by END,
                acknowledged_at = CASE WHEN $3 = 'ACKNOWLEDGED' THEN now() ELSE acknowledged_at END,
                resolved_by = CASE WHEN $3 = 'RESOLVED' THEN $4 ELSE resolved_by END,
                resolved_at = CASE WHEN $3 = 'RESOLVED' THEN now() ELSE resolved_at END,
                incident_id = COALESCE($5, incident_id)
          WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, alertId, body.data.status, actor.user.userId, body.data.incident_id ?? null],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!updated) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await deps.publisher
      .publish(
        organizationChannel(actor.organizationId),
        JSON.stringify({ type: 'alert.updated', payload: { id: alertId, status: body.data.status } }),
      )
      .catch(() => undefined);

    return { status: 'ok' };
  }));

  // =========================================================================
  // Incidents
  // =========================================================================

  app.get('/api/incidents', handle(async (request) => {
    const actor = await guard.requireRead(request, 'incident.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, title, severity, status, server_id, assigned_to, alert_count,
                first_alert_at, last_alert_at, resolved_at, created_at, updated_at
           FROM incidents
          WHERE organization_id = $1
          ORDER BY created_at DESC
          LIMIT 100`,
        [actor.organizationId],
      );
      return { incidents: rows };
    });
  }));

  // Détail d'un incident : métadonnées, timeline (incident_events) et les alertes
  // rattachées, qui constituent la chaîne de preuve. Le niveau de preuve E0–E5 est
  // DÉRIVÉ des alertes réelles (nombre de catégories corrélées + gravité), pas inventé.
  app.get('/api/incidents/:id', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'incident.read');
    const id = String((request.params as { id: string }).id ?? '');

    return withTenant(pool, actor.organizationId, async (client) => {
      const incident = await client.query(
        `SELECT id, title, description, severity, status, server_id, assigned_to,
                alert_count, first_alert_at, last_alert_at, acknowledged_at,
                resolved_at, created_at, updated_at
           FROM incidents WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, id],
      );
      if (incident.rowCount === 0) {
        reply.status(404);
        return { error: 'not_found' };
      }

      const timeline = await client.query(
        `SELECT e.kind, e.body, e.metadata, e.created_at, u.display_name AS actor_name
           FROM incident_events e
           LEFT JOIN users u ON u.id = e.actor_user_id
          WHERE e.organization_id = $1 AND e.incident_id = $2
          ORDER BY e.created_at ASC`,
        [actor.organizationId, id],
      );

      const alerts = await client.query<{ category: string; severity: string }>(
        `SELECT id, severity, category, summary, metadata, occurred_at
           FROM alerts
          WHERE organization_id = $1 AND incident_id = $2
          ORDER BY occurred_at ASC
          LIMIT 200`,
        [actor.organizationId, id],
      );

      // Niveau de preuve dérivé (miroir de la logique du cœur, §15).
      const categories = new Set(alerts.rows.map((a) => a.category));
      const severities = new Set(alerts.rows.map((a) => a.severity));
      const critical = severities.has('CRITICAL');
      const high = critical || severities.has('HIGH');
      let evidenceLevel = 'E0';
      if (alerts.rows.length > 0) {
        if (categories.size >= 2 && critical) evidenceLevel = 'E4';
        else if (categories.size >= 2) evidenceLevel = 'E3';
        else if (high) evidenceLevel = 'E2';
        else evidenceLevel = 'E1';
      }

      return {
        incident: incident.rows[0],
        timeline: timeline.rows,
        alerts: alerts.rows,
        evidence_level: evidenceLevel,
      };
    });
  }));

  // Note de révision / d'appel (§40) : ajoute un commentaire horodaté à la timeline.
  const incidentCommentSchema = z.object({ body: z.string().min(1).max(8000) }).strict();
  app.post('/api/incidents/:id/comment', handle(async (request, reply) => {
    const actor = await guard.require(request, 'incident.write');
    const id = String((request.params as { id: string }).id ?? '');
    const parsed = incidentCommentSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const done = await withTenant(pool, actor.organizationId, async (client) => {
      const exists = await client.query(
        `SELECT 1 FROM incidents WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, id],
      );
      if (exists.rowCount === 0) return false;
      await client.query(
        `INSERT INTO incident_events (organization_id, incident_id, actor_user_id, kind, body)
              VALUES ($1, $2, $3, 'comment', $4)`,
        [actor.organizationId, id, actor.user.userId, parsed.data.body],
      );
      return true;
    });
    if (!done) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'incident.comment', { kind: 'incident', id }, {}, request.ip);
    reply.status(201);
    return { ok: true };
  }));

  app.post('/api/incidents', handle(async (request, reply) => {
    const actor = await guard.require(request, 'incident.write');
    const body = incidentCreateSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    const incidentId = newId('inc');

    const created = await withTenant(pool, actor.organizationId, async (client) => {
      await client.query(
        `INSERT INTO incidents (id, organization_id, server_id, title, description,
                                severity, opened_by)
              VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          incidentId,
          actor.organizationId,
          body.data.server_id ?? null,
          body.data.title,
          body.data.description ?? null,
          body.data.severity,
          actor.user.userId,
        ],
      );

      await client.query(
        `INSERT INTO incident_events (organization_id, incident_id, actor_user_id, kind)
              VALUES ($1, $2, $3, 'created')`,
        [actor.organizationId, incidentId, actor.user.userId],
      );

      if (body.data.alert_ids?.length) {
        // Le rattachement est borné à l'organisation : passer l'identifiant
        // d'une alerte du voisin ne rattache rien, et RLS le garantit même si
        // ce WHERE était incomplet.
        const { rowCount } = await client.query(
          `UPDATE alerts SET incident_id = $2
            WHERE organization_id = $1 AND id = ANY($3::text[])`,
          [actor.organizationId, incidentId, body.data.alert_ids],
        );

        await client.query(
          `UPDATE incidents
              SET alert_count = $3,
                  first_alert_at = (SELECT min(occurred_at) FROM alerts
                                     WHERE organization_id = $1 AND incident_id = $2),
                  last_alert_at = (SELECT max(occurred_at) FROM alerts
                                    WHERE organization_id = $1 AND incident_id = $2)
            WHERE organization_id = $1 AND id = $2`,
          [actor.organizationId, incidentId, rowCount ?? 0],
        );
      }

      return true;
    });

    if (created) {
      await audit(actor, 'incident.created', { kind: 'incident', id: incidentId }, {
        severity: body.data.severity,
      }, request.ip);
    }

    reply.status(201);
    return { incident: { id: incidentId } };
  }));

  app.patch('/api/incidents/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'incident.write');
    const body = incidentPatchSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const incidentId = (request.params as { id: string }).id;

    const updated = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE incidents
            SET title = COALESCE($3, title),
                description = COALESCE($4, description),
                severity = COALESCE($5, severity),
                status = COALESCE($6, status),
                assigned_to = COALESCE($7, assigned_to),
                -- La contrainte incidents_resolved_consistency impose que
                -- resolved_at soit posé exactement quand le statut est final.
                resolved_at = CASE
                    WHEN $6 IN ('RESOLVED', 'CLOSED') THEN COALESCE(resolved_at, now())
                    WHEN $6 IS NOT NULL THEN NULL
                    ELSE resolved_at END,
                updated_at = now()
          WHERE organization_id = $1 AND id = $2`,
        [
          actor.organizationId,
          incidentId,
          body.data.title ?? null,
          body.data.description ?? null,
          body.data.severity ?? null,
          body.data.status ?? null,
          body.data.assigned_to ?? null,
        ],
      );

      if ((rowCount ?? 0) > 0 && body.data.status) {
        await client.query(
          `INSERT INTO incident_events (organization_id, incident_id, actor_user_id, kind, metadata)
                VALUES ($1, $2, $3, 'status_changed', $4)`,
          [actor.organizationId, incidentId, actor.user.userId, JSON.stringify({ to: body.data.status })],
        );
      }

      return (rowCount ?? 0) > 0;
    });

    if (!updated) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'incident.updated', { kind: 'incident', id: incidentId }, body.data, request.ip);
    return { status: 'ok' };
  }));

  // =========================================================================
  // Commandes vers les agents
  // =========================================================================

  app.post('/api/servers/:id/commands', handle(async (request, reply) => {
    const actor = await guard.require(request, 'command.issue');
    const body = issueCommandSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const serverId = (request.params as { id: string }).id;
    const commandId = `cmd_${newId('cmd').replace('cmd_', '')}`;

    const queued = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `INSERT INTO agent_commands (id, organization_id, server_id, type, payload,
                                     issued_by, expires_at)
         SELECT $1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7)
          WHERE EXISTS (SELECT 1 FROM servers
                         WHERE organization_id = $2 AND id = $3 AND deleted_at IS NULL)`,
        [
          commandId,
          actor.organizationId,
          serverId,
          body.data.type,
          JSON.stringify(body.data.payload ?? {}),
          actor.user.userId,
          body.data.ttl_seconds,
        ],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!queued) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'command.issued', { kind: 'server', id: serverId }, {
      command_id: commandId,
      type: body.data.type,
    }, request.ip);

    reply.status(202);
    // La commande est en file : l'agent la récupérera à son prochain poll.
    // L'allowlist finale est côté agent, et l'opérateur du serveur peut la
    // réduire encore : une commande acceptée ici peut être refusée là-bas, et
    // c'est une décision légitime, pas une erreur.
    return { command: { id: commandId, type: body.data.type, status: 'PENDING' } };
  }));

  app.get('/api/servers/:id/commands', handle(async (request) => {
    const actor = await guard.requireRead(request, 'server.read');
    const serverId = (request.params as { id: string }).id;

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, type, status, result, reason, created_at, sent_at,
                acknowledged_at, executed_at, duration_ms, delivery_count, expires_at
           FROM agent_commands
          WHERE organization_id = $1 AND server_id = $2
          ORDER BY created_at DESC LIMIT 50`,
        [actor.organizationId, serverId],
      );
      return { commands: rows };
    });
  }));

  // Multi-vue : demande d'observation serveur-autoritative d'un joueur. Émet une
  // commande `spectate_request` (ou `spectate_stop`) que l'agent applique en
  // plaçant une caméra d'administration DANS le monde du jeu. Aucune capture de
  // l'écran ni de la machine du joueur — le serveur reconstitue la scène.
  const spectateSchema = z
    .object({ identifier: z.string().min(1).max(128), stop: z.boolean().optional() })
    .strict();

  app.post('/api/servers/:id/spectate', handle(async (request, reply) => {
    const actor = await guard.require(request, 'command.issue');
    const body = spectateSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const serverId = (request.params as { id: string }).id;
    const commandId = `cmd_${newId('cmd').replace('cmd_', '')}`;
    const type = body.data.stop ? 'spectate_stop' : 'spectate_request';

    const queued = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `INSERT INTO agent_commands (id, organization_id, server_id, type, payload,
                                     issued_by, expires_at)
         SELECT $1, $2, $3, $4, $5, $6, now() + make_interval(secs => 300)
          WHERE EXISTS (SELECT 1 FROM servers
                         WHERE organization_id = $2 AND id = $3 AND deleted_at IS NULL)`,
        [
          commandId, actor.organizationId, serverId, type,
          JSON.stringify({ target: body.data.identifier, admin: actor.user.userId }),
          actor.user.userId,
        ],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!queued) { reply.status(404); return { error: 'not_found' }; }

    await audit(actor, 'spectate.requested', { kind: 'server', id: serverId }, {
      command_id: commandId, type, target: body.data.identifier,
    }, request.ip);

    reply.status(202);
    return { command: { id: commandId, type, status: 'PENDING' } };
  }));

  // =========================================================================
  // Audit et vue d'ensemble
  // =========================================================================

  app.get('/api/audit-logs', handle(async (request) => {
    const actor = await guard.requireRead(request, 'audit.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT a.id, a.action, a.actor_kind, a.actor_label, a.target_kind, a.target_id,
                a.metadata, a.created_at, u.email AS actor_email
           FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id
          WHERE a.organization_id = $1
          ORDER BY a.created_at DESC LIMIT 200`,
        [actor.organizationId],
      );
      return { entries: rows };
    });
  }));

  app.get('/api/overview', handle(async (request) => {
    const actor = await guard.requireRead(request, 'server.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT
            (SELECT count(*) FROM servers
              WHERE organization_id = $1 AND deleted_at IS NULL AND state = 'ONLINE') AS servers_online,
            (SELECT count(*) FROM servers
              WHERE organization_id = $1 AND deleted_at IS NULL AND state = 'OFFLINE') AS servers_offline,
            (SELECT count(*) FROM servers
              WHERE organization_id = $1 AND deleted_at IS NULL AND state = 'DEGRADED') AS servers_degraded,
            (SELECT COALESCE(sum(players_online), 0) FROM servers
              WHERE organization_id = $1 AND deleted_at IS NULL AND state = 'ONLINE') AS players_online,
            (SELECT count(*) FROM alerts
              WHERE organization_id = $1 AND status = 'OPEN') AS alerts_open,
            (SELECT count(*) FROM alerts
              WHERE organization_id = $1 AND status = 'OPEN' AND severity = 'CRITICAL') AS alerts_critical,
            (SELECT count(*) FROM incidents
              WHERE organization_id = $1 AND status NOT IN ('RESOLVED', 'CLOSED')) AS incidents_open`,
        [actor.organizationId],
      );
      return { overview: rows[0] ?? {} };
    });
  }));

  // =========================================================================
  // Protections natives (§08 game events, §10 state bags, §21 orchestrateur
  // OneSync, §15 niveaux de preuve, §17 réputation, §29 performance).
  //
  // Ce que le CŒUR anticheat empêche à la source, côté serveur. Le catalogue
  // (nom, posture, référence) décrit ce que Z-Shield applique ; les compteurs
  // « bloqué 24h » et les métriques de réputation/preuve/perf sont alimentés par
  // les agents connectés — 0 en l'absence d'agent, jamais une valeur inventée.
  // =========================================================================
  // Forme de l'instantané agrégé remonté par le cœur via l'agent.
  type LayerCounters = { blocked?: number; observed?: number; lockdown?: string };
  type ProtectionsSnapshot = {
    layers?: Record<string, LayerCounters>;
    evidence?: Record<string, number>;
    reputation?: Record<string, number>;
    performance?: { critical_ms?: number; budget_ms?: number; overhead_pct?: number };
    onesync_lockdown?: 'inactive' | 'relaxed' | 'strict';
  };

  const EVIDENCE_LABELS: Record<string, string> = {
    E0: 'Signal faible', E1: 'Signal', E2: 'Anomalie confirmée',
    E3: 'Recoupée', E4: 'Preuve solide', E5: 'Triche prouvée',
  };
  const LOCKDOWN_RANK: Record<string, number> = { inactive: 0, relaxed: 1, strict: 2 };

  // =========================================================================
  // Réglages de protections par serveur (catalogue + choix du client)
  // =========================================================================

  const protectionSettingsSchema = z.object({
    items: z
      .array(
        z.object({
          id: z.string(),
          enabled: z.boolean(),
          mode: z.enum(['watch', 'block']),
        }),
      )
      .max(500),
  });

  // Le catalogue fusionné avec les choix enregistrés pour un serveur.
  app.get('/api/servers/:id/protection-settings', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const serverId = (request.params as { id: string }).id;

    const result = await withTenant(pool, actor.organizationId, async (client) => {
      const server = await client.query(
        `SELECT id FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if (server.rowCount === 0) return null;
      const { rows } = await client.query<{ protection_id: string; enabled: boolean; mode: 'watch' | 'block' }>(
        `SELECT protection_id, enabled, mode FROM server_protection_settings
          WHERE organization_id = $1 AND server_id = $2`,
        [actor.organizationId, serverId],
      );
      return rows;
    });

    if (result === null) {
      reply.status(404);
      return { error: 'not_found' };
    }

    const saved = new Map(result.map((r) => [r.protection_id, r]));
    let active = 0;
    const categories = PROTECTION_CATALOG.map((cat) => ({
      id: cat.id,
      label: cat.label,
      items: cat.items.map((it) => {
        const s = saved.get(it.id);
        const enabled = s ? s.enabled : it.defaultEnabled;
        const mode = s ? s.mode : it.defaultMode;
        if (enabled) active += 1;
        return { id: it.id, name: it.name, description: it.description, enabled, mode };
      }),
    }));

    return { total: PROTECTION_COUNT, active, categories };
  }));

  // Enregistre les choix du client. Seuls les identifiants connus du catalogue
  // sont acceptés ; le reste est ignoré silencieusement.
  app.put('/api/servers/:id/protection-settings', handle(async (request, reply) => {
    const actor = await guard.require(request, 'configuration.write');
    const serverId = (request.params as { id: string }).id;

    const body = protectionSettingsSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const items = body.data.items.filter((i) => PROTECTION_BY_ID.has(i.id));

    const ok = await withTenant(pool, actor.organizationId, async (client) => {
      const server = await client.query(
        `SELECT id FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if (server.rowCount === 0) return false;

      for (const it of items) {
        await client.query(
          `INSERT INTO server_protection_settings
                 (organization_id, server_id, protection_id, enabled, mode, updated_at)
           VALUES ($1, $2, $3, $4, $5, now())
           ON CONFLICT (organization_id, server_id, protection_id)
           DO UPDATE SET enabled = EXCLUDED.enabled, mode = EXCLUDED.mode, updated_at = now()`,
          [actor.organizationId, serverId, it.id, it.enabled, it.mode],
        );
      }
      // Bump du config_version : l'agent redemandera sa config au prochain heartbeat.
      await client.query(
        `UPDATE servers SET config_version = config_version + 1, updated_at = now()
          WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, serverId],
      );
      return true;
    });

    if (!ok) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'protections.updated', { kind: 'server', id: serverId }, { changed: items.length }, request.ip);
    return { ok: true, changed: items.length };
  }));

  app.get('/api/protections', handle(async (request) => {
    const actor = await guard.requireRead(request, 'detection.read');

    // Compteurs live : dernier instantané par serveur, remonté par l'agent.
    // Agrégés sur toute l'organisation. Table absente → 0 (aucune valeur inventée).
    const snapshots = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ snapshot: ProtectionsSnapshot }>(
        `SELECT snapshot FROM server_protections WHERE organization_id = $1`,
        [actor.organizationId],
      );
      return rows.map((r) => r.snapshot ?? {});
    });

    // Agrégation multi-serveurs.
    const blocked = { game_events: 0, statebag: 0 };
    const evidenceCounts: Record<string, number> = { E0: 0, E1: 0, E2: 0, E3: 0, E4: 0, E5: 0 };
    const reputation: Record<string, number> = { ACTIVE: 0, DEGRADED: 0, OBSERVATION: 0, DISABLED: 0 };
    let lockdown: 'inactive' | 'relaxed' | 'strict' = 'inactive';
    let overheadSum = 0;
    let overheadN = 0;
    let budgetMs = 2;

    for (const snap of snapshots) {
      blocked.game_events += Number(snap.layers?.game_events?.blocked ?? 0);
      blocked.statebag += Number(snap.layers?.statebag?.blocked ?? 0);
      for (const level of Object.keys(evidenceCounts)) {
        evidenceCounts[level] = (evidenceCounts[level] ?? 0) + Number(snap.evidence?.[level] ?? 0);
      }
      for (const state of Object.keys(reputation)) {
        reputation[state] = (reputation[state] ?? 0) + Number(snap.reputation?.[state] ?? 0);
      }
      const snapLock = snap.onesync_lockdown ?? 'inactive';
      if ((LOCKDOWN_RANK[snapLock] ?? 0) > (LOCKDOWN_RANK[lockdown] ?? 0)) lockdown = snapLock;
      if (snap.performance?.overhead_pct != null) {
        overheadSum += Number(snap.performance.overhead_pct);
        overheadN += 1;
      }
      if (snap.performance?.budget_ms != null) budgetMs = Number(snap.performance.budget_ms);
    }

    const blockedFor = (id: string): number =>
      id === 'game_events' ? blocked.game_events : id === 'statebag' ? blocked.statebag : 0;

    const CATALOG = [
      { id: 'game_events', name: 'Blocage des triches à la source', ref: 'Prévention', posture: 'PREVENT' as const,
        summary: 'Explosions abusives, dégâts impossibles et objets illégaux bloqués avant même d’avoir lieu.' },
      { id: 'statebag', name: 'Protection des données du joueur', ref: 'Prévention', posture: 'PREVENT' as const,
        summary: 'Un joueur ne peut pas se donner de l’argent, le mode invincible ou les droits admin.' },
      { id: 'orchestrator', name: 'Verrouillage du serveur', ref: 'Prévention', posture: 'PREVENT' as const,
        summary: 'Empêche les joueurs de faire apparaître véhicules et objets qu’ils n’ont pas le droit de créer.' },
      { id: 'evidence', name: 'Contrôle des preuves', ref: 'Analyse', posture: 'DETECT' as const,
        summary: 'Une sanction lourde n’est jamais prise sur un simple doute : il faut une preuve solide.' },
      { id: 'reputation', name: 'Fiabilité des contrôles', ref: 'Analyse', posture: 'DETECT' as const,
        summary: 'Un contrôle qui se trompe trop souvent est mis de côté automatiquement.' },
      { id: 'performance', name: 'Impact sur les performances', ref: 'Confort', posture: 'ADVISORY' as const,
        summary: 'Z-Shield reste léger : le travail lourd s’efface pour laisser le serveur fluide.' },
    ];

    return {
      layers: CATALOG.map((l) => ({ ...l, status: 'ACTIVE' as const, blocked_24h: blockedFor(l.id) })),
      reputation: [] as unknown[],
      reputation_counts: reputation,
      evidence: Object.keys(evidenceCounts).map((level) => ({
        level, label: EVIDENCE_LABELS[level], count: evidenceCounts[level],
      })),
      performance: {
        critical_ms: 0,
        budget_ms: budgetMs,
        overhead_pct: overheadN > 0 ? overheadSum / overheadN : 0,
      },
      onesync_lockdown: lockdown,
    };
  }));

  app.get('/api/analytics/alerts-per-day', handle(async (request) => {
    const actor = await guard.requireRead(request, 'analytics.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      // Agrégation en base : renvoyer les lignes brutes et compter côté client
      // ne tient pas au-delà de quelques milliers d'alertes.
      const { rows } = await client.query(
        `SELECT date_trunc('day', created_at) AS day, severity, count(*)::int AS total
           FROM alerts
          WHERE organization_id = $1 AND created_at > now() - interval '30 days'
          GROUP BY 1, 2 ORDER BY 1`,
        [actor.organizationId],
      );
      return { series: rows };
    });
  }));

  // Détections par heure sur 24 h — pour un graphe temps réel (rafraîchi par le
  // websocket). Agrégation en base ; les heures sans détection sont renvoyées à 0
  // par une série générée, pour un tracé continu.
  app.get('/api/analytics/detections-per-hour', handle(async (request) => {
    const actor = await guard.requireRead(request, 'analytics.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ hour: string; total: number }>(
        `SELECT to_char(h.hour, 'YYYY-MM-DD"T"HH24:00:00Z') AS hour,
                COALESCE(d.total, 0)::int AS total
           FROM generate_series(
                  date_trunc('hour', now()) - interval '23 hours',
                  date_trunc('hour', now()),
                  interval '1 hour') AS h(hour)
           LEFT JOIN (
                SELECT date_trunc('hour', created_at) AS hour, count(*)::int AS total
                  FROM detections
                 WHERE organization_id = $1 AND created_at > now() - interval '24 hours'
                 GROUP BY 1
           ) d ON d.hour = h.hour
          ORDER BY h.hour`,
        [actor.organizationId],
      );
      return { series: rows };
    });
  }));

  // =========================================================================
  // Offre et quotas
  //
  // Aucun paiement réel : la spécification l'interdit sans le prestataire. Ce
  // qui existe est le modèle — plan, abonnement, quotas — et la consommation
  // réelle, qui est ce dont un client a besoin pour savoir s'il est à l'étroit.
  // =========================================================================

  // =========================================================================
  // Anticheat : détections, joueurs à risque, bannissements, règles, réglages
  //
  // Rappel de conception : ces endpoints exposent ce que le SERVEUR observe et
  // décide. Aucun ne renvoie de capture d'écran ni de flux : ces données
  // n'existent pas dans le système. Un bannissement est une entrée de registre
  // que l'agent applique côté serveur, pas une action que la plateforme
  // exécute sur un joueur.
  // =========================================================================

  const detectionQuerySchema = z
    .object({
      server_id: z.string().max(64).optional(),
      kind: z.string().max(32).optional(),
      disposition: z.enum(['OBSERVED', 'FLAGGED', 'KICKED', 'BANNED', 'DISMISSED']).optional(),
      player: z.string().max(128).optional(),
      limit: z.coerce.number().int().min(1).max(200).default(50),
    })
    .strict();

  app.get('/api/detections', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const query = detectionQuerySchema.safeParse(request.query);
    if (!query.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const filters = query.data;

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, server_id, player_identifier, player_name, kind, disposition,
                confidence, evidence, detector, occurred_at, created_at
           FROM detections
          WHERE organization_id = $1
            AND ($2::text IS NULL OR server_id = $2)
            AND ($3::detection_kind IS NULL OR kind = $3::detection_kind)
            AND ($4::detection_disposition IS NULL OR disposition = $4::detection_disposition)
            AND ($5::text IS NULL OR player_identifier = $5)
          ORDER BY created_at DESC
          LIMIT $6`,
        [
          actor.organizationId,
          filters.server_id ?? null,
          filters.kind ?? null,
          filters.disposition ?? null,
          filters.player ?? null,
          filters.limit,
        ],
      );
      return { detections: rows };
    });
  }));

  app.get('/api/players', handle(async (request) => {
    // Joueurs à risque : la vue player_threat agrège les détections en score.
    // Ce ne sont pas « tous les joueurs connectés » — le protocole ne les
    // transporte pas — mais ceux qui ont produit au moins une détection.
    const actor = await guard.requireRead(request, 'detection.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT player_identifier, player_name, detection_count, detections_24h,
                last_seen_at, threat_score
           FROM player_threat
          WHERE organization_id = $1
          ORDER BY threat_score DESC, last_seen_at DESC
          LIMIT 100`,
        [actor.organizationId],
      );
      return { players: rows };
    });
  }));

  app.get('/api/players/:identifier', handle(async (request) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const identifier = decodeURIComponent((request.params as { identifier: string }).identifier);

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows: threat } = await client.query(
        `SELECT player_identifier, player_name, detection_count, detections_24h,
                last_seen_at, threat_score
           FROM player_threat
          WHERE organization_id = $1 AND player_identifier = $2`,
        [actor.organizationId, identifier],
      );

      const { rows: recent } = await client.query(
        `SELECT id, server_id, kind, disposition, confidence, evidence, occurred_at, created_at
           FROM detections
          WHERE organization_id = $1 AND player_identifier = $2
          ORDER BY created_at DESC LIMIT 40`,
        [actor.organizationId, identifier],
      );

      const { rows: activeBan } = await client.query(
        `SELECT id, scope, reason, expires_at, created_at
           FROM bans
          WHERE organization_id = $1 AND identifier = $2 AND status = 'ACTIVE'
          LIMIT 1`,
        [actor.organizationId, identifier],
      );

      // --- Dossier « renseignement joueur » -------------------------------
      // Réputation, historique et liens, tous CALCULÉS à partir des données de
      // cette organisation. Pas de réseau inter-organisations fantôme : la
      // « réputation inter-serveurs » couvre les serveurs de cette organisation.

      // Historique complet des sanctions (tous statuts).
      const { rows: banHistory } = await client.query(
        `SELECT id, scope, reason, status, server_id, issued_by_auto, created_at, expires_at
           FROM bans
          WHERE organization_id = $1 AND identifier = $2
          ORDER BY created_at DESC LIMIT 20`,
        [actor.organizationId, identifier],
      );

      // Serveurs de l'organisation où cet identifiant a été vu (détections + bans).
      const { rows: serversSeen } = await client.query(
        `SELECT DISTINCT s.id, s.name
           FROM servers s
          WHERE s.organization_id = $1
            AND (s.id IN (SELECT server_id FROM detections
                           WHERE organization_id = $1 AND player_identifier = $2
                             AND server_id IS NOT NULL)
              OR s.id IN (SELECT server_id FROM bans
                           WHERE organization_id = $1 AND identifier = $2
                             AND server_id IS NOT NULL))`,
        [actor.organizationId, identifier],
      );

      // Comptes alternatifs possibles : MÊME pseudo sur un AUTRE identifiant.
      // Signal indicatif (à corréler), présenté comme tel — pas une preuve.
      const { rows: possibleAlts } = await client.query(
        `SELECT d.player_identifier, max(d.player_name) AS player_name,
                count(*)::int AS detections, max(d.created_at) AS last_seen
           FROM detections d
          WHERE d.organization_id = $1
            AND d.player_identifier <> $2
            AND d.player_name IS NOT NULL
            AND lower(d.player_name) = (
                  SELECT lower(player_name) FROM detections
                   WHERE organization_id = $1 AND player_identifier = $2
                     AND player_name IS NOT NULL
                   ORDER BY created_at DESC LIMIT 1)
          GROUP BY d.player_identifier
          ORDER BY last_seen DESC LIMIT 10`,
        [actor.organizationId, identifier],
      );

      // Score de confiance (0–100) : gravité agrégée + historique de sanctions.
      const base = Number(threat[0]?.threat_score ?? 0);
      const banBonus = Math.min(
        30,
        banHistory.filter((b) => b.status === 'ACTIVE' || b.status === 'KICKED').length * 12,
      );
      const confidence = Math.max(0, Math.min(100, Math.round(base + banBonus)));

      return {
        player: threat[0] ?? null,
        detections: recent,
        active_ban: activeBan[0] ?? null,
        dossier: {
          confidence,
          ban_history: banHistory,
          servers_seen: serversSeen,
          possible_alts: possibleAlts,
        },
      };
    });
  }));

  const banCreateSchema = z
    .object({
      scope: z.enum(['license', 'discord', 'steam', 'ip', 'fivem']),
      identifier: z.string().min(1).max(128),
      reason: z.string().min(1).max(400),
      server_id: z.string().max(64).nullable().optional(),
      detection_id: z.string().max(64).nullable().optional(),
      player_name: z.string().max(64).nullable().optional(),
      duration_days: z.number().int().min(1).max(3650).nullable().optional(),
      // File de revue : une sanction créée en attente ne bannit pas encore, elle
      // se tranche depuis le tableau de bord (confirmer / kick / faux positif).
      pending: z.boolean().optional(),
      risk: z.number().int().min(0).max(100).nullable().optional(),
      detection_category: z.string().max(40).nullable().optional(),
      detector: z.string().max(64).nullable().optional(),
      evidence_kind: z.enum(['clip', 'screenshot']).nullable().optional(),
    })
    .strict();

  app.get('/api/bans', handle(async (request) => {
    const actor = await guard.requireRead(request, 'ban.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT b.id, b.scope, b.identifier, b.player_name, b.reason, b.status,
                b.server_id, b.issued_by_auto, b.expires_at, b.created_at,
                b.risk, b.detection_category, b.detector, b.evidence_kind,
                b.reviewed_at,
                u.email AS issued_by_email
           FROM bans b LEFT JOIN users u ON u.id = b.issued_by
          WHERE b.organization_id = $1
          ORDER BY (b.status = 'PENDING') DESC, b.created_at DESC LIMIT 200`,
        [actor.organizationId],
      );
      return { bans: rows };
    });
  }));

  app.post('/api/bans', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const body = banCreateSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const banId = newId('ban');

    const pending = body.data.pending === true;
    const status = pending ? 'PENDING' : 'ACTIVE';

    const result = await withTenant(pool, actor.organizationId, async (client) => {
      if (pending) {
        // Une sanction en attente n'entre pas en conflit avec l'index unique
        // (réservé à ACTIVE) : plusieurs sanctions à revoir peuvent coexister.
        const { rows } = await client.query<{ id: string }>(
          `INSERT INTO bans (id, organization_id, server_id, scope, identifier,
                             player_name, reason, detection_id, issued_by, issued_by_auto,
                             status, risk, detection_category, detector, evidence_kind)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true,'PENDING',$10,$11,$12,$13)
           RETURNING id`,
          [
            banId, actor.organizationId, body.data.server_id ?? null, body.data.scope,
            body.data.identifier, body.data.player_name ?? null, body.data.reason,
            body.data.detection_id ?? null, actor.user.userId,
            body.data.risk ?? null, body.data.detection_category ?? null,
            body.data.detector ?? null, body.data.evidence_kind ?? null,
          ],
        );
        return rows[0]?.id ?? banId;
      }
      // Ré-bannir un identifiant déjà actif met à jour plutôt que d'empiler :
      // l'index unique partiel l'impose, on l'anticipe pour un message clair.
      const { rows } = await client.query<{ id: string }>(
        `INSERT INTO bans (id, organization_id, server_id, scope, identifier,
                           player_name, reason, detection_id, issued_by, issued_by_auto,
                           expires_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false,
                      CASE WHEN $10::int IS NULL THEN NULL
                           ELSE now() + make_interval(days => $10::int) END)
         ON CONFLICT (organization_id, scope, identifier, COALESCE(server_id, ''))
                     WHERE status = 'ACTIVE'
         DO UPDATE SET reason = EXCLUDED.reason,
                       expires_at = EXCLUDED.expires_at,
                       player_name = COALESCE(EXCLUDED.player_name, bans.player_name)
         RETURNING id`,
        [
          banId,
          actor.organizationId,
          body.data.server_id ?? null,
          body.data.scope,
          body.data.identifier,
          body.data.player_name ?? null,
          body.data.reason,
          body.data.detection_id ?? null,
          actor.user.userId,
          body.data.duration_days ?? null,
        ],
      );
      return rows[0]?.id ?? banId;
    });

    await audit(actor, pending ? 'ban.pending_created' : 'ban.created',
      { kind: 'ban', id: result }, {
        scope: body.data.scope,
        identifier: body.data.identifier,
      }, request.ip);

    reply.status(201);
    return { ban: { id: result, status } };
  }));

  app.post('/api/bans/:id/lift', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const banId = (request.params as { id: string }).id;
    const body = z.object({ reason: z.string().max(400).optional() }).strict().safeParse(request.body ?? {});

    const lifted = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE bans
            SET status = 'LIFTED', lifted_at = now(), lifted_by = $3,
                lifted_reason = $4
          WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE'`,
        [actor.organizationId, banId, actor.user.userId,
         (body.success ? body.data.reason : undefined) ?? null],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!lifted) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'ban.lifted', { kind: 'ban', id: banId }, {}, request.ip);
    return { status: 'ok' };
  }));

  // -------------------------------------------------------------------------
  // File de revue des sanctions en attente : confirmer / réduire en kick /
  // faux positif. Chaque décision consigne un retour dans detection_feedback,
  // que l'anticheat lit pour calibrer ses seuils.
  // -------------------------------------------------------------------------
  const reviewFeedback = async (
    client: { query: (sql: string, params?: unknown[]) => Promise<unknown> },
    actor: RequestActor,
    ban: { id: string; detector: string | null; scope: string; identifier: string; server_id: string | null },
    verdict: 'false_positive' | 'confirmed',
  ) => {
    if (!ban.detector) return; // Pas de détecteur ciblable (ban manuel) : rien à calibrer.
    await client.query(
      `INSERT INTO detection_feedback (id, organization_id, server_id, detector, scope,
                                       identifier, verdict, ban_id, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        newId('det'), actor.organizationId, ban.server_id, ban.detector,
        ban.scope, ban.identifier, verdict, ban.id, actor.user.userId,
      ],
    );
  };

  const loadPendingBan = async (
    client: {
      query: (
        sql: string,
        params?: unknown[],
      ) => Promise<{ rows: Array<Record<string, unknown>> }>;
    },
    organizationId: string,
    banId: string,
  ) => {
    const { rows } = await client.query(
      `SELECT id, detector, scope, identifier, server_id
         FROM bans WHERE organization_id = $1 AND id = $2 AND status = 'PENDING'`,
      [organizationId, banId],
    );
    return rows[0] as
      | { id: string; detector: string | null; scope: string; identifier: string; server_id: string | null }
      | undefined;
  };

  app.post('/api/bans/:id/confirm', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const banId = (request.params as { id: string }).id;
    const ok = await withTenant(pool, actor.organizationId, async (client) => {
      const ban = await loadPendingBan(client, actor.organizationId, banId);
      if (!ban) return false;
      await client.query(
        `UPDATE bans SET status = 'ACTIVE', reviewed_by = $3, reviewed_at = now()
          WHERE organization_id = $1 AND id = $2 AND status = 'PENDING'`,
        [actor.organizationId, banId, actor.user.userId],
      );
      await reviewFeedback(client, actor, ban, 'confirmed');
      return true;
    });
    if (!ok) { reply.status(404); return { error: 'not_found' }; }
    await audit(actor, 'ban.confirmed', { kind: 'ban', id: banId }, {}, request.ip);
    return { status: 'ok', ban_status: 'ACTIVE' };
  }));

  app.post('/api/bans/:id/kick', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const banId = (request.params as { id: string }).id;
    const ok = await withTenant(pool, actor.organizationId, async (client) => {
      const ban = await loadPendingBan(client, actor.organizationId, banId);
      if (!ban) return false;
      // Sanction réduite : l'agent expulse une fois, aucun ban persistant.
      await client.query(
        `UPDATE bans SET status = 'KICKED', reviewed_by = $3, reviewed_at = now()
          WHERE organization_id = $1 AND id = $2 AND status = 'PENDING'`,
        [actor.organizationId, banId, actor.user.userId],
      );
      // Une réduction en kick conforte tout de même la détection.
      await reviewFeedback(client, actor, ban, 'confirmed');
      return true;
    });
    if (!ok) { reply.status(404); return { error: 'not_found' }; }
    await audit(actor, 'ban.reduced_kick', { kind: 'ban', id: banId }, {}, request.ip);
    return { status: 'ok', ban_status: 'KICKED' };
  }));

  app.post('/api/bans/:id/false-positive', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const banId = (request.params as { id: string }).id;
    const ok = await withTenant(pool, actor.organizationId, async (client) => {
      const ban = await loadPendingBan(client, actor.organizationId, banId);
      if (!ban) return false;
      await client.query(
        `UPDATE bans SET status = 'DISMISSED', reviewed_by = $3, reviewed_at = now()
          WHERE organization_id = $1 AND id = $2 AND status = 'PENDING'`,
        [actor.organizationId, banId, actor.user.userId],
      );
      // Retour d'apprentissage : l'anticheat relèvera le seuil du détecteur.
      await reviewFeedback(client, actor, ban, 'false_positive');
      return true;
    });
    if (!ok) { reply.status(404); return { error: 'not_found' }; }
    await audit(actor, 'ban.false_positive', { kind: 'ban', id: banId }, {}, request.ip);
    return { status: 'ok', ban_status: 'DISMISSED' };
  }));

  app.get('/api/security-rules', handle(async (request) => {
    const actor = await guard.requireRead(request, 'rule.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, server_id, event_name, event_side, validation_kind,
                validation_params, action, status, hit_count, last_hit_at, created_at
           FROM security_rules
          WHERE organization_id = $1
          ORDER BY hit_count DESC, event_name`,
        [actor.organizationId],
      );
      return { rules: rows };
    });
  }));

  const ruleCreateSchema = z
    .object({
      event_name: z.string().min(1).max(128),
      event_side: z.enum(['server', 'client']).default('server'),
      validation_kind: z.enum(['bounds', 'ownership', 'rate', 'allowlist', 'none']).default('bounds'),
      validation_params: z.record(z.union([z.string().max(200), z.number(), z.boolean()])).default({}),
      action: z.enum(['LOG', 'BLOCK', 'FLAG', 'KICK']).default('LOG'),
      server_id: z.string().max(64).nullable().optional(),
    })
    .strict();

  app.post('/api/security-rules', handle(async (request, reply) => {
    const actor = await guard.require(request, 'rule.manage');
    const body = ruleCreateSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const ruleId = newId('rul');

    const created = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `INSERT INTO security_rules (id, organization_id, server_id, event_name,
                                     event_side, validation_kind, validation_params,
                                     action, created_by)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
          WHERE $3::text IS NULL OR EXISTS (
                SELECT 1 FROM servers WHERE organization_id = $2 AND id = $3 AND deleted_at IS NULL)
         ON CONFLICT (organization_id, COALESCE(server_id, ''), event_name) DO NOTHING`,
        [
          ruleId,
          actor.organizationId,
          body.data.server_id ?? null,
          body.data.event_name,
          body.data.event_side,
          body.data.validation_kind,
          JSON.stringify(body.data.validation_params),
          body.data.action,
          actor.user.userId,
        ],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!created) {
      reply.status(409);
      return { error: 'conflict', message: 'une règle existe déjà pour cet event' };
    }

    await audit(actor, 'rule.created', { kind: 'rule', id: ruleId }, {
      event: body.data.event_name,
    }, request.ip);

    reply.status(201);
    return { rule: { id: ruleId } };
  }));

  app.patch('/api/security-rules/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'rule.manage');
    const ruleId = (request.params as { id: string }).id;
    const body = z
      .object({
        action: z.enum(['LOG', 'BLOCK', 'FLAG', 'KICK']).optional(),
        status: z.enum(['ACTIVE', 'DISABLED', 'DRAFT']).optional(),
      })
      .strict()
      .safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    const updated = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE security_rules
            SET action = COALESCE($3, action),
                status = COALESCE($4, status),
                updated_at = now()
          WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, ruleId, body.data.action ?? null, body.data.status ?? null],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!updated) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'rule.updated', { kind: 'rule', id: ruleId }, body.data, request.ip);
    return { status: 'ok' };
  }));

  app.get('/api/servers/:id/anticheat', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const serverId = (request.params as { id: string }).id;

    return withTenant(pool, actor.organizationId, async (client) => {
      const owned = await client.query(
        `SELECT 1 FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if (!owned.rowCount) {
        reply.status(404);
        return { error: 'not_found' };
      }

      const { rows } = await client.query(
        `SELECT * FROM anticheat_settings WHERE organization_id = $1 AND server_id = $2`,
        [actor.organizationId, serverId],
      );
      // Défauts renvoyés par l'API quand rien n'a encore été enregistré : le
      // frontend ne doit pas dupliquer ces valeurs par défaut, sinon elles
      // divergent le jour où on les change. Source unique de vérité ici.
      const settings = rows[0] ?? {
        detect_teleport: true,
        detect_speed: true,
        detect_godmode: true,
        detect_noclip: true,
        detect_injected_event: true,
        detect_firerate: true,
        detect_entity_spam: true,
        max_ground_speed_kmh: 62,
        max_tick_distance_m: 45,
        max_fire_rate_rps: 12,
        auto_ban_enabled: false,
        auto_ban_threshold: 85,
        critical_action: 'kick_flag',
        default_ban_days: 30,
        onesync_lockdown: 'inactive',
        is_default: true,
      };
      return { settings };
    });
  }));

  const anticheatSettingsSchema = z
    .object({
      detect_teleport: z.boolean(),
      detect_speed: z.boolean(),
      detect_godmode: z.boolean(),
      detect_noclip: z.boolean(),
      detect_injected_event: z.boolean(),
      detect_firerate: z.boolean(),
      detect_entity_spam: z.boolean(),
      max_ground_speed_kmh: z.number().int().min(20).max(500),
      max_tick_distance_m: z.number().int().min(5).max(500),
      max_fire_rate_rps: z.number().int().min(1).max(100),
      auto_ban_enabled: z.boolean(),
      auto_ban_threshold: z.number().int().min(1).max(100),
      critical_action: z.enum(['ban', 'kick_flag', 'flag']),
      default_ban_days: z.number().int().min(1).max(3650).nullable().optional(),
      onesync_lockdown: z.enum(['inactive', 'relaxed', 'strict']).optional(),
    })
    .strict();

  // =========================================================================
  // Licences anticheat.
  //
  // La plateforme émet une licence SIGNÉE (HMAC-SHA256, même format et même secret
  // que le cœur) portant une date d'expiration. Le cœur la vérifie hors-ligne et
  // coupe la protection à l'échéance. L'essai gratuit dure 7 jours.
  // =========================================================================
  const PLAN_DAYS: Record<string, number> = { trial: 7, starter: 30, pro: 30, enterprise: 30 };

  // `binding` = empreinte du serveur (la clé ne marchera QUE là), ou 'any' (passe partout).
  function signLicense(binding: string, plan: string, days: number) {
    const issued = Math.floor(Date.now() / 1000);
    const expires = issued + days * 86400;
    const payload = `v1|${binding}|${plan}|${issued}|${expires}`;
    const token = `${payload}~${hmacSha256Hex(env().LICENSE_SIGNING_SECRET, payload)}`;
    return { token, plan, issued, expires };
  }

  // Empreinte : 16 caractères hex (ce que le cœur affiche au démarrage), ou 'any'.
  const fingerprintSchema = z.string().regex(/^([0-9a-f]{16}|any)$/, 'empreinte invalide');

  const licenseIssueSchema = z
    .object({
      plan: z.enum(['trial', 'starter', 'pro', 'enterprise']).default('trial'),
      server_fingerprint: fingerprintSchema.optional(),
    })
    .strict();

  app.post('/api/servers/:id/license', handle(async (request, reply) => {
    const actor = await guard.require(request, 'anticheat.configure');
    const serverId = (request.params as { id: string }).id;
    const parsed = licenseIssueSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const plan = parsed.data.plan;

    const outcome = await withTenant(pool, actor.organizationId, async (client) => {
      // Vérifie le serveur ET récupère son empreinte pour lier la licence
      // automatiquement (anti-partage), sauf si une empreinte est passée explicitement.
      const srv = await client.query<{ server_fingerprint: string | null }>(
        `SELECT server_fingerprint FROM servers
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if (srv.rowCount === 0) return null;

      const binding = parsed.data.server_fingerprint ?? srv.rows[0]?.server_fingerprint ?? 'any';
      const lic = signLicense(binding, plan, PLAN_DAYS[plan] ?? 7);

      await client.query(
        `INSERT INTO licenses (organization_id, server_id, token, plan, issued_at, expires_at, created_by)
           VALUES ($1, $2, $3, $4, to_timestamp($5), to_timestamp($6), $7)
         ON CONFLICT (organization_id, server_id) DO UPDATE SET
            token = EXCLUDED.token, plan = EXCLUDED.plan,
            issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at,
            created_by = EXCLUDED.created_by`,
        [actor.organizationId, serverId, lic.token, plan, lic.issued, lic.expires, actor.user.userId],
      );
      return { lic, bound: binding !== 'any' };
    });

    if (!outcome) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'license.issued', { kind: 'server', id: serverId },
      { plan, bound: outcome.bound }, request.ip);
    reply.status(201);
    return {
      token: outcome.lic.token, plan, bound: outcome.bound,
      expires_at: new Date(outcome.lic.expires * 1000).toISOString(),
    };
  }));

  app.get('/api/servers/:id/license', handle(async (request) => {
    const actor = await guard.requireRead(request, 'server.read');
    const serverId = (request.params as { id: string }).id;
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ token: string; plan: string; expires_at: string }>(
        `SELECT token, plan, expires_at FROM licenses
          WHERE organization_id = $1 AND server_id = $2`,
        [actor.organizationId, serverId],
      );
      const row = rows[0];
      if (!row) return { has_license: false };
      const expires = new Date(row.expires_at).getTime();
      const daysLeft = Math.max(0, Math.ceil((expires - Date.now()) / 86_400_000));
      return {
        has_license: true,
        plan: row.plan,
        token: row.token,
        expires_at: row.expires_at,
        days_left: daysLeft,
        expired: expires < Date.now(),
      };
    });
  }));

  // Générateur de licences autonome (panel admin du vendeur). Émet une clé signée sans
  // la rattacher à un serveur du compte : utile pour vendre à des clients externes qui
  // se contentent de coller la clé. `server_fingerprint` lie la clé à UN serveur.
  const licenseGenerateSchema = z
    .object({
      plan: z.enum(['trial', 'starter', 'pro', 'enterprise']).default('trial'),
      days: z.number().int().min(1).max(3650).optional(),
      server_fingerprint: fingerprintSchema.optional(),
    })
    .strict();

  app.post('/api/licenses/generate', handle(async (request, reply) => {
    const actor = await guard.require(request, 'billing.manage');
    const parsed = licenseGenerateSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation', message: parsed.error.issues[0]?.message };
    }
    const plan = parsed.data.plan;
    const days = parsed.data.days ?? (PLAN_DAYS[plan] ?? 7);
    const binding = parsed.data.server_fingerprint ?? 'any';
    const lic = signLicense(binding, plan, days);
    await audit(actor, 'license.generated', { kind: 'license', id: binding },
      { plan, days, bound: binding !== 'any' }, request.ip);
    return {
      token: lic.token, plan, days,
      bound: binding !== 'any',
      expires_at: new Date(lic.expires * 1000).toISOString(),
    };
  }));

  // =========================================================================
  // Console VENDEUR (admin plateforme).
  //
  // Vue transversale sur TOUS les clients et leurs serveurs, pour gérer les
  // licences. Réservée aux utilisateurs `is_platform_admin`. Utilise
  // withPlatformAdmin (politique permissive cross-org). Chaque client, lui,
  // garde son propre dashboard isolé (RLS) sur SON serveur.
  // =========================================================================

  // Vérifie que l'appelant est admin plateforme. Renvoie l'actor, ou pose 403.
  async function platformAdmin(request: FastifyRequest, reply: FastifyReply) {
    const actor = await guard.actor(request);
    const { rows } = await pool.query<{ is_platform_admin: boolean }>(
      `SELECT is_platform_admin FROM users WHERE id = $1`,
      [actor.user.userId],
    );
    if (rows[0]?.is_platform_admin !== true) {
      reply.status(403);
      return null;
    }
    return actor;
  }

  app.get('/api/admin/servers', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };

    const now = Date.now();
    const rows = await withPlatformAdmin(pool, async (client) => {
      const res = await client.query<{
        id: string; organization_id: string; organization_name: string;
        name: string; environment: string; state: string;
        last_heartbeat_at: string | null; players_online: number | null;
        server_fingerprint: string | null;
        license_plan: string | null; license_expires_at: string | null;
      }>(
        `SELECT s.id, s.organization_id, o.name AS organization_name,
                s.name, s.environment, s.state, s.last_heartbeat_at,
                s.players_online, s.server_fingerprint,
                l.plan AS license_plan, l.expires_at AS license_expires_at
           FROM servers s
           JOIN organizations o ON o.id = s.organization_id
           LEFT JOIN licenses l ON l.organization_id = s.organization_id AND l.server_id = s.id
          WHERE s.deleted_at IS NULL
          ORDER BY o.name, s.name`,
      );
      return res.rows;
    });

    const servers = rows.map((r) => {
      const expires = r.license_expires_at ? new Date(r.license_expires_at).getTime() : null;
      return {
        id: r.id,
        organization_id: r.organization_id,
        organization_name: r.organization_name,
        name: r.name,
        environment: r.environment,
        state: r.state,
        last_heartbeat_at: r.last_heartbeat_at,
        players_online: r.players_online,
        server_fingerprint: r.server_fingerprint,
        license: r.license_plan
          ? {
              plan: r.license_plan,
              expires_at: r.license_expires_at,
              days_left: expires ? Math.max(0, Math.ceil((expires - now) / 86_400_000)) : 0,
              expired: expires ? expires < now : true,
            }
          : null,
      };
    });
    return { servers };
  }));

  const adminLicenseSchema = z
    .object({
      plan: z.enum(['trial', 'starter', 'pro', 'enterprise']).default('trial'),
      days: z.number().int().min(1).max(3650).optional(),
    })
    .strict();

  app.post('/api/admin/servers/:id/license', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };

    const serverId = (request.params as { id: string }).id;
    const parsed = adminLicenseSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const plan = parsed.data.plan;
    const days = parsed.data.days ?? (PLAN_DAYS[plan] ?? 7);

    const outcome = await withPlatformAdmin(pool, async (client) => {
      const srv = await client.query<{ organization_id: string; server_fingerprint: string | null }>(
        `SELECT organization_id, server_fingerprint FROM servers
          WHERE id = $1 AND deleted_at IS NULL`,
        [serverId],
      );
      if (srv.rowCount === 0) return null;
      const orgId = srv.rows[0]!.organization_id;
      const binding = srv.rows[0]!.server_fingerprint ?? 'any';
      const lic = signLicense(binding, plan, days);

      await client.query(
        `INSERT INTO licenses (organization_id, server_id, token, plan, issued_at, expires_at, created_by)
           VALUES ($1, $2, $3, $4, to_timestamp($5), to_timestamp($6), $7)
         ON CONFLICT (organization_id, server_id) DO UPDATE SET
            token = EXCLUDED.token, plan = EXCLUDED.plan,
            issued_at = EXCLUDED.issued_at, expires_at = EXCLUDED.expires_at,
            created_by = EXCLUDED.created_by`,
        [orgId, serverId, lic.token, plan, lic.issued, lic.expires, actor.user.userId],
      );
      return { lic, bound: binding !== 'any' };
    });

    if (!outcome) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'admin.license.issued', { kind: 'server', id: serverId },
      { plan, days, bound: outcome.bound }, request.ip);
    reply.status(201);
    return {
      token: outcome.lic.token, plan, bound: outcome.bound,
      expires_at: new Date(outcome.lic.expires * 1000).toISOString(),
    };
  }));

  // Réglage rapide du verrouillage OneSync (§21), sans réécrire tous les réglages.
  const lockdownSchema = z.object({ mode: z.enum(['inactive', 'relaxed', 'strict']) }).strict();
  app.patch('/api/servers/:id/lockdown', handle(async (request, reply) => {
    const actor = await guard.require(request, 'anticheat.configure');
    const serverId = (request.params as { id: string }).id;
    const parsed = lockdownSchema.safeParse(request.body);
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const saved = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `INSERT INTO anticheat_settings (organization_id, server_id, onesync_lockdown, updated_by)
           SELECT $1, $2, $3, $4
            WHERE EXISTS (SELECT 1 FROM servers
                           WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL)
         ON CONFLICT (organization_id, server_id) DO UPDATE SET
            onesync_lockdown = EXCLUDED.onesync_lockdown,
            updated_by = EXCLUDED.updated_by, updated_at = now()`,
        [actor.organizationId, serverId, parsed.data.mode, actor.user.userId],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!saved) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'anticheat.lockdown', { kind: 'server', id: serverId },
      { mode: parsed.data.mode }, request.ip);
    return { ok: true, onesync_lockdown: parsed.data.mode };
  }));

  app.put('/api/servers/:id/anticheat', handle(async (request, reply) => {
    const actor = await guard.require(request, 'anticheat.configure');
    const serverId = (request.params as { id: string }).id;
    const body = anticheatSettingsSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const s = body.data;

    const saved = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `INSERT INTO anticheat_settings
           (organization_id, server_id, detect_teleport, detect_speed, detect_godmode,
            detect_noclip, detect_injected_event, detect_firerate, detect_entity_spam,
            max_ground_speed_kmh, max_tick_distance_m, max_fire_rate_rps,
            auto_ban_enabled, auto_ban_threshold, critical_action, default_ban_days,
            onesync_lockdown, updated_by)
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
          WHERE EXISTS (SELECT 1 FROM servers
                         WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL)
         ON CONFLICT (organization_id, server_id) DO UPDATE SET
            detect_teleport = EXCLUDED.detect_teleport,
            detect_speed = EXCLUDED.detect_speed,
            detect_godmode = EXCLUDED.detect_godmode,
            detect_noclip = EXCLUDED.detect_noclip,
            detect_injected_event = EXCLUDED.detect_injected_event,
            detect_firerate = EXCLUDED.detect_firerate,
            detect_entity_spam = EXCLUDED.detect_entity_spam,
            max_ground_speed_kmh = EXCLUDED.max_ground_speed_kmh,
            max_tick_distance_m = EXCLUDED.max_tick_distance_m,
            max_fire_rate_rps = EXCLUDED.max_fire_rate_rps,
            auto_ban_enabled = EXCLUDED.auto_ban_enabled,
            auto_ban_threshold = EXCLUDED.auto_ban_threshold,
            critical_action = EXCLUDED.critical_action,
            default_ban_days = EXCLUDED.default_ban_days,
            onesync_lockdown = EXCLUDED.onesync_lockdown,
            updated_by = EXCLUDED.updated_by,
            updated_at = now()`,
        [
          actor.organizationId, serverId,
          s.detect_teleport, s.detect_speed, s.detect_godmode, s.detect_noclip,
          s.detect_injected_event, s.detect_firerate, s.detect_entity_spam,
          s.max_ground_speed_kmh, s.max_tick_distance_m, s.max_fire_rate_rps,
          s.auto_ban_enabled, s.auto_ban_threshold, s.critical_action,
          s.default_ban_days ?? null, s.onesync_lockdown ?? 'inactive', actor.user.userId,
        ],
      );
      return (rowCount ?? 0) > 0;
    });

    if (!saved) {
      reply.status(404);
      return { error: 'not_found' };
    }

    await audit(actor, 'anticheat.configured', { kind: 'server', id: serverId }, {
      auto_ban: s.auto_ban_enabled,
    }, request.ip);
    return { status: 'ok' };
  }));

  app.get('/api/billing/subscription', handle(async (request) => {
    const actor = await guard.requireRead(request, 'billing.manage');

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows: subscription } = await client.query(
        `SELECT s.plan_code, s.state, s.trial_ends_at, s.current_period_end,
                p.name AS plan_name, p.monthly_cents, p.currency
           FROM subscriptions s JOIN plans p ON p.code = s.plan_code
          WHERE s.organization_id = $1`,
        [actor.organizationId],
      );

      // Les quotas effectifs : un override commercial de l'organisation prime
      // sur la valeur du plan, sans qu'il faille créer un plan sur mesure.
      const { rows: entitlements } = await client.query(
        `SELECT pe.key,
                COALESCE(e.int_value, pe.int_value) AS int_value,
                COALESCE(e.bool_value, pe.bool_value) AS bool_value,
                CASE WHEN e.key IS NULL THEN 'plan' ELSE 'override' END AS source
           FROM subscriptions s
           JOIN plan_entitlements pe ON pe.plan_code = s.plan_code
           LEFT JOIN entitlements e
                  ON e.organization_id = s.organization_id AND e.key = pe.key
          WHERE s.organization_id = $1
          ORDER BY pe.key`,
        [actor.organizationId],
      );

      const { rows: usage } = await client.query(
        `SELECT (SELECT count(*)::int FROM servers
                  WHERE organization_id = $1 AND deleted_at IS NULL) AS servers,
                (SELECT count(*)::int FROM memberships
                  WHERE organization_id = $1) AS users,
                (SELECT count(*)::int FROM alerts
                  WHERE organization_id = $1
                    AND created_at > now() - interval '30 days') AS alerts_30d`,
        [actor.organizationId],
      );

      return {
        subscription: subscription[0] ?? null,
        entitlements,
        usage: usage[0] ?? {},
      };
    });
  }));

  app.get('/api/csrf', handle(async (_request, reply) => {
    return { csrf_token: issueCsrfToken(reply, deps.isProduction) };
  }));

  void CSRF_HEADER;
}
