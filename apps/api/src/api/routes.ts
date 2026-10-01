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
import { newId, newOpaqueToken, hmacSha256Hex, hashToken, hashPassword, constantTimeEqual } from '../lib/crypto.ts';
import { env } from '../config/env.ts';
import { organizationChannel } from '../lib/redis.ts';
import {
  liveKey,
  heatmapKey,
  heatmapBucket,
  HEATMAP_BUCKET_SECONDS,
  HEATMAP_RETENTION_BUCKETS,
  HEATMAP_CELL_SIZE,
} from '../agent-gateway/service.ts';
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
  // Invitations — comptes multiples par organisation
  //
  // Un membre habilité (member.manage) invite quelqu'un par e-mail + rôle. On
  // génère un CODE opaque (jeton 32 octets), on n'en stocke que le hachage, et
  // on renvoie le code EN CLAIR une seule fois pour que l'admin le transmette
  // (lien /invite.html?code=...). L'invité crée SON compte avec ce code et
  // rejoint l'organisation avec le rôle prévu. Voir migration 0014 pour les
  // politiques RLS « par code » qui autorisent le parcours public.
  // =========================================================================

  const inviteRoleSchema = z.enum(['ADMIN', 'STAFF', 'VIEWER']);
  const inviteCreateSchema = z
    .object({ email: z.string().email().max(254), role: inviteRoleSchema.default('STAFF') })
    .strict();
  const inviteAcceptSchema = z
    .object({
      code: z.string().min(10).max(400),
      display_name: z.string().min(1).max(80),
      password: z.string().min(12).max(256),
    })
    .strict();
  const INVITE_TTL_DAYS = 7;

  app.get('/api/invitations', handle(async (request) => {
    const actor = await guard.requireRead(request, 'member.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, email, role, invited_by, created_at, expires_at, accepted_at
           FROM invitations WHERE organization_id = $1
          ORDER BY (accepted_at IS NULL) DESC, created_at DESC LIMIT 100`,
        [actor.organizationId],
      );
      return { invitations: rows };
    });
  }));

  app.post('/api/invitations', handle(async (request, reply) => {
    const actor = await guard.require(request, 'member.manage');
    const body = inviteCreateSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const code = newOpaqueToken();
    const id = newId('inv');
    const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 24 * 3600 * 1000);

    await withTenant(pool, actor.organizationId, async (client) => {
      // Ré-inviter la même adresse régénère le code et réarme l'expiration.
      await client.query(
        `INSERT INTO invitations (id, organization_id, email, role, token_hash, invited_by, expires_at)
              VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (organization_id, email) DO UPDATE
            SET role = EXCLUDED.role, token_hash = EXCLUDED.token_hash,
                invited_by = EXCLUDED.invited_by, expires_at = EXCLUDED.expires_at,
                accepted_at = NULL, created_at = now()`,
        [id, actor.organizationId, body.data.email, body.data.role, hashToken(code), actor.user.userId, expiresAt],
      );
    });

    await audit(actor, 'invitation.created', { kind: 'invitation', id },
      { email: body.data.email, role: body.data.role }, request.ip);
    reply.status(201);
    // Le code n'est renvoyé QU'ICI, une seule fois (seul son hachage est stocké).
    return { code, email: body.data.email, role: body.data.role, expires_at: expiresAt.toISOString() };
  }));

  app.delete('/api/invitations/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'member.manage');
    const id = (request.params as { id: string }).id;
    const done = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `DELETE FROM invitations WHERE organization_id = $1 AND id = $2 AND accepted_at IS NULL`,
        [actor.organizationId, id],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!done) {
      reply.status(404);
      return { error: 'not_found' };
    }
    await audit(actor, 'invitation.revoked', { kind: 'invitation', id }, {}, request.ip);
    return { status: 'ok' };
  }));

  // ---- Parcours PUBLIC (pas de session) : résoudre puis accepter un code -----

  app.get('/api/invitations/lookup', handle(async (request, reply) => {
    const code = (request.query as { code?: string }).code;
    if (!code || code.length < 10) {
      reply.status(400);
      return { valid: false, error: 'validation' };
    }
    const hashHex = hashToken(code).toString('hex');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      // hashHex est strictement hexadécimal (sortie d'un digest) : pas d'injection.
      await client.query(`SET LOCAL app.invite_code = '${hashHex}'`);
      const { rows } = await client.query<{
        organization_id: string; email: string; role: string;
        expires_at: string; accepted_at: string | null; organization_name: string;
      }>(
        `SELECT i.organization_id, i.email, i.role, i.expires_at, i.accepted_at,
                o.name AS organization_name
           FROM invitations i JOIN organizations o ON o.id = i.organization_id
          WHERE i.token_hash = decode($1, 'hex')`,
        [hashHex],
      );
      await client.query('COMMIT');
      const inv = rows[0];
      if (!inv) { reply.status(404); return { valid: false, error: 'not_found' }; }
      if (inv.accepted_at) return { valid: false, error: 'already_accepted' };
      if (new Date(inv.expires_at).getTime() < Date.now()) return { valid: false, error: 'expired' };
      return { valid: true, organization_name: inv.organization_name, email: inv.email, role: inv.role };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }));

  app.post('/api/invitations/accept', handle(async (request, reply) => {
    const body = inviteAcceptSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', field: body.error.issues[0]?.path.join('.') };
    }
    const hashHex = hashToken(body.data.code).toString('hex');
    const passwordHash = await hashPassword(body.data.password);

    const client = await pool.connect();
    let userId = '';
    let organizationId = '';
    try {
      await client.query('BEGIN');
      await client.query(`SET LOCAL app.invite_code = '${hashHex}'`);
      const inv = (
        await client.query<{
          id: string; organization_id: string; email: string; role: string;
          expires_at: string; accepted_at: string | null;
        }>(
          `SELECT id, organization_id, email, role, expires_at, accepted_at
             FROM invitations WHERE token_hash = decode($1, 'hex') FOR UPDATE`,
          [hashHex],
        )
      ).rows[0];

      if (!inv || inv.accepted_at || new Date(inv.expires_at).getTime() < Date.now()) {
        await client.query('ROLLBACK');
        reply.status(400);
        return { error: 'invalid_or_expired' };
      }
      organizationId = inv.organization_id;

      // Réutilise le compte si l'e-mail existe déjà (l'utilisateur rejoint une
      // organisation de plus) ; sinon crée le compte avec le mot de passe fourni.
      const existing = (
        await client.query<{ id: string }>(`SELECT id FROM users WHERE email = $1`, [inv.email])
      ).rows[0];
      if (existing) {
        userId = existing.id;
      } else {
        userId = newId('usr');
        await client.query(
          `INSERT INTO users (id, email, password_hash, display_name, email_verified_at)
                VALUES ($1, $2, $3, $4, now())`,
          [userId, inv.email, passwordHash, body.data.display_name],
        );
      }

      // Contexte tenant posé APRÈS résolution de l'organisation : membership,
      // MAJ de l'invitation et audit passent par la politique tenant normale.
      await client.query(`SET LOCAL app.organization_id = '${organizationId}'`);
      await client.query(
        `INSERT INTO memberships (id, organization_id, user_id, role, invited_by, accepted_at)
              VALUES ($1, $2, $3, $4, $5, now())
         ON CONFLICT (organization_id, user_id)
         DO UPDATE SET role = EXCLUDED.role, accepted_at = now()`,
        [newId('usr').replace('usr_', 'mem_'), organizationId, userId, inv.role, null],
      );
      await client.query(`UPDATE invitations SET accepted_at = now() WHERE id = $1`, [inv.id]);
      await client.query(
        `INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action, target_kind, target_id)
              VALUES ($1, $2, 'user', 'invitation.accepted', 'membership', $3)`,
        [organizationId, userId, inv.id],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    // Connexion immédiate : on ouvre une session sur l'organisation rejointe.
    const created = await auth.createSession({
      userId,
      mfaSatisfied: true,
      organizationId,
      ip: request.ip,
      userAgent: request.headers['user-agent'] ?? null,
    });
    reply.setCookie(SESSION_COOKIE, created.token, cookieOptions(deps.isProduction, SESSION_TTL));
    const csrf = issueCsrfToken(reply, deps.isProduction);
    reply.status(201);
    return { status: 'ok', csrf_token: csrf, organization_id: organizationId };
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

  // -------------------------------------------------------------------------
  // Build prête à déposer : un seul fichier .cfg, tout déjà rempli pour CE
  // serveur (identifiants d'agent frais + clé de licence + lignes de
  // durcissement), au lieu de 6 lignes à recopier depuis 2 écrans différents.
  //
  // Reprend EXACTEMENT les mêmes garanties que POST /credentials : le secret
  // d'agent est révoqué et régénéré à chaque appel, donc chaque téléchargement
  // invalide le précédent (voir commentaire plus haut). On le dit clairement
  // au client plutôt que de prétendre qu'on peut « re-télécharger » sans effet —
  // ce serait soit un mensonge, soit un secret stocké en clair, réversible.
  app.post('/api/servers/:id/build', handle(async (request, reply) => {
    const actor = await guard.require(request, 'credential.manage');
    const serverId = (request.params as { id: string }).id;

    const server = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ id: string; name: string }>(
        `SELECT id, name FROM servers
          WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      return rows[0] ?? null;
    });
    if (!server) { reply.status(404); return { error: 'not_found' }; }

    const licenseToken = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ token: string; expires_at: string }>(
        `SELECT token, expires_at FROM licenses WHERE organization_id = $1 AND server_id = $2`,
        [actor.organizationId, serverId],
      );
      const row = rows[0];
      if (!row) return null;
      if (new Date(row.expires_at).getTime() < Date.now()) return null;
      return row.token;
    });
    if (!licenseToken) {
      reply.status(409);
      return { error: 'no_license', message: 'Active d’abord une licence pour ce serveur (bouton « Activer »).' };
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

    await withTenant(pool, actor.organizationId, async (client) => {
      await client.query(
        `UPDATE api_credentials
            SET status = 'REVOKED', revoked_at = now(), revoked_by = $3,
                revoke_reason = 'replaced by a freshly generated build'
          WHERE organization_id = $1 AND server_id = $2 AND status <> 'REVOKED'`,
        [actor.organizationId, serverId, actor.user.userId],
      );
    });
    const issued = await credentials.issue({
      organizationId: actor.organizationId, serverId, agentId, createdBy: actor.user.userId,
    });

    const dashboardUrl = `${request.protocol}://${request.host}`;
    const cfg = [
      `# =============================================================================`,
      `# Z-Shield — build pour « ${server.name} », générée le ${new Date().toISOString().slice(0, 10)}`,
      `# À déposer dans ton server.cfg (ou : exec zshield-${serverId}.cfg), APRÈS ton`,
      `# framework (ESX/QBCore). Le secret ci-dessous n'est valable qu'UNE FOIS : un`,
      `# nouveau téléchargement en génère un autre et invalide celui-ci.`,
      `# =============================================================================`,
      ``,
      `set onesync on`,
      ``,
      `# --- Durcissement moteur FiveM (natif, recommandé) ---`,
      `setr sv_stateBagStrictMode true`,
      `set rateLimiter_netEvent_rate 50`,
      `set rateLimiter_netEvent_burst 200`,
      `set rateLimiter_netEventFlood_rate 75`,
      `set rateLimiter_netEventFlood_burst 300`,
      `set rateLimiter_stateBag_rate 75`,
      `set rateLimiter_stateBag_burst 125`,
      `set rateLimiter_stateBagFlood_rate 150`,
      `set rateLimiter_stateBagFlood_burst 175`,
      `set sv_filterRequestControl 2`,
      `sv_scriptHookAllowed false`,
      `set sv_endpointPrivacy true`,
      `set sv_enableNetworkedPhoneExplosions false`,
      ``,
      `# --- Identifiants d'agent (générés pour CE serveur) ---`,
      `set zshield_agent_id "${agentId}"`,
      `set zshield_server_id "${serverId}"`,
      `set zshield_key_id "${issued.keyId}"`,
      `set zshield_agent_secret "${issued.secret}"`,
      ``,
      `# --- Licence (liée à CE serveur) ---`,
      `set zshield_license_key "${licenseToken}"`,
      `set zshield_dashboard_url "${dashboardUrl}"`,
      ``,
      `# --- Démarrage (après avoir déposé les dossiers zshield-ac et zshield-agent`,
      `#     dans resources/, depuis le .zip téléchargé ci-dessus) ---`,
      `ensure zshield-agent`,
      `ensure zshield-ac`,
      ``,
    ].join('\n');

    await audit(actor, 'server.build_generated', { kind: 'server', id: serverId }, {
      key_id: issued.keyId,
    }, request.ip);

    reply.status(201);
    return {
      filename: `zshield-${serverId}.cfg`,
      cfg,
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
  // Vue live + captures du rendu de jeu
  // =========================================================================

  // Vue live : dernier instantané des joueurs (Redis, TTL court, jamais en SQL).
  // `live:false` = aucun instantané récent (agent éteint, `live.enabled` à false
  // dans la config de l'agent, ou serveur vide/hors ligne) : l'UI l'explique.
  app.get('/api/servers/:id/live', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'server.read');
    const serverId = (request.params as { id: string }).id;

    const exists = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `SELECT 1 FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!exists) { reply.status(404); return { error: 'not_found' }; }

    reply.header('Cache-Control', 'no-store');
    let raw: string | null = null;
    try { raw = await deps.publisher.get(liveKey(actor.organizationId, serverId)); } catch { raw = null; }
    if (!raw) return { live: false };
    try {
      const snap = JSON.parse(raw) as { at: number; sampled_at: number; players: unknown[] };
      return { live: true, age_ms: Math.max(0, Date.now() - snap.at), sampled_at: snap.sampled_at, players: snap.players };
    } catch {
      return { live: false };
    }
  }));

  // Heatmap : compteurs par case de grille (50 m), sur les ~30 dernières minutes.
  // Opt-in par organisation (`organizations.heatmap_enabled`) — désactivée par défaut,
  // séparément de `live.enabled` côté agent. Jamais de trajectoire individuelle :
  // seulement des compteurs additionnés, sans lien vers un joueur.
  app.get('/api/servers/:id/heatmap', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'server.read');
    const serverId = (request.params as { id: string }).id;

    const exists = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `SELECT 1 FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!exists) { reply.status(404); return { error: 'not_found' }; }

    const { rows } = await pool.query<{ heatmap_enabled: boolean }>(
      `SELECT heatmap_enabled FROM organizations WHERE id = $1`, [actor.organizationId]);
    if (rows[0]?.heatmap_enabled !== true) return { enabled: false, cells: [] };

    reply.header('Cache-Control', 'no-store');
    const now = heatmapBucket();
    const totals = new Map<string, number>();
    for (let i = 0; i < HEATMAP_RETENTION_BUCKETS; i++) {
      let hash: Record<string, string> = {};
      try { hash = await deps.publisher.hgetall(heatmapKey(actor.organizationId, serverId, now - i)); }
      catch { hash = {}; }
      for (const [field, value] of Object.entries(hash)) {
        totals.set(field, (totals.get(field) ?? 0) + (Number(value) || 0));
      }
    }

    const cells = Array.from(totals.entries()).map(([field, count]) => {
      const [gx, gy] = field.split(':').map(Number);
      return { gx, gy, count };
    });
    return {
      enabled: true,
      cell_size: HEATMAP_CELL_SIZE,
      window_seconds: HEATMAP_BUCKET_SECONDS * HEATMAP_RETENTION_BUCKETS,
      cells,
    };
  }));

  // Activer / désactiver la heatmap pour l'organisation (opt-in, comme le réseau de bans).
  app.post('/api/organization/heatmap-optin', handle(async (request, reply) => {
    const actor = await guard.require(request, 'server.write');
    const parsed = z.object({ enabled: z.boolean() }).strict().safeParse(request.body ?? {});
    if (!parsed.success) { reply.status(400); return { error: 'validation' }; }
    await pool.query(`UPDATE organizations SET heatmap_enabled = $2 WHERE id = $1`,
      [actor.organizationId, parsed.data.enabled]);
    await audit(actor, 'heatmap.optin', { kind: 'organization', id: actor.organizationId },
      { enabled: parsed.data.enabled }, request.ip);
    return { status: 'ok', enabled: parsed.data.enabled };
  }));

  // Demande de capture du RENDU DE JEU d'un joueur EN LIGNE (slot serveur). Crée une
  // ligne PENDING (hachage d'un jeton à usage unique) + une commande `capture_request`.
  // L'URL d'upload n'est construite qu'à la livraison à l'agent (jamais stockée).
  const captureSchema = z
    .object({
      slot: z.number().int().min(0).max(65535),
      identifier: z.string().max(128).optional(),
      name: z.string().max(64).optional(),
    })
    .strict();

  app.post('/api/servers/:id/capture', handle(async (request, reply) => {
    const actor = await guard.require(request, 'command.issue');
    const body = captureSchema.safeParse(request.body);
    if (!body.success) {
      reply.status(400);
      return { error: 'validation', message: body.error.issues[0]?.message };
    }
    const serverId = (request.params as { id: string }).id;
    const captureId = newId('cap');
    const commandId = newId('cmd');
    const token = newOpaqueToken();

    const outcome = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount: srv } = await client.query(
        `SELECT 1 FROM servers WHERE organization_id = $1 AND id = $2 AND deleted_at IS NULL`,
        [actor.organizationId, serverId],
      );
      if ((srv ?? 0) === 0) return 'not_found' as const;

      // Anti-abus : 6 demandes par minute et par membre.
      const { rows: recent } = await client.query<{ n: string }>(
        `SELECT count(*)::text AS n FROM evidence_captures
          WHERE organization_id = $1 AND requested_by = $2 AND created_at > now() - interval '1 minute'`,
        [actor.organizationId, actor.user.userId],
      );
      if (Number(recent[0]?.n ?? 0) >= 6) return 'rate_limited' as const;

      // Rétention : 30 jours, et au plus 300 captures par organisation.
      await client.query(
        `DELETE FROM evidence_captures
          WHERE organization_id = $1
            AND (created_at < now() - interval '30 days'
                 OR id IN (SELECT id FROM evidence_captures WHERE organization_id = $1
                            ORDER BY created_at DESC OFFSET 300))`,
        [actor.organizationId],
      );

      await client.query(
        `INSERT INTO evidence_captures
           (id, organization_id, server_id, target_slot, target_identifier, target_name,
            requested_by, command_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(secs => 300))`,
        [captureId, actor.organizationId, serverId, body.data.slot,
         body.data.identifier ?? null, body.data.name ?? null,
         actor.user.userId, commandId, hashToken(token)],
      );
      await client.query(
        `INSERT INTO agent_commands (id, organization_id, server_id, type, payload, issued_by, expires_at)
         VALUES ($1, $2, $3, 'capture_request', $4, $5, now() + make_interval(secs => 300))`,
        [commandId, actor.organizationId, serverId,
         JSON.stringify({ target: String(body.data.slot), capture_id: captureId, token,
                          admin: actor.user.userId }),
         actor.user.userId],
      );
      return 'ok' as const;
    });

    if (outcome === 'not_found') { reply.status(404); return { error: 'not_found' }; }
    if (outcome === 'rate_limited') { reply.status(429); return { error: 'rate_limited', message: 'Trop de captures demandées, réessaie dans une minute.' }; }

    await audit(actor, 'capture.requested', { kind: 'server', id: serverId }, {
      capture_id: captureId, slot: body.data.slot, identifier: body.data.identifier ?? null,
    }, request.ip);

    reply.status(202);
    return { capture: { id: captureId, status: 'PENDING' }, command: { id: commandId } };
  }));

  app.get('/api/servers/:id/captures', handle(async (request) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const serverId = (request.params as { id: string }).id;
    const q = request.query as { identifier?: string; limit?: string };
    const limit = Math.min(Math.max(Number(q.limit ?? 30) || 30, 1), 100);
    const identifier = typeof q.identifier === 'string' && q.identifier.length <= 128 ? q.identifier : null;

    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT c.id,
                CASE WHEN c.status = 'PENDING' AND c.expires_at <= now() THEN 'EXPIRED' ELSE c.status END AS status,
                c.target_slot, c.target_identifier, c.target_name, c.bytes, c.mime,
                c.created_at, c.received_at, u.display_name AS requested_by_name
           FROM evidence_captures c LEFT JOIN users u ON u.id = c.requested_by
          WHERE c.organization_id = $1 AND c.server_id = $2
            AND ($3::text IS NULL OR c.target_identifier = $3)
          ORDER BY c.created_at DESC LIMIT $4`,
        [actor.organizationId, serverId, identifier, limit],
      );
      return { captures: rows };
    });
  }));

  app.get('/api/captures/:id/image', handle(async (request, reply) => {
    const actor = await guard.requireRead(request, 'detection.read');
    const id = (request.params as { id: string }).id;
    if (!/^cap_[0-9a-z]{26}$/.test(id)) { reply.status(404); return { error: 'not_found' }; }

    const row = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ mime: string; image: Buffer }>(
        `SELECT mime, image FROM evidence_captures
          WHERE organization_id = $1 AND id = $2 AND status = 'RECEIVED'`,
        [actor.organizationId, id],
      );
      return rows[0] ?? null;
    });
    if (!row) { reply.status(404); return { error: 'not_found' }; }

    reply.header('Content-Type', row.mime);
    reply.header('Cache-Control', 'private, max-age=300');
    reply.header('Content-Security-Policy', "default-src 'none'; sandbox");
    reply.header('Content-Disposition', 'inline');
    return reply.send(row.image);
  }));

  app.delete('/api/captures/:id', handle(async (request, reply) => {
    const actor = await guard.require(request, 'command.issue');
    const id = (request.params as { id: string }).id;
    if (!/^cap_[0-9a-z]{26}$/.test(id)) { reply.status(404); return { error: 'not_found' }; }

    const removed = await withTenant(pool, actor.organizationId, async (client) => {
      const { rowCount } = await client.query(
        `DELETE FROM evidence_captures WHERE organization_id = $1 AND id = $2`,
        [actor.organizationId, id],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!removed) { reply.status(404); return { error: 'not_found' }; }

    await audit(actor, 'capture.deleted', { kind: 'capture', id }, {}, request.ip);
    reply.status(204);
    return null;
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

  // Synthèse analytique pour l'onglet Analytics : bans/jour (14 j), top détecteurs (30 j),
  // taux de faux positifs, et totaux. Tout est agrégé sous RLS (données de l'org).
  app.get('/api/analytics/summary', handle(async (request) => {
    const actor = await guard.requireRead(request, 'server.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const org = actor.organizationId;
      const bansPerDay = await client.query<{ day: string; total: number }>(
        `SELECT to_char(date_trunc('day', created_at), 'YYYY-MM-DD') AS day, count(*)::int AS total
           FROM bans WHERE organization_id = $1 AND created_at > now() - interval '14 days'
          GROUP BY 1 ORDER BY 1`,
        [org],
      );
      const topDetectors = await client.query<{ detector: string; total: number }>(
        `SELECT COALESCE(kind::text, 'inconnu') AS detector, count(*)::int AS total
           FROM detections WHERE organization_id = $1 AND created_at > now() - interval '30 days'
          GROUP BY 1 ORDER BY total DESC LIMIT 8`,
        [org],
      );
      const banStats = await client.query<{ total: string; active: string; dismissed: string }>(
        `SELECT count(*)::text AS total,
                count(*) FILTER (WHERE status = 'ACTIVE')::text AS active,
                count(*) FILTER (WHERE status = 'DISMISSED')::text AS dismissed
           FROM bans WHERE organization_id = $1`,
        [org],
      );
      const det30 = await client.query<{ total: string }>(
        `SELECT count(*)::text AS total FROM detections
          WHERE organization_id = $1 AND created_at > now() - interval '30 days'`,
        [org],
      );
      const totalBans = Number(banStats.rows[0]?.total ?? '0');
      const dismissed = Number(banStats.rows[0]?.dismissed ?? '0');
      return {
        bans_per_day: bansPerDay.rows,
        top_detectors: topDetectors.rows,
        totals: {
          bans_total: totalBans,
          bans_active: Number(banStats.rows[0]?.active ?? '0'),
          false_positives: dismissed,
          fp_rate: totalBans > 0 ? Math.round((dismissed / totalBans) * 100) : 0,
          detections_30d: Number(det30.rows[0]?.total ?? '0'),
        },
      };
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

    // Réseau de bans partagés : si l'org a opté pour le partage, contribue le HASH
    // de l'identifiant au pool anonyme (uniquement pour un ban ACTIF). Fire-and-forget.
    if (!pending) {
      void contributeSharedBan(actor.organizationId, body.data.identifier);
    }

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
      // Un ban ACTIVE existant pour le meme identifiant entrerait en conflit avec
      // l'index unique partiel (bans_active_identifier_idx) et ferait echouer
      // l'UPDATE ci-dessous avec une erreur Postgres brute (500 cote client). On
      // leve ce conflit nous-memes : l'ancien est leve (LIFTED), celui-ci devient
      // la sanction active en cours.
      await client.query(
        `UPDATE bans SET status = 'LIFTED'
          WHERE organization_id = $1 AND scope = $2 AND identifier = $3
            AND COALESCE(server_id, '') = COALESCE($4, '') AND status = 'ACTIVE'`,
        [actor.organizationId, ban.scope, ban.identifier, ban.server_id],
      );
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

  // =========================================================================
  // Appels de ban (contestation). Page publique -> revue admin.
  // =========================================================================
  const appealSubmitSchema = z
    .object({
      identifier: z.string().min(1).max(128),
      contact: z.string().max(200).optional(),
      message: z.string().min(1).max(2000),
    })
    .strict();
  // Anti-spam simple par IP (mémoire) : 1 appel / 60 s / IP.
  const appealLastByIp = new Map<string, number>();

  // PUBLIC : un joueur banni conteste (sans compte). On retrouve son ban actif le
  // plus récent (toutes orgs) et on crée l'appel dans l'org propriétaire. Réponse
  // générique dans tous les cas (anti-énumération : on ne révèle pas s'il est banni).
  app.post('/api/appeals', handle(async (request, reply) => {
    const parsed = appealSubmitSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const ip = request.ip;
    const now = Date.now();
    const last = appealLastByIp.get(ip) ?? 0;
    if (now - last < 60_000) {
      reply.status(429);
      return { status: 'received' }; // même forme que le succès : on ne détaille pas
    }
    appealLastByIp.set(ip, now);

    const { identifier, contact, message } = parsed.data;
    try {
      await withPlatformAdmin(pool, async (client) => {
        const ban = await client.query<{ id: string; organization_id: string }>(
          `SELECT id, organization_id FROM bans
            WHERE identifier = $1 AND status = 'ACTIVE'
            ORDER BY created_at DESC LIMIT 1`,
          [identifier],
        );
        if (ban.rowCount === 0) return; // pas de ban actif : on ne crée rien (réponse générique)
        await client.query(
          `INSERT INTO ban_appeals (organization_id, ban_id, identifier, contact, message, ip)
                VALUES ($1, $2, $3, $4, $5, $6)`,
          [ban.rows[0]!.organization_id, ban.rows[0]!.id, identifier, contact ?? null, message, ip],
        );
      });
    } catch (error) {
      logger.error('échec de soumission d’appel', {
        detail: error instanceof Error ? error.message : String(error),
      });
    }
    reply.status(202);
    return { status: 'received' };
  }));

  // ADMIN : liste des appels de l'organisation (en attente d'abord).
  app.get('/api/appeals', handle(async (request) => {
    const actor = await guard.requireRead(request, 'ban.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, ban_id, identifier, contact, message, status, created_at,
                resolved_at
           FROM ban_appeals
          WHERE organization_id = $1
          ORDER BY (status = 'PENDING') DESC, created_at DESC
          LIMIT 200`,
        [actor.organizationId],
      );
      return { appeals: rows };
    });
  }));

  // ADMIN : trancher un appel. approve -> lève le ban rattaché ; reject -> refus.
  const appealResolveSchema = z.object({ decision: z.enum(['approve', 'reject']) }).strict();
  app.post('/api/appeals/:id/resolve', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const appealId = (request.params as { id: string }).id;
    const parsed = appealResolveSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }
    const decision = parsed.data.decision;

    const result = await withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query<{ ban_id: string | null; status: string }>(
        `SELECT ban_id, status FROM ban_appeals
          WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [appealId, actor.organizationId],
      );
      const appeal = rows[0];
      if (!appeal) return { status: 404 as const };
      if (appeal.status !== 'PENDING') return { status: 409 as const };

      await client.query(
        `UPDATE ban_appeals SET status = $3, resolved_by = $4, resolved_at = now()
          WHERE id = $1 AND organization_id = $2`,
        [appealId, actor.organizationId, decision === 'approve' ? 'APPROVED' : 'REJECTED', actor.user.userId],
      );
      // Approuvé : on lève le ban rattaché (s'il est encore actif).
      if (decision === 'approve' && appeal.ban_id) {
        await client.query(
          `UPDATE bans SET status = 'LIFTED', lifted_at = now(), lifted_by = $3,
                  lifted_reason = 'appel de ban accepté'
            WHERE organization_id = $1 AND id = $2 AND status = 'ACTIVE'`,
          [actor.organizationId, appeal.ban_id, actor.user.userId],
        );
      }
      return { status: 200 as const, banId: appeal.ban_id };
    });

    if (result.status === 404) { reply.status(404); return { error: 'not_found' }; }
    if (result.status === 409) { reply.status(409); return { error: 'already_resolved' }; }
    await audit(actor, decision === 'approve' ? 'appeal.approved' : 'appeal.rejected',
      { kind: 'appeal', id: appealId }, {}, request.ip);
    return { status: 'ok', decision };
  }));

  // =========================================================================
  // Réseau de bans partagés (opt-in). On ne partage qu'un HASH salé de
  // l'identifiant + des compteurs agrégés — jamais l'identifiant brut, jamais
  // quel serveur l'a banni. C'est un SIGNAL, jamais un ban automatique.
  // =========================================================================
  const banHash = (identifier: string) =>
    hmacSha256Hex(env().LICENSE_SIGNING_SECRET, 'sharedban:' + identifier);

  async function orgSharesBans(orgId: string): Promise<boolean> {
    const { rows } = await pool.query<{ share_bans: boolean }>(
      `SELECT share_bans FROM organizations WHERE id = $1`, [orgId]);
    return rows[0]?.share_bans === true;
  }

  // Contribue un ban au pool anonyme (si l'org partage). Dédup par (hash, org).
  async function contributeSharedBan(orgId: string, identifier: string): Promise<void> {
    try {
      if (!(await orgSharesBans(orgId))) return;
      const h = banHash(identifier);
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const ins = await client.query(
          `INSERT INTO global_ban_reporters (identifier_hash, organization_id)
                VALUES ($1, $2) ON CONFLICT DO NOTHING`,
          [h, orgId],
        );
        const newReporter = (ins.rowCount ?? 0) > 0;
        await client.query(
          `INSERT INTO global_ban_signals (identifier_hash, org_count, report_count)
                VALUES ($1, 1, 1)
           ON CONFLICT (identifier_hash) DO UPDATE SET
                report_count = global_ban_signals.report_count + 1,
                org_count = global_ban_signals.org_count + CASE WHEN $2 THEN 1 ELSE 0 END,
                last_reported_at = now()`,
          [h, newReporter],
        );
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK'); throw e;
      } finally {
        client.release();
      }
    } catch (error) {
      logger.error('échec de contribution au réseau de bans', {
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  }

  // Statut opt-in de l'organisation.
  app.get('/api/network/status', handle(async (request) => {
    const actor = await guard.requireRead(request, 'ban.read');
    return { enabled: await orgSharesBans(actor.organizationId) };
  }));

  // Activer / désactiver le partage (réciprocité : partager pour voir les signaux).
  app.post('/api/network/optin', handle(async (request, reply) => {
    const actor = await guard.require(request, 'ban.manage');
    const parsed = z.object({ enabled: z.boolean() }).strict().safeParse(request.body ?? {});
    if (!parsed.success) { reply.status(400); return { error: 'validation' }; }
    await pool.query(`UPDATE organizations SET share_bans = $2 WHERE id = $1`,
      [actor.organizationId, parsed.data.enabled]);
    await audit(actor, 'network.optin', { kind: 'organization', id: actor.organizationId },
      { enabled: parsed.data.enabled }, request.ip);
    return { status: 'ok', enabled: parsed.data.enabled };
  }));

  // Signal réseau pour un identifiant. Réservé aux orgs opt-in (réciprocité).
  // Ne renvoie qu'un agrégat (nb d'orgs, nb de signalements), jamais qui.
  app.get('/api/network/check', handle(async (request) => {
    const actor = await guard.requireRead(request, 'ban.read');
    const q = z.object({ identifier: z.string().min(1).max(128) })
      .safeParse(request.query ?? {});
    if (!q.success) return { enabled: false, error: 'validation' };
    if (!(await orgSharesBans(actor.organizationId))) return { enabled: false };
    const { rows } = await pool.query<{ org_count: number; report_count: number; last_reported_at: string }>(
      `SELECT org_count, report_count, last_reported_at
         FROM global_ban_signals WHERE identifier_hash = $1`,
      [banHash(q.data.identifier)],
    );
    const row = rows[0];
    return {
      enabled: true,
      found: !!row,
      org_count: row?.org_count ?? 0,
      report_count: row?.report_count ?? 0,
      last_reported_at: row?.last_reported_at ?? null,
    };
  }));

  // =========================================================================
  // Marketplace de signatures (communautaire, modéré).
  //
  // Un serveur qui croise un nouveau cheat PROPOSE une signature. Un admin
  // plateforme MODÈRE. Les signatures approuvées sont diffusées ANONYMISÉES
  // (jamais l'org ni l'auteur) à tous les serveurs abonnés, qui les ajoutent à
  // leur config (injection.cheat_signatures). Aucune diffusion sans validation
  // humaine : une proposition erronée ne doit pas devenir un faux positif chez
  // tout le monde.
  // =========================================================================
  const signatureSubmitSchema = z.object({
    label: z.string().min(2).max(120),
    category: z.enum(['event', 'resource', 'entity', 'convar', 'pattern']),
    pattern: z.string().min(2).max(256),
    cheat_name: z.string().max(80).optional(),
    description: z.string().max(2000).optional(),
  }).strict();

  // Proposer une signature (réservé aux rôles qui configurent l'anticheat).
  app.post('/api/signatures', handle(async (request, reply) => {
    const actor = await guard.require(request, 'anticheat.configure');
    const parsed = signatureSubmitSchema.safeParse(request.body ?? {});
    if (!parsed.success) { reply.status(400); return { error: 'validation' }; }
    const d = parsed.data;
    const id = newId('sig');
    try {
      const done = await withTenant(pool, actor.organizationId, async (client) => {
        await client.query(
          `INSERT INTO signature_submissions
             (id, organization_id, submitted_by, label, category, pattern, cheat_name, description)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [id, actor.organizationId, actor.user.userId, d.label, d.category, d.pattern,
           d.cheat_name ?? null, d.description ?? null],
        );
        return true;
      });
      if (!done) { reply.status(500); return { error: 'insert_failed' }; }
    } catch (error) {
      // Violation d'unicité (org + catégorie + pattern) : déjà proposée.
      if (error && typeof error === 'object' && (error as { code?: string }).code === '23505') {
        reply.status(409);
        return { error: 'already_submitted' };
      }
      throw error;
    }
    await audit(actor, 'signature.submitted', { kind: 'signature', id },
      { category: d.category }, request.ip);
    reply.status(201);
    return { status: 'ok', id };
  }));

  // Mes propositions et leur statut (pending/approved/rejected).
  app.get('/api/signatures/mine', handle(async (request) => {
    const actor = await guard.requireRead(request, 'detection.read');
    return withTenant(pool, actor.organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT id, label, category, pattern, cheat_name, description, status,
                review_note, reviewed_at, created_at
           FROM signature_submissions
          WHERE organization_id = $1
          ORDER BY created_at DESC
          LIMIT 200`,
        [actor.organizationId],
      );
      return { submissions: rows };
    });
  }));

  // Flux des signatures APPROUVÉES, commun à tous les serveurs abonnés.
  // Anonymisé : on n'expose ni l'organisation ni l'auteur, seulement la
  // signature validée. C'est ce flux que les serveurs ajoutent à leur config.
  app.get('/api/signatures/approved', handle(async (request) => {
    await guard.requireRead(request, 'detection.read');
    const rows = await withPlatformAdmin(pool, async (client) => {
      const res = await client.query<{
        id: string; label: string; category: string; pattern: string;
        cheat_name: string | null; reviewed_at: string | null;
      }>(
        `SELECT id, label, category, pattern, cheat_name, reviewed_at
           FROM signature_submissions
          WHERE status = 'approved'
          ORDER BY reviewed_at DESC NULLS LAST
          LIMIT 1000`,
      );
      return res.rows;
    });
    return { signatures: rows };
  }));

  // ADMIN PLATEFORME : file de modération (par défaut, en attente d'abord).
  app.get('/api/admin/signatures', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };
    const status = String((request.query as { status?: string } | undefined)?.status ?? '');
    const rows = await withPlatformAdmin(pool, async (client) => {
      const res = await client.query(
        `SELECT s.id, s.organization_id, o.name AS organization_name,
                u.display_name AS submitter_name,
                s.label, s.category, s.pattern, s.cheat_name, s.description,
                s.status, s.review_note, s.reviewed_at, s.created_at
           FROM signature_submissions s
           JOIN organizations o ON o.id = s.organization_id
           LEFT JOIN users u ON u.id = s.submitted_by
          WHERE ($1 = '' OR s.status = $1)
          ORDER BY (s.status = 'pending') DESC, s.created_at DESC
          LIMIT 500`,
        [status],
      );
      return res.rows;
    });
    return { submissions: rows };
  }));

  // ADMIN PLATEFORME : trancher une proposition (approve / reject + note).
  const signatureReviewSchema = z.object({
    decision: z.enum(['approve', 'reject']),
    note: z.string().max(1000).optional(),
  }).strict();
  app.post('/api/admin/signatures/:id/review', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };
    const id = String((request.params as { id: string }).id ?? '');
    const parsed = signatureReviewSchema.safeParse(request.body ?? {});
    if (!parsed.success) { reply.status(400); return { error: 'validation' }; }
    const newStatus = parsed.data.decision === 'approve' ? 'approved' : 'rejected';
    const outcome = await withPlatformAdmin(pool, async (client) => {
      const { rows } = await client.query<{ status: string }>(
        `SELECT status FROM signature_submissions WHERE id = $1 FOR UPDATE`, [id]);
      if (rows.length === 0) return 404 as const;
      await client.query(
        `UPDATE signature_submissions
            SET status = $2, review_note = $3, reviewed_by = $4,
                reviewed_at = now(), updated_at = now()
          WHERE id = $1`,
        [id, newStatus, parsed.data.note ?? null, actor.user.userId],
      );
      return 200 as const;
    });
    if (outcome === 404) { reply.status(404); return { error: 'not_found' }; }
    await audit(actor, newStatus === 'approved' ? 'signature.approved' : 'signature.rejected',
      { kind: 'signature', id }, {}, request.ip);
    return { status: 'ok', decision: parsed.data.decision };
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

  // Vérifie une clé collée par le client (même format et même secret que
  // signLicense et que le cœur anticheat). Renvoie le contenu vérifié, ou null
  // si la signature est invalide, la structure incorrecte, ou la clé expirée.
  // La comparaison de signature est en temps constant (constantTimeEqual).
  function verifyLicenseKey(
    key: string,
  ): { binding: string; plan: string; issued: number; expires: number } | null {
    const raw = key.trim();
    const cut = raw.lastIndexOf('~');
    if (cut <= 0) return null;
    const payload = raw.slice(0, cut);
    const signature = raw.slice(cut + 1);
    if (!constantTimeEqual(signature, hmacSha256Hex(env().LICENSE_SIGNING_SECRET, payload))) {
      return null;
    }
    const parts = payload.split('|');
    if (parts.length !== 5 || parts[0] !== 'v1') return null;
    const [, binding, plan, issuedStr, expiresStr] = parts;
    const issued = Number(issuedStr);
    const expires = Number(expiresStr);
    if (!Number.isInteger(issued) || !Number.isInteger(expires)) return null;
    if (!['trial', 'starter', 'pro', 'enterprise'].includes(plan!)) return null;
    if (!/^([0-9a-f]{16}|any)$/.test(binding!)) return null;
    if (expires * 1000 <= Date.now()) return null; // clé expirée
    return { binding: binding!, plan: plan!, issued, expires };
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

  // -------------------------------------------------------------------------
  // Activation d'un compte par clé de licence.
  //
  // Parcours voulu : un nouvel utilisateur s'inscrit → son compte est VIDE
  // (aucun serveur). Il colle la clé de licence qu'on lui a vendue et son
  // premier serveur est créé pour lui, avec la licence rattachée. La clé est
  // vérifiée hors-ligne (signature HMAC + expiration) et ne peut servir qu'UNE
  // fois : une clé déjà activée sur un serveur est refusée (anti-partage).
  // -------------------------------------------------------------------------
  const activateSchema = z
    .object({
      license_key: z.string().min(1).max(512),
      server_name: z.string().min(1).max(120).optional(),
    })
    .strict();

  app.post('/api/activate', handle(async (request, reply) => {
    const actor = await guard.require(request, 'server.write');
    const parsed = activateSchema.safeParse(request.body ?? {});
    if (!parsed.success) {
      reply.status(400);
      return { error: 'validation' };
    }

    // 1) Vérifie la clé hors-ligne (signature + expiration). On ne révèle pas
    //    quelle partie a échoué : une clé invalide reste une clé invalide.
    const info = verifyLicenseKey(parsed.data.license_key);
    if (!info) {
      reply.status(422);
      return { error: 'invalid_license', message: 'Clé de licence invalide ou expirée.' };
    }
    const token = parsed.data.license_key.trim();

    // 2) Anti-partage : la même clé ne peut pas activer deux serveurs (même
    //    entre organisations différentes). Contrôle transversal en lecture.
    const alreadyUsed = await withPlatformAdmin(pool, async (client) => {
      const { rowCount } = await client.query(
        `SELECT 1 FROM licenses WHERE token = $1 LIMIT 1`,
        [token],
      );
      return (rowCount ?? 0) > 0;
    });
    if (alreadyUsed) {
      reply.status(409);
      return { error: 'license_in_use', message: 'Cette clé a déjà été activée sur un serveur.' };
    }

    const serverName = parsed.data.server_name?.trim() || 'Mon serveur FiveM';

    // 3) Rattache la licence, dans une seule transaction :
    //    - si le compte a déjà un serveur SANS licence (créé avant activation),
    //      on active CE serveur (pas de nouveau, pas de quota consommé) ;
    //    - sinon si le compte est vide, on crée son premier serveur ;
    //    - sinon (déjà un serveur licencié, quota atteint) on refuse proprement.
    const outcome = await withTenant(pool, actor.organizationId, async (client) => {
      const unlicensed = await client.query<{ id: string; name: string }>(
        `SELECT s.id, s.name FROM servers s
          WHERE s.organization_id = $1 AND s.deleted_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM licenses l
                             WHERE l.organization_id = s.organization_id AND l.server_id = s.id)
          ORDER BY s.created_at
          LIMIT 1`,
        [actor.organizationId],
      );

      let serverId: string;
      let name: string;
      let created = false;
      if (unlicensed.rowCount && unlicensed.rows[0]) {
        serverId = unlicensed.rows[0].id;
        name = unlicensed.rows[0].name;
      } else {
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

        serverId = newId('srv');
        name = serverName;
        created = true;
        await client.query(
          `INSERT INTO servers (id, organization_id, name, environment, created_by)
                VALUES ($1, $2, $3, 'production', $4)`,
          [serverId, actor.organizationId, name, actor.user.userId],
        );
      }

      // On stocke la clé TELLE QUELLE (le client l'a payée) avec son plan et sa
      // date d'expiration vérifiés, sans la re-signer. L'empreinte se remplira
      // au premier heartbeat de son serveur FiveM.
      await client.query(
        `INSERT INTO licenses (organization_id, server_id, token, plan, issued_at, expires_at, created_by)
              VALUES ($1, $2, $3, $4, to_timestamp($5), to_timestamp($6), $7)`,
        [actor.organizationId, serverId, token, info.plan, info.issued, info.expires, actor.user.userId],
      );

      return { exceeded: false as const, serverId, name, created };
    });

    if (outcome.exceeded) {
      reply.status(402);
      return { error: 'entitlement_exceeded', limit: outcome.allowed, used: outcome.used };
    }

    await audit(actor, 'account.activated', { kind: 'server', id: outcome.serverId },
      { plan: info.plan, bound: info.binding !== 'any', created: outcome.created }, request.ip);

    reply.status(201);
    return {
      status: 'ok',
      server: { id: outcome.serverId, name: outcome.name },
      plan: info.plan,
      bound: info.binding !== 'any',
      expires_at: new Date(info.expires * 1000).toISOString(),
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
        license_revoked_at: string | null; license_revoked_reason: string | null;
      }>(
        `SELECT s.id, s.organization_id, o.name AS organization_name,
                s.name, s.environment, s.state, s.last_heartbeat_at,
                s.players_online, s.server_fingerprint,
                l.plan AS license_plan, l.expires_at AS license_expires_at,
                l.revoked_at AS license_revoked_at, l.revoked_reason AS license_revoked_reason
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
              revoked: r.license_revoked_at != null,
              revoked_reason: r.license_revoked_reason,
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
            created_by = EXCLUDED.created_by,
            revoked_at = NULL, revoked_reason = NULL, revoked_by = NULL`,
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

  // Révocation (kill-switch) : marque la licence d'un serveur comme révoquée.
  // Le verdict signé servi à l'anticheat (/api/license/verify) la coupera à
  // distance. Réservé à l'admin plateforme.
  const revokeSchema = z.object({ reason: z.string().max(200).optional() }).strict();
  app.post('/api/admin/servers/:id/license/revoke', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };
    const serverId = (request.params as { id: string }).id;
    const parsed = revokeSchema.safeParse(request.body ?? {});
    const reason = parsed.success ? (parsed.data.reason ?? null) : null;

    const ok = await withPlatformAdmin(pool, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE licenses SET revoked_at = now(), revoked_reason = $2, revoked_by = $3
          WHERE server_id = $1`,
        [serverId, reason, actor.user.userId],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!ok) {
      reply.status(404);
      return { error: 'not_found', message: 'Aucune licence sur ce serveur.' };
    }
    await audit(actor, 'admin.license.revoked', { kind: 'server', id: serverId },
      { reason }, request.ip);
    return { status: 'ok', revoked: true };
  }));

  // Rétablit une licence révoquée (remboursement annulé, faux positif…).
  app.post('/api/admin/servers/:id/license/restore', handle(async (request, reply) => {
    const actor = await platformAdmin(request, reply);
    if (!actor) return { error: 'forbidden' };
    const serverId = (request.params as { id: string }).id;

    const ok = await withPlatformAdmin(pool, async (client) => {
      const { rowCount } = await client.query(
        `UPDATE licenses SET revoked_at = NULL, revoked_reason = NULL, revoked_by = NULL
          WHERE server_id = $1`,
        [serverId],
      );
      return (rowCount ?? 0) > 0;
    });
    if (!ok) {
      reply.status(404);
      return { error: 'not_found', message: 'Aucune licence sur ce serveur.' };
    }
    await audit(actor, 'admin.license.restored', { kind: 'server', id: serverId }, {}, request.ip);
    return { status: 'ok', revoked: false };
  }));

  // -------------------------------------------------------------------------
  // Verdict de licence EN LIGNE (kill-switch) — endpoint PUBLIC interrogé par
  // l'anticheat. Renvoie un verdict SIGNÉ (même secret que les licences) :
  //   "lv1|<empreinte>|<active|revoked>|<issued_at>~<hmac_hex>"
  // Le cœur (server/license_online.lua) le vérifie et coupe à distance une clé
  // révoquée. Pas de session requise : l'agent n'a pas de session utilisateur.
  // On ne révèle rien de sensible — seulement actif/révoqué pour une empreinte.
  // -------------------------------------------------------------------------
  function signVerdict(serverId: string, status: 'active' | 'revoked') {
    const issued = Math.floor(Date.now() / 1000);
    const payload = `lv1|${serverId}|${status}|${issued}`;
    return `${payload}~${hmacSha256Hex(env().LICENSE_SIGNING_SECRET, payload)}`;
  }
  const verifyQuerySchema = z.object({
    server: z.string().regex(/^[0-9a-f]{16}$/).optional(),
    fingerprint: z.string().regex(/^[0-9a-f]{16}$/).optional(),
  });
  app.get('/api/license/verify', handle(async (request, reply) => {
    const q = verifyQuerySchema.safeParse(request.query ?? {});
    const fp = q.success ? (q.data.server ?? q.data.fingerprint) : undefined;
    if (!fp) {
      reply.status(400);
      return { error: 'validation', message: 'Paramètre server (empreinte 16 hex) requis.' };
    }
    // Recherche transversale par empreinte : on lit l'état de révocation de la
    // licence du serveur portant cette empreinte.
    const row = await withPlatformAdmin(pool, async (client) => {
      const res = await client.query<{ revoked_at: string | null }>(
        `SELECT l.revoked_at
           FROM servers s
           JOIN licenses l ON l.organization_id = s.organization_id AND l.server_id = s.id
          WHERE s.server_fingerprint = $1 AND s.deleted_at IS NULL
          LIMIT 1`,
        [fp],
      );
      return res.rows[0] ?? null;
    });
    // Empreinte inconnue ou non révoquée -> verdict actif (la coupe à
    // l'expiration reste gérée hors-ligne par le cœur). Révoquée -> verdict
    // révoqué, collant côté cœur.
    const status: 'active' | 'revoked' = row && row.revoked_at != null ? 'revoked' : 'active';
    reply.header('Cache-Control', 'no-store');
    return { verdict: signVerdict(fp, status), status };
  }));

  // Offres publiques (onglet Tarifs). Renvoie les plans visibles + leurs quotas,
  // pour un affichage honnête (mêmes chiffres que ceux réellement appliqués).
  app.get('/api/plans', handle(async (request) => {
    await guard.actor(request); // session valide requise, aucune donnée sensible
    const { rows: plans } = await pool.query<{
      code: string; name: string; monthly_cents: number; currency: string;
    }>(
      `SELECT code, name, monthly_cents, currency FROM plans
        WHERE is_public = true AND code <> 'free'
        ORDER BY monthly_cents`,
    );
    const { rows: ents } = await pool.query<{
      plan_code: string; key: string; int_value: string | null; bool_value: boolean | null;
    }>(
      `SELECT plan_code, key, int_value, bool_value FROM plan_entitlements
        WHERE plan_code IN (SELECT code FROM plans WHERE is_public = true AND code <> 'free')`,
    );
    const byPlan: Record<string, Record<string, number | boolean | null>> = {};
    for (const e of ents) {
      (byPlan[e.plan_code] ??= {})[e.key] =
        e.int_value != null ? Number(e.int_value) : e.bool_value;
    }
    return {
      plans: plans.map((p) => ({
        code: p.code,
        name: p.name,
        monthly_cents: p.monthly_cents,
        currency: p.currency,
        entitlements: byPlan[p.code] ?? {},
      })),
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