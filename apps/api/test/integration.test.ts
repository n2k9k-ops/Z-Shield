/**
 * Tests d'intégration : isolation multi-tenant au niveau HTTP, et chaîne
 * complète de la passerelle agent.
 *
 * Ces tests passent par `app.inject()`, donc par le routage réel, les gardes
 * réelles, PostgreSQL réel avec RLS active et Redis réel. Un test d'isolation
 * qui appellerait directement les fonctions internes ne prouverait rien sur ce
 * que voit un vrai client.
 *
 * Prérequis (sinon la suite est ignorée, pas déclarée verte) :
 *   - PostgreSQL joignable, migrations appliquées ;
 *   - Redis joignable ;
 *   - TEST_DATABASE_URL (rôle applicatif, NOBYPASSRLS) ;
 *   - TEST_DATABASE_ADMIN_URL (rôle propriétaire, pour le nettoyage) ;
 *   - TEST_REDIS_URL.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { after, before, describe, it } from 'node:test';
import { Pool } from 'pg';
import type { FastifyInstance } from 'fastify';

import { buildApp } from '../src/app.ts';
import { createPool } from '../src/lib/db.ts';
import { createRedis, type RedisBundle } from '../src/lib/redis.ts';
import { createLogger } from '../src/lib/logger.ts';
import { hmacSha256Hex, sha256Hex } from '../src/lib/crypto.ts';
import { canonicalRequest } from '../src/agent-gateway/protocol.ts';

const APP_URL = process.env.TEST_DATABASE_URL;
const ADMIN_URL = process.env.TEST_DATABASE_ADMIN_URL;
const REDIS_URL = process.env.TEST_REDIS_URL;

const available = Boolean(APP_URL && ADMIN_URL && REDIS_URL);

describe('isolation multi-tenant et passerelle agent', { skip: !available }, () => {
  let app: FastifyInstance;
  let pool: Pool;
  let admin: Pool;
  let redis: RedisBundle;

  interface Tenant {
    email: string;
    cookie: string;
    csrf: string;
    organizationId: string;
    serverId: string;
  }

  let acme: Tenant;
  let globex: Tenant;

  // ---------------------------------------------------------------------------
  // Utilitaires
  // ---------------------------------------------------------------------------

  const cookieFrom = (headers: Record<string, unknown>): string => {
    const raw = headers['set-cookie'];
    const list = Array.isArray(raw) ? raw : [String(raw)];
    const session = list.find((entry) => entry.startsWith('zshield_session='));
    assert.ok(session, 'aucun cookie de session émis');
    return session.split(';')[0]!;
  };

  async function createTenant(label: string): Promise<Tenant> {
    const email = `${label}-${randomBytes(4).toString('hex')}@example.test`;
    const password = 'development-password-1';

    const registered = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email,
        password,
        display_name: `${label} owner`,
        organization_name: `${label} ${randomBytes(2).toString('hex')}`,
      },
    });
    assert.equal(registered.statusCode, 202);

    const loggedIn = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email, password },
    });
    assert.equal(loggedIn.statusCode, 200);

    const body = loggedIn.json() as { csrf_token: string; organization_id: string };
    const cookie = cookieFrom(loggedIn.headers as Record<string, unknown>);

    const created = await app.inject({
      method: 'POST',
      url: '/api/servers',
      headers: {
        cookie: `${cookie}; zshield_csrf=${body.csrf_token}`,
        'x-csrf-token': body.csrf_token,
      },
      payload: { name: `${label} main`, environment: 'production' },
    });
    assert.equal(created.statusCode, 201, `création de serveur : ${created.body}`);

    return {
      email,
      cookie,
      csrf: body.csrf_token,
      organizationId: body.organization_id,
      serverId: (created.json() as { server: { id: string } }).server.id,
    };
  }

  /**
   * En-têtes d'un client authentifié.
   *
   * Le cookie de session ET le cookie CSRF doivent tenir dans le MÊME en-tête
   * Cookie : l'option `cookies` d'app.inject remplace l'en-tête au lieu de
   * fusionner avec lui, ce qui ferait disparaître la session.
   */
  const asTenant = (tenant: Tenant) => ({
    headers: {
      cookie: `${tenant.cookie}; zshield_csrf=${tenant.csrf}`,
      'x-csrf-token': tenant.csrf,
    },
  });

  before(async () => {
    pool = createPool({ connectionString: APP_URL!, max: 5 });
    admin = new Pool({ connectionString: ADMIN_URL! });
    redis = createRedis(REDIS_URL!);

    // Contrôle préalable avec délai court. Sans lui, un Redis ou un Postgres
    // absent fait attendre la suite indéfiniment : ioredis retente sans fin et
    // le pool attend sa connexion. Un job d'intégration qui pend est pire
    // qu'un job qui échoue — personne ne sait s'il travaille ou s'il est mort.
    const preflight = async (label: string, probe: Promise<unknown>) => {
      const timeout = new Promise((_resolve, reject) => {
        setTimeout(() => reject(new Error(`${label} injoignable après 5 s`)), 5_000).unref();
      });
      await Promise.race([probe, timeout]);
    };

    await preflight('PostgreSQL (rôle applicatif)', pool.query('SELECT 1'));
    await preflight('PostgreSQL (rôle propriétaire)', admin.query('SELECT 1'));
    await preflight('Redis', redis.commands.ping());

    // Table rase. Sous le rôle propriétaire : le rôle applicatif n'a
    // volontairement pas le privilège TRUNCATE.
    await admin.query(`
      TRUNCATE alerts, telemetry_samples, agent_commands, incident_events, incidents,
               api_credentials, agents, servers, audit_logs, sessions, memberships,
               invitations, subscriptions, organizations, mfa_factors, users
        RESTART IDENTITY CASCADE
    `);
    await redis.commands.flushdb();

    app = await buildApp({
      pool,
      redis,
      logger: createLogger('error', { service: 'test' }),
      config: {
        credentialKey: randomBytes(32),
        sessionSecret: randomBytes(48).toString('base64url'),
        clockSkewSeconds: 300,
        nonceTtlSeconds: 900,
        agentRateLimitPerMinute: 10_000,
        corsOrigins: ['http://localhost:3000'],
        isProduction: false,
        logLevel: 'error',
      },
    });

    acme = await createTenant('acme');
    globex = await createTenant('globex');
  });

  after(async () => {
    await app?.close();
    await pool?.end();
    await admin?.end();
    await redis?.close();
  });

  // ---------------------------------------------------------------------------
  // Lecture
  // ---------------------------------------------------------------------------

  it('la connexion Discord désactivée renvoie honnêtement vers /login', async () => {
    // Par défaut DISCORD_LOGIN_ENABLED est faux : le bouton ne doit jamais
    // ouvrir un aller-retour cassé, mais rediriger vers l'écran de connexion
    // avec un motif explicite.
    const response = await app.inject({
      method: 'GET',
      url: '/api/auth/discord/start',
      headers: { referer: 'http://localhost:3000/login' },
    });
    assert.equal(response.statusCode, 302);
    assert.match(response.headers.location as string, /\/login\?e=discord_unavailable$/);
  });

  it('chaque organisation ne voit que ses propres serveurs', async () => {
    for (const tenant of [acme, globex]) {
      const response = await app.inject({
        method: 'GET',
        url: '/api/servers',
        headers: { cookie: tenant.cookie },
      });
      assert.equal(response.statusCode, 200);

      const { servers } = response.json() as { servers: Array<{ id: string }> };
      assert.equal(servers.length, 1);
      assert.equal(servers[0]!.id, tenant.serverId);
    }
  });

  it("une alerte d'une organisation est invisible pour l'autre", async () => {
    // Insertion directe, comme le ferait la passerelle agent.
    await admin.query(
      `INSERT INTO alerts (id, organization_id, server_id, agent_alert_id, severity,
                           category, summary, occurred_at)
            VALUES ($1, $2, $3, 'secret-1', 'CRITICAL', 'movement',
                    'Alerte confidentielle de Globex', now())`,
      [`al_${randomBytes(13).toString('hex')}`, globex.organizationId, globex.serverId],
    );

    const mine = await app.inject({
      method: 'GET',
      url: '/api/alerts',
      headers: { cookie: globex.cookie },
    });
    assert.equal((mine.json() as { alerts: unknown[] }).alerts.length, 1);

    const theirs = await app.inject({
      method: 'GET',
      url: '/api/alerts',
      headers: { cookie: acme.cookie },
    });
    assert.equal(theirs.statusCode, 200);
    assert.equal((theirs.json() as { alerts: unknown[] }).alerts.length, 0);
  });

  it('filtrer sur le server_id du voisin ne renvoie rien', async () => {
    const response = await app.inject({
      method: 'GET',
      url: `/api/alerts?server_id=${globex.serverId}`,
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);
    assert.equal((response.json() as { alerts: unknown[] }).alerts.length, 0);
  });

  it("le journal d'audit reste cloisonné", async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/audit-logs',
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);

    const { entries } = response.json() as { entries: Array<{ target_id: string | null }> };
    assert.ok(entries.length > 0, "le journal d'audit d'Acme devrait contenir ses propres actions");
    for (const entry of entries) {
      assert.notEqual(entry.target_id, globex.serverId);
      assert.notEqual(entry.target_id, globex.organizationId);
    }
  });

  // ---------------------------------------------------------------------------
  // Écriture croisée : IDOR
  // ---------------------------------------------------------------------------

  const crossTenantMutations: Array<{
    label: string;
    method: 'POST' | 'PUT' | 'PATCH' | 'DELETE';
    url: (target: Tenant) => string;
    payload?: Record<string, unknown>;
  }> = [
    {
      label: 'supprimer le serveur du voisin',
      method: 'DELETE',
      url: (target) => `/api/servers/${target.serverId}`,
    },
    {
      label: 'réécrire la configuration du voisin',
      method: 'PUT',
      url: (target) => `/api/servers/${target.serverId}/configuration`,
      payload: { heartbeat_interval: 900 },
    },
    {
      label: 'générer une credential sur le serveur du voisin',
      method: 'POST',
      url: (target) => `/api/servers/${target.serverId}/credentials`,
    },
    {
      label: 'envoyer une commande au serveur du voisin',
      method: 'POST',
      url: (target) => `/api/servers/${target.serverId}/commands`,
      payload: { type: 'request_status' },
    },
  ];

  for (const mutation of crossTenantMutations) {
    it(`${mutation.label} renvoie 404`, async () => {
      const response = await app.inject({
        method: mutation.method,
        url: mutation.url(globex),
        ...asTenant(acme),
        // `payload: undefined` n'est pas accepté par la signature d'inject ;
        // le DELETE du lot n'a pas de corps.
        ...(mutation.payload ? { payload: mutation.payload } : {}),
      });
      // 404 et non 403 : distinguer « existe mais interdit » de « n'existe pas »
      // permettrait d'énumérer les ressources d'une autre organisation.
      assert.equal(response.statusCode, 404, `réponse inattendue : ${response.body}`);
    });
  }

  it('file de revue : créer une sanction en attente, la confirmer', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/bans',
      ...asTenant(acme),
      payload: {
        scope: 'license', identifier: 'license:pending-confirm', reason: 'Cadence de tir élevée',
        pending: true, risk: 58, detection_category: 'Armes', detector: 'weapon.firerate',
        evidence_kind: 'clip', player_name: 'Kevin_LS',
      },
    });
    assert.equal(created.statusCode, 201);
    assert.equal((created.json() as { ban: { status: string } }).ban.status, 'PENDING');
    const banId = (created.json() as { ban: { id: string } }).ban.id;

    const confirm = await app.inject({
      method: 'POST',
      url: `/api/bans/${banId}/confirm`,
      ...asTenant(acme),
      payload: {},
    });
    assert.equal(confirm.statusCode, 200);
    assert.equal((confirm.json() as { ban_status: string }).ban_status, 'ACTIVE');

    const fb = await admin.query(
      `SELECT verdict FROM detection_feedback WHERE ban_id = $1`,
      [banId],
    );
    assert.equal(fb.rows[0]?.verdict, 'confirmed');
  });

  it('file de revue : « faux positif » écarte la sanction et consigne le retour', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/bans',
      ...asTenant(acme),
      payload: {
        scope: 'license', identifier: 'license:pending-fp', reason: 'Rotation caméra anormale',
        pending: true, risk: 41, detection_category: 'Aimbot', detector: 'aim.camera',
      },
    });
    const banId = (created.json() as { ban: { id: string } }).ban.id;

    const fp = await app.inject({
      method: 'POST',
      url: `/api/bans/${banId}/false-positive`,
      ...asTenant(acme),
      payload: {},
    });
    assert.equal(fp.statusCode, 200);
    assert.equal((fp.json() as { ban_status: string }).ban_status, 'DISMISSED');

    const fb = await admin.query(
      `SELECT verdict, detector FROM detection_feedback WHERE ban_id = $1`,
      [banId],
    );
    assert.equal(fb.rows[0]?.verdict, 'false_positive');
    assert.equal(fb.rows[0]?.detector, 'aim.camera');
  });

  it('confirmer une sanction déjà tranchée renvoie 404', async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/bans',
      ...asTenant(acme),
      payload: {
        scope: 'license', identifier: 'license:pending-once', reason: 'Test', pending: true,
        detector: 'weapon.firerate',
      },
    });
    const banId = (created.json() as { ban: { id: string } }).ban.id;
    await app.inject({ method: 'POST', url: `/api/bans/${banId}/kick`, ...asTenant(acme), payload: {} });
    // Deuxième décision : la sanction n'est plus PENDING.
    const again = await app.inject({
      method: 'POST', url: `/api/bans/${banId}/confirm`, ...asTenant(acme), payload: {},
    });
    assert.equal(again.statusCode, 404);
  });

  it("une sanction en attente d'une organisation est invisible pour l'autre", async () => {
    const created = await app.inject({
      method: 'POST',
      url: '/api/bans',
      ...asTenant(globex),
      payload: {
        scope: 'license', identifier: 'license:globex-secret', reason: 'Secret', pending: true,
        detector: 'movement.teleport',
      },
    });
    const banId = (created.json() as { ban: { id: string } }).ban.id;
    // acme ne doit ni voir ni pouvoir trancher la sanction de globex.
    const cross = await app.inject({
      method: 'POST', url: `/api/bans/${banId}/confirm`, ...asTenant(acme), payload: {},
    });
    assert.equal(cross.statusCode, 404);
  });

  it('renseignement joueur : dossier avec comptes alternatifs et historique', async () => {
    // Deux identifiants, même pseudo -> alt possible. Insertion directe comme
    // le ferait la passerelle agent.
    const mkDet = (id: string, ident: string, name: string) =>
      admin.query(
        `INSERT INTO detections (id, organization_id, server_id, player_identifier,
                                 player_name, kind, confidence, detector, occurred_at)
              VALUES ($1, $2, $3, $4, $5, 'firerate', 70, 'weapon.firerate', now())`,
        [`det_${randomBytes(13).toString('hex')}`, acme.organizationId, acme.serverId, ident, name],
      );
    await mkDet('a', 'license:dossier-main', 'GhostAlt');
    await mkDet('b', 'license:dossier-alt', 'GhostAlt');

    const response = await app.inject({
      method: 'GET',
      url: `/api/players/${encodeURIComponent('license:dossier-main')}`,
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);
    const body = response.json() as {
      dossier: {
        confidence: number;
        ban_history: unknown[];
        servers_seen: Array<{ id: string }>;
        possible_alts: Array<{ player_identifier: string }>;
      };
    };
    assert.equal(typeof body.dossier.confidence, 'number');
    assert.ok(Array.isArray(body.dossier.ban_history));
    assert.ok(body.dossier.servers_seen.some((s) => s.id === acme.serverId));
    assert.ok(body.dossier.possible_alts.some((a) => a.player_identifier === 'license:dossier-alt'));
  });

  it('Multi-vue : une demande d’observation émet une commande spectate_request', async () => {
    const response = await app.inject({
      method: 'POST',
      url: `/api/servers/${acme.serverId}/spectate`,
      ...asTenant(acme),
      payload: { identifier: 'license:watch-me' },
    });
    assert.equal(response.statusCode, 202, response.body);
    assert.equal((response.json() as { command: { type: string } }).command.type, 'spectate_request');

    const cmd = await admin.query(
      `SELECT type, payload FROM agent_commands
        WHERE organization_id = $1 AND server_id = $2 AND type = 'spectate_request'
        ORDER BY created_at DESC LIMIT 1`,
      [acme.organizationId, acme.serverId],
    );
    assert.equal(cmd.rows[0]?.type, 'spectate_request');
    assert.equal((cmd.rows[0]?.payload as { target: string }).target, 'license:watch-me');
  });

  it('Multi-vue : observer un serveur du voisin renvoie 404', async () => {
    const response = await app.inject({
      method: 'POST',
      url: `/api/servers/${globex.serverId}/spectate`,
      ...asTenant(acme),
      payload: { identifier: 'license:x' },
    });
    assert.equal(response.statusCode, 404);
  });

  it('la matrice des accès reflète la source de vérité RBAC', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/rbac/matrix',
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);
    const body = response.json() as {
      roles: string[];
      permissions: string[];
      grants: Record<string, string[]>;
    };
    assert.ok(body.roles.includes('OWNER') && body.roles.includes('VIEWER'));
    assert.ok((body.grants.OWNER ?? []).includes('ban.manage'));
    assert.ok(!(body.grants.VIEWER ?? []).includes('ban.manage'));
    assert.ok((body.grants.VIEWER ?? []).includes('detection.read'));
  });

  it("lire les commandes du serveur du voisin renvoie une liste vide", async () => {
    const response = await app.inject({
      method: 'GET',
      url: `/api/servers/${globex.serverId}/commands`,
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);
    assert.equal((response.json() as { commands: unknown[] }).commands.length, 0);
  });

  it("basculer vers l'organisation du voisin est refusé", async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/switch-organization',
      ...asTenant(acme),
      payload: { organization_id: globex.organizationId },
    });
    assert.equal(response.statusCode, 404);

    // La session doit être restée sur son organisation d'origine.
    const me = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie: acme.cookie } });
    assert.equal((me.json() as { organization_id: string }).organization_id, acme.organizationId);
  });

  // ---------------------------------------------------------------------------
  // Authentification et CSRF
  // ---------------------------------------------------------------------------

  it('une requête sans session est refusée', async () => {
    const response = await app.inject({ method: 'GET', url: '/api/servers' });
    assert.equal(response.statusCode, 401);
  });

  it('une mutation sans jeton CSRF est refusée', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/servers',
      headers: { cookie: acme.cookie },
      payload: { name: 'Sans CSRF' },
    });
    assert.equal(response.statusCode, 403);
    assert.equal((response.json() as { error: string }).error, 'csrf_failed');
  });

  it('un jeton CSRF ne correspondant pas au cookie est refusé', async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/servers',
      headers: {
        cookie: `${acme.cookie}; zshield_csrf=${acme.csrf}`,
        'x-csrf-token': 'jeton-forge-par-un-tiers',
      },
      payload: { name: 'CSRF incohérent' },
    });
    assert.equal(response.statusCode, 403);
  });

  it('une lecture reste possible sans jeton CSRF', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/api/servers',
      headers: { cookie: acme.cookie },
    });
    assert.equal(response.statusCode, 200);
  });

  it('un mot de passe erroné ne révèle pas si le compte existe', async () => {
    const known = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: acme.email, password: 'mauvais-mot-de-passe' },
    });
    const unknown = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: 'inexistant@example.test', password: 'mauvais-mot-de-passe' },
    });

    assert.equal(known.statusCode, 401);
    assert.equal(unknown.statusCode, 401);
    assert.deepEqual(known.json(), unknown.json());
  });

  it("l'inscription répond identiquement pour un email déjà pris", async () => {
    const response = await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email: acme.email,
        password: 'development-password-2',
        display_name: 'Imposteur',
        organization_name: 'Imposteur SA',
      },
    });
    assert.equal(response.statusCode, 202);
    assert.deepEqual(response.json(), { status: 'pending_verification' });
  });

  // ---------------------------------------------------------------------------
  // RBAC appliqué côté serveur
  // ---------------------------------------------------------------------------

  it("un VIEWER ne peut pas créer de serveur, même avec un CSRF valide", async () => {
    const email = `viewer-${randomBytes(4).toString('hex')}@example.test`;
    const password = 'development-password-1';

    await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email,
        password,
        display_name: 'Viewer',
        organization_name: `viewer-org-${randomBytes(2).toString('hex')}`,
      },
    });

    // Rattaché à Acme en VIEWER, et sa session est repointée sur Acme.
    const { rows } = await admin.query<{ id: string }>('SELECT id FROM users WHERE email = $1', [email]);
    const userId = rows[0]!.id;
    await admin.query(
      `INSERT INTO memberships (id, organization_id, user_id, role, accepted_at)
            VALUES ($1, $2, $3, 'VIEWER', now())`,
      [`mem_${randomBytes(8).toString('hex')}`, acme.organizationId, userId],
    );

    const loggedIn = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email, password },
    });
    const cookie = cookieFrom(loggedIn.headers as Record<string, unknown>);
    const csrf = (loggedIn.json() as { csrf_token: string }).csrf_token;

    await admin.query(
      `UPDATE sessions SET organization_id = $2 WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId, acme.organizationId],
    );

    const response = await app.inject({
      method: 'POST',
      url: '/api/servers',
      headers: { cookie: `${cookie}; zshield_csrf=${csrf}`, 'x-csrf-token': csrf },
      payload: { name: 'Serveur interdit' },
    });
    assert.equal(response.statusCode, 403);
    assert.equal((response.json() as { error: string }).error, 'forbidden');

    // Et il ne voit pas non plus le journal d'audit.
    const audit = await app.inject({ method: 'GET', url: '/api/audit-logs', headers: { cookie } });
    assert.equal(audit.statusCode, 403);
  });

  it("le retrait d'une adhésion coupe l'accès à la requête suivante", async () => {
    const email = `revoked-${randomBytes(4).toString('hex')}@example.test`;
    const password = 'development-password-1';

    await app.inject({
      method: 'POST',
      url: '/api/auth/register',
      payload: {
        email,
        password,
        display_name: 'Partant',
        organization_name: `partant-org-${randomBytes(2).toString('hex')}`,
      },
    });

    const loggedIn = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email, password },
    });
    const cookie = cookieFrom(loggedIn.headers as Record<string, unknown>);

    const before = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie } });
    assert.equal(before.statusCode, 200);

    // Le rôle est résolu en base à chaque requête : supprimer l'adhésion doit
    // suffire, sans attendre l'expiration de la session.
    const { rows } = await admin.query<{ id: string }>('SELECT id FROM users WHERE email = $1', [email]);
    await admin.query('DELETE FROM memberships WHERE user_id = $1', [rows[0]!.id]);

    const afterRemoval = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { cookie } });
    assert.equal(afterRemoval.statusCode, 401);
  });

  // ---------------------------------------------------------------------------
  // Quotas
  // ---------------------------------------------------------------------------

  it('le quota de serveurs du plan free est appliqué côté serveur', async () => {
    // L'inscription place l'organisation en plan free : servers.max = 1, et un
    // serveur a déjà été créé.
    const response = await app.inject({
      method: 'POST',
      url: '/api/servers',
      ...asTenant(acme),
      payload: { name: 'Second serveur' },
    });
    assert.equal(response.statusCode, 402);
    assert.equal((response.json() as { error: string }).error, 'entitlement_exceeded');
  });

  // ---------------------------------------------------------------------------
  // Validation
  // ---------------------------------------------------------------------------

  it('un champ inconnu dans la configuration distante est rejeté', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: `/api/servers/${acme.serverId}/configuration`,
      ...asTenant(acme),
      // L'agent rejette TOUT le document sur un seul champ inconnu : accepter
      // ici produirait un serveur qui ignore silencieusement sa configuration.
      payload: { heartbeat_interval: 60, enable_kick_command: true },
    });
    assert.equal(response.statusCode, 400);
  });

  it('une valeur hors bornes du protocole est rejetée', async () => {
    const response = await app.inject({
      method: 'PUT',
      url: `/api/servers/${acme.serverId}/configuration`,
      ...asTenant(acme),
      payload: { heartbeat_interval: 5 }, // le protocole impose 15 à 900
    });
    assert.equal(response.statusCode, 400);
  });

  it("un type de commande hors allowlist est rejeté", async () => {
    const response = await app.inject({
      method: 'POST',
      url: `/api/servers/${acme.serverId}/commands`,
      ...asTenant(acme),
      payload: { type: 'execute_lua' },
    });
    assert.equal(response.statusCode, 400);
  });

  // ---------------------------------------------------------------------------
  // Passerelle agent, chaîne complète
  // ---------------------------------------------------------------------------

  describe('passerelle agent', () => {
    let keyId: string;
    let secret: string;
    let agentId: string;
    let serverId: string;

    before(async () => {
      const response = await app.inject({
        method: 'POST',
        url: `/api/servers/${globex.serverId}/credentials`,
        ...asTenant(globex),
      });
      assert.equal(response.statusCode, 201);

      const body = response.json() as {
        key_id: string;
        secret: string;
        agent_id: string;
        server_id: string;
      };
      keyId = body.key_id;
      secret = body.secret;
      agentId = body.agent_id;
      serverId = body.server_id;
    });

    /** Signe exactement comme l'agent Lua. */
    const sign = (options: {
      method: string;
      path: string;
      query?: string;
      body?: string;
      keyId?: string;
      secret?: string;
      serverId?: string;
      timestamp?: number;
      nonce?: string;
    }) => {
      const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
      const nonce = options.nonce ?? randomBytes(16).toString('hex');
      const requestId = randomBytes(12).toString('hex');
      const canonical = canonicalRequest({
        method: options.method,
        path: options.path,
        query: options.query ?? '',
        agentId,
        serverId: options.serverId ?? serverId,
        keyId: options.keyId ?? keyId,
        timestamp,
        nonce,
        bodyHash: sha256Hex(Buffer.from(options.body ?? '', 'utf8')),
      });

      return {
        'content-type': 'application/json; charset=utf-8',
        'x-zshield-agent-id': agentId,
        'x-zshield-server-id': options.serverId ?? serverId,
        'x-zshield-key-id': options.keyId ?? keyId,
        'x-zshield-timestamp': String(timestamp),
        'x-zshield-nonce': nonce,
        'x-zshield-signature': hmacSha256Hex(options.secret ?? secret, canonical),
        'x-zshield-protocol': '1',
        'x-zshield-agent-version': '1.0.0',
        'x-zshield-request-id': requestId,
      };
    };

    const envelope = (kind: string, payload: unknown, overrides: Record<string, unknown> = {}) =>
      JSON.stringify({
        protocol_version: 1,
        agent_version: '1.0.0',
        kind,
        server_id: serverId,
        agent_id: agentId,
        environment: 'production',
        sent_at: Math.floor(Date.now() / 1000),
        payload,
        ...overrides,
      });

    it('un handshake correctement signé réussit et signe sa réponse', async () => {
      const body = envelope('handshake', {
        server: { fxserver_version: '6683', onesync: 'on', max_players: 64, uptime_seconds: 120 },
        capabilities: ['heartbeat', 'telemetry', 'alerts'],
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/handshake',
        headers: sign({ method: 'POST', path: '/v1/agents/handshake', body }),
        payload: body,
      });

      assert.equal(response.statusCode, 200, response.body);
      const json = response.json() as {
        ok: boolean;
        api_version: number;
        min_agent_protocol: number;
        server_name: string;
      };
      assert.equal(json.ok, true);
      assert.equal(json.api_version, 1);
      // Obligatoire : sans ce champ l'agent échoue fermé.
      assert.equal(json.min_agent_protocol, 1);

      // Toute réponse doit être signée, y compris les erreurs.
      assert.ok(response.headers['x-zshield-signature']);
      assert.ok(response.headers['x-zshield-nonce']);
      assert.ok(response.headers['x-zshield-timestamp']);
    });

    it('une signature invalide est rejetée en 401', async () => {
      const body = envelope('heartbeat', {});
      const headers = sign({ method: 'POST', path: '/v1/agents/heartbeat', body });
      headers['x-zshield-signature'] = 'f'.repeat(64);

      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers,
        payload: body,
      });
      assert.equal(response.statusCode, 401);
    });

    it('une alerte avec sanction crée un ban (PENDING si non-CRITICAL)', async () => {
      const body = envelope('alerts', {
        alerts: [
          {
            id: `sig-${randomBytes(6).toString('hex')}`,
            category: 'weapon',
            severity: 'HIGH',
            summary: 'cadence de tir invraisemblable',
            occurred_at: Math.floor(Date.now() / 1000),
            sanction: {
              scope: 'license',
              identifier: 'license:gateway-pending',
              detector: 'weapon.firerate',
              risk: 72,
              evidence_kind: 'clip',
              player_name: 'Kevin_LS',
            },
          },
        ],
      });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/alerts',
        headers: sign({ method: 'POST', path: '/v1/agents/alerts', body }),
        payload: body,
      });
      assert.equal(response.statusCode, 200, response.body);

      const ban = await admin.query(
        `SELECT status, detector, issued_by_auto, risk, evidence_kind
           FROM bans WHERE organization_id = $1 AND identifier = $2`,
        [globex.organizationId, 'license:gateway-pending'],
      );
      assert.equal(ban.rows[0]?.status, 'PENDING');
      assert.equal(ban.rows[0]?.issued_by_auto, true);
      assert.equal(ban.rows[0]?.detector, 'weapon.firerate');
    });

    it('une alerte CRITICAL avec sanction crée un ban ACTIF immédiat', async () => {
      const body = envelope('alerts', {
        alerts: [
          {
            id: `sig-${randomBytes(6).toString('hex')}`,
            category: 'resource',
            severity: 'CRITICAL',
            summary: 'traces d’injection confirmées',
            occurred_at: Math.floor(Date.now() / 1000),
            sanction: {
              scope: 'license',
              identifier: 'license:gateway-active',
              detector: 'injection.trace',
            },
          },
        ],
      });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/alerts',
        headers: sign({ method: 'POST', path: '/v1/agents/alerts', body }),
        payload: body,
      });
      assert.equal(response.statusCode, 200, response.body);

      const ban = await admin.query(
        `SELECT status FROM bans WHERE organization_id = $1 AND identifier = $2`,
        [globex.organizationId, 'license:gateway-active'],
      );
      assert.equal(ban.rows[0]?.status, 'ACTIVE');
    });

    it('un nonce rejoué est rejeté', async () => {
      const nonce = randomBytes(16).toString('hex');
      const payload = {
        state: 'ONLINE',
        agent_version: '1.0.0',
        protocol_version: 1,
        uptime_seconds: 60,
        players_online: 12,
        config_version: 0,
        queue_size: 0,
        health: 'HEALTHY',
      };

      const first = envelope('heartbeat', payload);
      const firstResponse = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({ method: 'POST', path: '/v1/agents/heartbeat', body: first, nonce }),
        payload: first,
      });
      assert.equal(firstResponse.statusCode, 200, firstResponse.body);

      const second = envelope('heartbeat', payload);
      const secondResponse = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({ method: 'POST', path: '/v1/agents/heartbeat', body: second, nonce }),
        payload: second,
      });
      assert.equal(secondResponse.statusCode, 401);
      assert.equal((secondResponse.json() as { error: string }).error, 'E_AUTH_REPLAY');
    });

    it('un horodatage hors fenêtre est rejeté', async () => {
      const body = envelope('heartbeat', {});
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({
          method: 'POST',
          path: '/v1/agents/heartbeat',
          body,
          timestamp: Math.floor(Date.now() / 1000) - 3600,
        }),
        payload: body,
      });
      assert.equal(response.statusCode, 401);
      assert.equal((response.json() as { error: string }).error, 'E_AUTH_CLOCK_SKEW');
    });

    it("un agent ne peut pas écrire sur le serveur d'une autre organisation", async () => {
      // La credential est liée au serveur de Globex ; on prétend être celui
      // d'Acme. La signature est valide, l'identité ne l'est pas.
      const body = envelope('heartbeat', {}, { server_id: acme.serverId });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({
          method: 'POST',
          path: '/v1/agents/heartbeat',
          body,
          serverId: acme.serverId,
        }),
        payload: body,
      });
      assert.equal(response.statusCode, 401);
    });

    it("une enveloppe incohérente avec les en-têtes signés est rejetée", async () => {
      // En-têtes corrects, enveloppe mensongère : l'autorité est l'en-tête.
      const body = envelope('heartbeat', {}, { server_id: acme.serverId });
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({ method: 'POST', path: '/v1/agents/heartbeat', body }),
        payload: body,
      });
      assert.equal(response.statusCode, 400);
      assert.equal((response.json() as { error: string }).error, 'E_VALIDATION');
    });

    it('une credential révoquée cesse immédiatement de fonctionner', async () => {
      const revoke = await app.inject({
        method: 'DELETE',
        url: `/api/servers/${serverId}/credentials/${keyId}`,
        ...asTenant(globex),
      });
      assert.equal(revoke.statusCode, 200);

      const body = envelope('heartbeat', {});
      const response = await app.inject({
        method: 'POST',
        url: '/v1/agents/heartbeat',
        headers: sign({ method: 'POST', path: '/v1/agents/heartbeat', body }),
        payload: body,
      });
      assert.equal(response.statusCode, 401);
      assert.equal((response.json() as { error: string }).error, 'E_AUTH_CREDENTIAL_REVOKED');
    });
  });
});
