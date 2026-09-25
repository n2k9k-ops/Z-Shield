/**
 * Connexion Discord (OAuth2) — provisionnement et rattachement de comptes.
 *
 * Exerce directement AuthService.loginWithDiscord contre PostgreSQL réel, pour
 * couvrir les trois chemins et les refus de sécurité. Ignoré (pas déclaré vert)
 * si la base de test n'est pas configurée.
 *
 * Prérequis : TEST_DATABASE_URL (rôle applicatif), TEST_DATABASE_ADMIN_URL
 * (rôle superutilisateur / BYPASSRLS, pour la table rase).
 */
import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, it } from 'node:test';
import { Pool } from 'pg';

import { createPool } from '../src/lib/db.ts';
import { AuthService } from '../src/auth/sessions.ts';

const APP_URL = process.env.TEST_DATABASE_URL;
const ADMIN_URL = process.env.TEST_DATABASE_ADMIN_URL;
const available = Boolean(APP_URL && ADMIN_URL);

describe('connexion Discord', { skip: !available }, () => {
  let pool: Pool;
  let admin: Pool;
  let auth: AuthService;

  before(async () => {
    pool = createPool({ connectionString: APP_URL!, max: 5 });
    admin = new Pool({ connectionString: ADMIN_URL! });
    auth = new AuthService(pool);
  });

  after(async () => {
    await pool?.end();
    await admin?.end();
  });

  beforeEach(async () => {
    await admin.query(`
      TRUNCATE discord_identities, sessions, memberships, subscriptions, organizations,
               mfa_factors, audit_logs, users
        RESTART IDENTITY CASCADE
    `);
  });

  const baseInput = {
    discordUserId: '123456789012345678',
    email: 'pilote@example.com',
    emailVerified: true,
    username: 'pilote',
    avatarUrl: null,
    displayName: 'Pilote LS',
  };

  it('provisionne un nouveau compte + organisation au premier login', async () => {
    const outcome = await auth.loginWithDiscord(baseInput);
    assert.equal(outcome.status, 'ok');

    const { rows } = await admin.query(
      `SELECT u.email, u.email_verified_at, m.role, di.discord_user_id
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         JOIN discord_identities di ON di.user_id = u.id
        WHERE u.email = $1`,
      [baseInput.email],
    );
    assert.equal(rows.length, 1);
    assert.equal(rows[0].role, 'OWNER');
    assert.equal(rows[0].discord_user_id, baseInput.discordUserId);
    assert.notEqual(rows[0].email_verified_at, null); // e-mail Discord vérifié
  });

  it('réutilise le même compte au second login (pas de doublon)', async () => {
    await auth.loginWithDiscord(baseInput);
    const second = await auth.loginWithDiscord(baseInput);
    assert.equal(second.status, 'ok');

    const { rows } = await admin.query('SELECT count(*)::int AS n FROM users');
    assert.equal(rows[0].n, 1);
  });

  it('rattache une identité Discord à un compte e-mail existant (e-mail vérifié)', async () => {
    // Compte créé par la voie e-mail classique.
    const reg = await auth.register({
      email: baseInput.email,
      password: 'motdepasse-costaud',
      displayName: 'Pilote LS',
      organizationName: 'Los Santos RP',
    });
    assert.equal(reg.created, true);

    const outcome = await auth.loginWithDiscord(baseInput);
    assert.equal(outcome.status, 'ok');

    const { rows } = await admin.query('SELECT count(*)::int AS n FROM users');
    assert.equal(rows[0].n, 1); // rattaché, pas dupliqué
    const link = await admin.query(
      'SELECT user_id FROM discord_identities WHERE discord_user_id = $1',
      [baseInput.discordUserId],
    );
    assert.equal(link.rows[0].user_id, reg.userId);
  });

  it("refuse de rattacher un compte existant si l'e-mail Discord n'est PAS vérifié", async () => {
    await auth.register({
      email: baseInput.email,
      password: 'motdepasse-costaud',
      displayName: 'Pilote LS',
      organizationName: 'Los Santos RP',
    });

    const outcome = await auth.loginWithDiscord({ ...baseInput, emailVerified: false });
    assert.equal(outcome.status, 'error');
    if (outcome.status === 'error') assert.equal(outcome.reason, 'email_taken');

    // Aucune liaison n'a été créée.
    const link = await admin.query('SELECT 1 FROM discord_identities WHERE discord_user_id = $1', [
      baseInput.discordUserId,
    ]);
    assert.equal(link.rowCount, 0);
  });

  it('refuse le provisionnement sans e-mail', async () => {
    const outcome = await auth.loginWithDiscord({ ...baseInput, email: null });
    assert.equal(outcome.status, 'error');
    if (outcome.status === 'error') assert.equal(outcome.reason, 'no_email');
  });
});
