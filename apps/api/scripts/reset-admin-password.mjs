// Réinitialisation d'un mot de passe depuis un terminal de confiance (Render Shell
// ou machine ayant accès à la base). Le mot de passe est saisi ICI, masqué, et
// n'est jamais affiché ni journalisé. Même scrypt que lib/crypto.ts.
//
// Usage (dans le Shell du service API sur Render) :
//   node apps/api/scripts/reset-admin-password.mjs ton@email.com
import { scrypt, randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import pg from 'pg';

const email = (process.argv[2] || '').trim().toLowerCase();
if (!email) { console.error('Usage: node reset-admin-password.mjs <email>'); process.exit(1); }
const url = process.env.DATABASE_MIGRATION_URL || process.env.DATABASE_URL;
if (!url) { console.error('DATABASE_URL absent.'); process.exit(1); }

function ask(q) {
  return new Promise((res) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (s) => { if (s.includes(q)) rl.output.write(s); };  // masque la frappe
    rl.question(q, (a) => { rl.close(); process.stdout.write('\n'); res(a); });
  });
}
const N = 32768, r = 8, p = 1;
const kdf = (pw, salt) => new Promise((ok, ko) =>
  scrypt(pw, salt, 32, { N, r, p, maxmem: 128 * N * r * 2 }, (e, k) => (e ? ko(e) : ok(k))));

const pw1 = await ask('Nouveau mot de passe (12 caractères min) : ');
const pw2 = await ask('Confirme le mot de passe : ');
if (pw1 !== pw2) { console.error('Les deux saisies diffèrent.'); process.exit(1); }
if (pw1.length < 12) { console.error('12 caractères minimum.'); process.exit(1); }

const salt = randomBytes(16);
const hash = ['scrypt', N, r, p, salt.toString('base64'), (await kdf(pw1, salt)).toString('base64')].join('$');

const client = new pg.Client({ connectionString: url, ssl: /sslmode=|render\.com/.test(url) ? { rejectUnauthorized: false } : undefined });
await client.connect();
try {
  await client.query('BEGIN');
  const { rows } = await client.query(
    `UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL
      WHERE email = $1 AND deleted_at IS NULL RETURNING id`, [email, hash]);
  if (!rows[0]) { await client.query('ROLLBACK'); console.error('Aucun compte avec cet email.'); process.exit(1); }
  await client.query(`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, [rows[0].id]);
  await client.query(`INSERT INTO audit_logs (organization_id, actor_user_id, actor_kind, action)
                      VALUES (NULL, $1, 'user', 'auth.password_reset')`, [rows[0].id]);
  await client.query('COMMIT');
  console.log('OK : mot de passe mis à jour, sessions révoquées. Connecte-toi normalement.');
} catch (e) { await client.query('ROLLBACK'); console.error('Échec :', e.message); process.exit(1); }
finally { await client.end(); }
