/**
 * Exécuteur de migrations.
 *
 * Idempotent : chaque fichier est appliqué une fois, dans une transaction, et
 * son empreinte est enregistrée. Un fichier déjà appliqué mais modifié depuis
 * fait échouer la migration au lieu d'être ignoré — sinon deux environnements
 * finissent avec des schémas différents en croyant être à jour.
 */
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from 'pg';

const here = dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = resolve(here, '../../../../db/migrations');

const connectionString = process.env.DATABASE_MIGRATION_URL ?? process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_MIGRATION_URL ou DATABASE_URL est requis');
}

const client = new Client({ connectionString });
await client.connect();

await client.query(`
  CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    text PRIMARY KEY,
    checksum    text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
  )
`);

const files = readdirSync(MIGRATIONS_DIR)
  .filter((name) => name.endsWith('.sql'))
  .sort();

const { rows } = await client.query<{ filename: string; checksum: string }>(
  'SELECT filename, checksum FROM schema_migrations',
);
const applied = new Map(rows.map((row) => [row.filename, row.checksum]));

let count = 0;

for (const filename of files) {
  const sql = readFileSync(join(MIGRATIONS_DIR, filename), 'utf8');
  const checksum = createHash('sha256').update(sql).digest('hex');
  const previous = applied.get(filename);

  if (previous) {
    if (previous !== checksum) {
      throw new Error(
        `${filename} a déjà été appliquée mais son contenu a changé. ` +
          'Créer une nouvelle migration au lieu de modifier celle-ci.',
      );
    }
    continue;
  }

  process.stdout.write(`application de ${filename}\n`);
  try {
    // Les fichiers gèrent eux-mêmes BEGIN/COMMIT : certaines opérations DDL ne
    // supportent pas d'être imbriquées dans une transaction externe.
    await client.query(sql);
    await client.query(
      'INSERT INTO schema_migrations (filename, checksum) VALUES ($1, $2)',
      [filename, checksum],
    );
    count += 1;
  } catch (error) {
    await client.end();
    throw new Error(
      `${filename} a échoué : ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

process.stdout.write(`${count} migration(s) appliquée(s), ${files.length} au total\n`);
await client.end();
