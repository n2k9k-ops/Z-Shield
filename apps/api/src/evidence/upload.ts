/**
 * Réception des captures du RENDU DE JEU (screenshot-basic) envoyées par un client.
 *
 * Surface isolée : pas de cookie, pas de session. L'autorité est un jeton à usage
 * unique (5 min) dont seul le hachage est en base, fourni au client via l'URL que la
 * plateforme a construite pour l'agent. Toute autre situation répond le même 404
 * générique : on n'apprend à personne si une capture existe, a expiré ou a déjà servi.
 *
 * Défenses : taille plafonnée, type déterminé par les octets (JPEG/PNG) et non par
 * l'en-tête, limitation de débit par IP, image servie ensuite avec CSP « none ».
 */
import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { withTenant } from '../lib/db.ts';
import { hashToken } from '../lib/crypto.ts';

export const MAX_IMAGE_BYTES = 1_572_864; // 1,5 Mio
const ORG_RE = /^org_[0-9a-z]{26}$/;
const CAP_RE = /^cap_[0-9a-z]{26}$/;

export interface ParsedImage {
  mime: 'image/jpeg' | 'image/png';
  data: Buffer;
}

function sniff(data: Buffer): ParsedImage['mime'] | null {
  if (data.length > 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff) return 'image/jpeg';
  if (
    data.length > 8 &&
    data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4e && data[3] === 0x47 &&
    data[4] === 0x0d && data[5] === 0x0a && data[6] === 0x1a && data[7] === 0x0a
  ) return 'image/png';
  return null;
}

/**
 * Extrait l'image d'un corps `multipart/form-data` (première partie qui est une image)
 * ou d'un corps image brut. Retourne null si rien d'exploitable.
 */
export function parseUpload(body: Buffer, contentType: string | undefined): ParsedImage | null {
  if (!Buffer.isBuffer(body) || body.length === 0 || body.length > MAX_IMAGE_BYTES + 4096) return null;
  const ct = contentType ?? '';

  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(ct);
  if (/multipart\/form-data/i.test(ct) && m) {
    const boundary = Buffer.from(`--${(m[1] ?? m[2] ?? '').trim()}`);
    let pos = body.indexOf(boundary);
    while (pos !== -1) {
      const after = pos + boundary.length;
      if (body.subarray(after, after + 2).toString() === '--') break; // fin
      const headStart = after + 2; // saute CRLF
      const headEnd = body.indexOf('\r\n\r\n', headStart);
      if (headEnd === -1) break;
      const next = body.indexOf(boundary, headEnd + 4);
      if (next === -1) break;
      const data = body.subarray(headEnd + 4, next - 2); // retire le CRLF avant le délimiteur
      const mime = sniff(data);
      if (mime && data.length <= MAX_IMAGE_BYTES) return { mime, data: Buffer.from(data) };
      pos = next;
    }
    return null;
  }

  const mime = sniff(body);
  if (mime && body.length <= MAX_IMAGE_BYTES) return { mime, data: body };
  return null;
}

interface UploadOptions {
  pool: Pool;
  logger: { warn: (msg: string, meta?: Record<string, unknown>) => void };
}

export async function evidenceUploadRoutes(
  app: FastifyInstance,
  { pool, logger }: UploadOptions,
): Promise<void> {
  // Corps lu en brut (multipart ou image), quelle que soit l'étiquette Content-Type.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('*', { parseAs: 'buffer', bodyLimit: MAX_IMAGE_BYTES + 4096 },
    (_request, body, done) => done(null, body));

  const hits = new Map<string, { n: number; start: number }>();
  const limited = (ip: string): boolean => {
    const now = Date.now();
    const h = hits.get(ip);
    if (!h || now - h.start > 60_000) {
      hits.set(ip, { n: 1, start: now });
      if (hits.size > 5000) hits.clear();
      return false;
    }
    h.n += 1;
    return h.n > 30;
  };

  app.post(
    '/api/evidence/upload/:org/:id',
    { bodyLimit: MAX_IMAGE_BYTES + 4096 },
    async (request, reply) => {
      // Le jeton fait foi, pas les cookies : réponse lisible depuis la NUI du jeu.
      reply.header('Access-Control-Allow-Origin', '*');
      reply.header('Cache-Control', 'no-store');

      const notFound = () => {
        reply.status(404);
        return { error: 'not_found' };
      };

      if (limited(request.ip)) {
        reply.status(429);
        return { error: 'rate_limited' };
      }

      const { org, id } = request.params as { org: string; id: string };
      const token = (request.query as { t?: string }).t;
      if (!ORG_RE.test(org) || !CAP_RE.test(id) || typeof token !== 'string' ||
          token.length < 20 || token.length > 100) {
        return notFound();
      }

      const image = parseUpload(request.body as Buffer, request.headers['content-type']);
      if (!image) {
        reply.status(400);
        return { error: 'invalid_image' };
      }

      const presented = hashToken(token);
      const stored = await withTenant(pool, org, async (client) => {
        const { rows } = await client.query<{ token_hash: Buffer; status: string; live: boolean }>(
          `SELECT token_hash, status, (expires_at > now()) AS live
             FROM evidence_captures
            WHERE organization_id = $1 AND id = $2
            FOR UPDATE`,
          [org, id],
        );
        const row = rows[0];
        if (!row || row.status !== 'PENDING' || !row.live) return false;
        if (row.token_hash.length !== presented.length ||
            !timingSafeEqual(row.token_hash, presented)) return false;

        await client.query(
          `UPDATE evidence_captures
              SET status = 'RECEIVED', mime = $3, bytes = $4, image = $5, received_at = now()
            WHERE organization_id = $1 AND id = $2`,
          [org, id, image.mime, image.data.length, image.data],
        );
        return true;
      });

      if (!stored) {
        logger.warn('upload de capture refusé', { id });
        return notFound();
      }
      return { ok: true };
    },
  );
}
