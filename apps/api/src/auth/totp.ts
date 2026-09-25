/**
 * TOTP (RFC 6238) et codes de récupération.
 *
 * Implémenté sur `node:crypto` plutôt qu'avec une bibliothèque : l'algorithme
 * tient en trente lignes, et une dépendance de plus dans le chemin
 * d'authentification est une surface de plus à surveiller.
 *
 * Deux points souvent manqués et traités ici :
 *
 *   1. **anti-rejeu.** Un code TOTP reste valable ~90 s avec une fenêtre de ±1.
 *      Sans mémoriser le dernier pas utilisé, un code intercepté est rejouable
 *      pendant tout ce temps. `last_used_step` en base sert à cela.
 *
 *   2. **fenêtre de tolérance.** ±1 pas (30 s) absorbe une horloge de téléphone
 *      légèrement décalée. Élargir à ±3 « pour le confort » triple la fenêtre
 *      de rejeu ; c'est un arbitrage, pas un réglage anodin.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { hashToken } from '../lib/crypto.ts';

const STEP_SECONDS = 30;
const DIGITS = 6;
const DEFAULT_WINDOW = 1;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(): string {
  // 20 octets = 160 bits, la taille recommandée pour HMAC-SHA1.
  const bytes = randomBytes(20);
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];

  return output;
}

function base32Decode(input: string): Buffer {
  const normalised = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const character of normalised) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index === -1) throw new Error('secret TOTP invalide');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/** Code à 6 chiffres pour un pas donné. */
export function totpCodeForStep(secret: string, step: number): string {
  const key = base32Decode(secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));

  const digest = createHmac('sha1', key).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    ((digest[offset]! & 0x7f) << 24) |
    (digest[offset + 1]! << 16) |
    (digest[offset + 2]! << 8) |
    digest[offset + 3]!;

  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, '0');
}

export function currentStep(now: number = Date.now()): number {
  return Math.floor(now / 1000 / STEP_SECONDS);
}

export interface TotpVerification {
  valid: boolean;
  /** Pas consommé, à persister pour interdire le rejeu. */
  step?: number;
  reason?: 'malformed' | 'mismatch' | 'replayed';
}

/**
 * Vérifie un code.
 *
 * `lastUsedStep` doit venir de la base. Un pas inférieur ou égal est refusé
 * même si le code est mathématiquement correct : c'est un rejeu.
 */
export function verifyTotp(
  secret: string,
  code: string,
  options: { lastUsedStep?: number | null; now?: number; window?: number } = {},
): TotpVerification {
  const cleaned = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(cleaned)) return { valid: false, reason: 'malformed' };

  const window = options.window ?? DEFAULT_WINDOW;
  const center = currentStep(options.now ?? Date.now());
  const provided = Buffer.from(cleaned, 'utf8');

  for (let offset = -window; offset <= window; offset += 1) {
    const step = center + offset;
    if (step < 0) continue;

    const expected = Buffer.from(totpCodeForStep(secret, step), 'utf8');
    if (expected.length === provided.length && timingSafeEqual(expected, provided)) {
      if (options.lastUsedStep != null && step <= options.lastUsedStep) {
        return { valid: false, reason: 'replayed' };
      }
      return { valid: true, step };
    }
  }

  return { valid: false, reason: 'mismatch' };
}

/** URI otpauth:// pour le QR code. Le secret n'est jamais journalisé. */
export function totpUri(secret: string, accountEmail: string, issuer = 'ZShield'): string {
  const label = encodeURIComponent(`${issuer}:${accountEmail}`);
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

// ---------------------------------------------------------------------------
// Codes de récupération
// ---------------------------------------------------------------------------

/**
 * Dix codes à usage unique. Retournés en clair une seule fois ; seuls leurs
 * hachages sont stockés, comme des mots de passe — parce que c'en sont.
 */
export function generateRecoveryCodes(count = 10): { codes: string[]; hashes: string[] } {
  const codes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const raw = randomBytes(5).toString('hex').toUpperCase();
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return { codes, hashes: codes.map((code) => hashToken(code).toString('base64')) };
}

/**
 * Consomme un code de récupération. Retourne la liste restante, amputée du code
 * utilisé : un code de récupération réutilisable n'est plus un facteur.
 */
export function consumeRecoveryCode(
  presented: string,
  storedHashes: string[],
): { accepted: boolean; remaining: string[] } {
  const candidate = hashToken(presented.trim().toUpperCase()).toString('base64');
  const index = storedHashes.indexOf(candidate);

  if (index === -1) return { accepted: false, remaining: storedHashes };

  const remaining = [...storedHashes];
  remaining.splice(index, 1);
  return { accepted: true, remaining };
}
