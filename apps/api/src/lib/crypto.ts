/**
 * Primitives cryptographiques. Un seul endroit pour toute manipulation de
 * secret : signature HMAC, chiffrement au repos, hachage de mot de passe,
 * génération d'identifiants.
 *
 * Distinction importante, qui commande tout le reste :
 *
 *   - un mot de passe est *vérifié*        -> haché de façon irréversible (scrypt) ;
 *   - un secret HMAC est *recalculé*       -> chiffré, donc réversible (AES-256-GCM).
 *
 * Confondre les deux mène soit à des mots de passe déchiffrables, soit à des
 * secrets d'agent inutilisables. Voir docs/ARCHITECTURE.md §2.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual as nodeTimingSafeEqual,
} from 'node:crypto';

/**
 * `promisify` ne conserve pas la surcharge de scrypt qui accepte des options,
 * d'où ce wrapper typé explicitement plutôt qu'un cast au point d'appel.
 */
interface ScryptOptions {
  N: number;
  r: number;
  p: number;
  maxmem: number;
}

function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

// ---------------------------------------------------------------------------
// Empreintes et signatures
// ---------------------------------------------------------------------------

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export function hmacSha256Hex(secret: string, message: string): string {
  return createHmac('sha256', secret).update(message, 'utf8').digest('hex');
}

/**
 * Comparaison en temps constant de deux chaînes hexadécimales.
 *
 * `timingSafeEqual` lève si les longueurs diffèrent, ce qui réintroduirait une
 * fuite par exception. On compare donc des empreintes de longueur fixe des deux
 * valeurs : une signature trop courte échoue sans révéler où.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = createHash('sha256').update(a, 'utf8').digest();
  const right = createHash('sha256').update(b, 'utf8').digest();
  return nodeTimingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// Chiffrement des secrets au repos
// ---------------------------------------------------------------------------

const GCM_IV_BYTES = 12;
const GCM_TAG_BYTES = 16;
const ENVELOPE_VERSION = 1;

/**
 * Format : [version:1][iv:12][tag:16][ciphertext:n]
 *
 * L'octet de version permet une rotation d'algorithme sans deviner le format
 * des lignes existantes.
 */
export function encryptSecret(plaintext: string, key: Buffer): Buffer {
  if (key.length !== 32) {
    throw new Error('clé de chiffrement invalide : 32 octets attendus');
  }

  const iv = randomBytes(GCM_IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([Buffer.from([ENVELOPE_VERSION]), iv, tag, ciphertext]);
}

export function decryptSecret(envelope: Buffer, key: Buffer): string {
  if (key.length !== 32) {
    throw new Error('clé de chiffrement invalide : 32 octets attendus');
  }
  if (envelope.length < 1 + GCM_IV_BYTES + GCM_TAG_BYTES) {
    throw new Error('enveloppe chiffrée tronquée');
  }

  const version = envelope[0];
  if (version !== ENVELOPE_VERSION) {
    throw new Error(`version d'enveloppe non supportée : ${String(version)}`);
  }

  const iv = envelope.subarray(1, 1 + GCM_IV_BYTES);
  const tag = envelope.subarray(1 + GCM_IV_BYTES, 1 + GCM_IV_BYTES + GCM_TAG_BYTES);
  const ciphertext = envelope.subarray(1 + GCM_IV_BYTES + GCM_TAG_BYTES);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  // `final()` lève si le tag ne correspond pas : une ligne modifiée en base est
  // détectée, pas déchiffrée en silence.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

// ---------------------------------------------------------------------------
// Mots de passe
// ---------------------------------------------------------------------------

/**
 * scrypt, fourni par Node, donc sans dépendance native à compiler.
 *
 * Argon2id serait préférable sur le papier ; il impose une dépendance binaire
 * dans l'image Docker. Ces paramètres (N=2^15, r=8, p=1) coûtent environ 100 ms
 * et 32 Mio, ce qui est au-dessus des recommandations OWASP pour scrypt.
 */
const SCRYPT_PARAMS = { N: 32768, r: 8, p: 1, keylen: 32 } as const;

export async function hashPassword(password: string): Promise<string> {
  if (password.length < 12) {
    throw new Error('mot de passe trop court : 12 caractères minimum');
  }
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: 128 * SCRYPT_PARAMS.N * SCRYPT_PARAMS.r * 2,
  });

  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt.toString('base64'),
    derived.toString('base64'),
  ].join('$');
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4] ?? '', 'base64');
  const expected = Buffer.from(parts[5] ?? '', 'base64');

  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) return false;
  if (salt.length === 0 || expected.length === 0) return false;

  const derived = await scrypt(password, salt, expected.length, {
    N,
    r,
    p,
    maxmem: 128 * N * r * 2,
  });

  return nodeTimingSafeEqual(derived, expected);
}

// ---------------------------------------------------------------------------
// Jetons et identifiants
// ---------------------------------------------------------------------------

/** Base32 sans caractères ambigus : ni I, ni L, ni O, ni U. */
const ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

function randomBase32(length: number): string {
  // Rejet des valeurs qui tomberaient hors d'un multiple de 32, pour ne pas
  // biaiser la distribution vers le début de l'alphabet.
  const out: string[] = [];
  while (out.length < length) {
    for (const byte of randomBytes(length)) {
      if (byte < 248) out.push(ALPHABET[byte % 32]!);
      if (out.length === length) break;
    }
  }
  return out.join('');
}

export type IdPrefix =
  | 'org'
  | 'usr'
  | 'srv'
  | 'agt'
  | 'key'
  | 'al'
  | 'inc'
  | 'cmd'
  | 'ses'
  | 'mfa'
  | 'sub'
  | 'inv'
  | 'ntf'
  | 'det'
  | 'ban'
  | 'rul';

/** 26 caractères base32, soit 130 bits d'aléa. Non séquentiel, non énumérable. */
export function newId(prefix: IdPrefix): string {
  return `${prefix}_${randomBase32(26)}`;
}

/** Secret d'agent : 48 caractères, au-dessus du minimum de 32 imposé par l'agent. */
export function newAgentSecret(): string {
  return randomBytes(36).toString('base64url');
}

/** Jeton opaque pour session, invitation ou reset. Seul son hachage est stocké. */
export function newOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest();
}

/** Nonce de réponse : 32 caractères hex, même format que celui de l'agent. */
export function newResponseNonce(): string {
  return randomBytes(16).toString('hex');
}
