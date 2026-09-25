/**
 * Tests TOTP. Vérifient l'algorithme contre les vecteurs de la RFC 6238, mais
 * surtout les deux propriétés dont dépend la sécurité du second facteur :
 * l'anti-rejeu et la borne de la fenêtre de tolérance.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  consumeRecoveryCode,
  currentStep,
  generateRecoveryCodes,
  generateTotpSecret,
  totpCodeForStep,
  totpUri,
  verifyTotp,
} from '../src/auth/totp.ts';

// Secret de la RFC 6238 ("12345678901234567890") encodé en base32.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('TOTP, vecteurs RFC 6238', () => {
  const vectors: Array<{ unixTime: number; code: string }> = [
    { unixTime: 59, code: '287082' },
    { unixTime: 1111111109, code: '081804' },
    { unixTime: 1111111111, code: '050471' },
    { unixTime: 1234567890, code: '005924' },
    { unixTime: 2000000000, code: '279037' },
  ];

  for (const vector of vectors) {
    it(`t=${vector.unixTime} produit ${vector.code}`, () => {
      const step = Math.floor(vector.unixTime / 30);
      assert.equal(totpCodeForStep(RFC_SECRET, step), vector.code);
    });
  }
});

describe('vérification TOTP', () => {
  const now = 1234567890 * 1000;

  it('accepte le code du pas courant', () => {
    const code = totpCodeForStep(RFC_SECRET, currentStep(now));
    const result = verifyTotp(RFC_SECRET, code, { now });
    assert.equal(result.valid, true);
    assert.equal(result.step, currentStep(now));
  });

  it('accepte le pas précédent et le suivant (horloge décalée)', () => {
    for (const offset of [-1, 1]) {
      const code = totpCodeForStep(RFC_SECRET, currentStep(now) + offset);
      assert.equal(verifyTotp(RFC_SECRET, code, { now }).valid, true, `offset ${offset}`);
    }
  });

  it('refuse un pas trop éloigné : la fenêtre est bornée', () => {
    for (const offset of [-2, 2, 10]) {
      const code = totpCodeForStep(RFC_SECRET, currentStep(now) + offset);
      const result = verifyTotp(RFC_SECRET, code, { now });
      assert.equal(result.valid, false, `offset ${offset} accepté à tort`);
      assert.equal(result.reason, 'mismatch');
    }
  });

  it('refuse un code déjà consommé, même s’il est mathématiquement correct', () => {
    const step = currentStep(now);
    const code = totpCodeForStep(RFC_SECRET, step);

    const first = verifyTotp(RFC_SECRET, code, { now });
    assert.equal(first.valid, true);

    // Deuxième présentation du même code, avec le pas mémorisé : un code reste
    // valable environ 90 s avec la fenêtre de tolérance, donc sans cette
    // vérification un code intercepté est rejouable pendant tout ce temps.
    const replayed = verifyTotp(RFC_SECRET, code, { now, lastUsedStep: first.step });
    assert.equal(replayed.valid, false);
    assert.equal(replayed.reason, 'replayed');
  });

  it('refuse aussi un pas antérieur au dernier consommé', () => {
    const step = currentStep(now);
    const previous = totpCodeForStep(RFC_SECRET, step - 1);
    const result = verifyTotp(RFC_SECRET, previous, { now, lastUsedStep: step });
    assert.equal(result.valid, false);
    assert.equal(result.reason, 'replayed');
  });

  it('rejette un format invalide sans calculer quoi que ce soit', () => {
    for (const bad of ['', '12345', '1234567', 'abcdef', '12 34 56 78']) {
      const result = verifyTotp(RFC_SECRET, bad, { now });
      assert.equal(result.valid, false);
      assert.equal(result.reason, 'malformed');
    }
  });

  it('tolère les espaces dans un code correct', () => {
    const code = totpCodeForStep(RFC_SECRET, currentStep(now));
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    assert.equal(verifyTotp(RFC_SECRET, spaced, { now }).valid, true);
  });
});

describe('secrets et URI', () => {
  it('génère un secret base32 de 160 bits', () => {
    const secret = generateTotpSecret();
    assert.match(secret, /^[A-Z2-7]{32}$/);
  });

  it('génère des secrets distincts', () => {
    const seen = new Set(Array.from({ length: 200 }, () => generateTotpSecret()));
    assert.equal(seen.size, 200);
  });

  it('produit une URI otpauth exploitable par une application d’authentification', () => {
    const uri = totpUri(RFC_SECRET, 'admin@example.test');
    assert.ok(uri.startsWith('otpauth://totp/ZShield%3Aadmin%40example.test?'));
    assert.ok(uri.includes(`secret=${RFC_SECRET}`));
    assert.ok(uri.includes('digits=6'));
    assert.ok(uri.includes('period=30'));
  });
});

describe('codes de récupération', () => {
  it('génère dix codes et autant de hachages', () => {
    const { codes, hashes } = generateRecoveryCodes();
    assert.equal(codes.length, 10);
    assert.equal(hashes.length, 10);
    for (const code of codes) assert.match(code, /^[0-9A-F]{5}-[0-9A-F]{5}$/);
  });

  it('ne stocke pas les codes en clair', () => {
    const { codes, hashes } = generateRecoveryCodes();
    for (const code of codes) {
      assert.equal(hashes.some((hash) => hash.includes(code)), false);
    }
  });

  it('consomme un code valide et le retire de la liste', () => {
    const { codes, hashes } = generateRecoveryCodes();
    const result = consumeRecoveryCode(codes[3]!, hashes);
    assert.equal(result.accepted, true);
    assert.equal(result.remaining.length, 9);
  });

  it('refuse un code déjà consommé : un code réutilisable n’est pas un facteur', () => {
    const { codes, hashes } = generateRecoveryCodes();
    const first = consumeRecoveryCode(codes[0]!, hashes);
    const second = consumeRecoveryCode(codes[0]!, first.remaining);
    assert.equal(second.accepted, false);
    assert.equal(second.remaining.length, 9);
  });

  it('refuse un code inconnu sans modifier la liste', () => {
    const { hashes } = generateRecoveryCodes();
    const result = consumeRecoveryCode('AAAAA-BBBBB', hashes);
    assert.equal(result.accepted, false);
    assert.equal(result.remaining.length, 10);
  });

  it('accepte un code saisi en minuscules ou avec des espaces', () => {
    const { codes, hashes } = generateRecoveryCodes();
    const result = consumeRecoveryCode(`  ${codes[0]!.toLowerCase()} `, hashes);
    assert.equal(result.accepted, true);
  });
});
