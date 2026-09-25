/**
 * Tests des primitives cryptographiques.
 *
 * Ce qui est vérifié ici n'est pas « le chiffrement fonctionne » mais les
 * propriétés dont dépend la sécurité du produit : une ligne altérée en base est
 * détectée, un mot de passe n'est pas déchiffrable, un identifiant n'est pas
 * devinable.
 */
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  constantTimeEqual,
  decryptSecret,
  encryptSecret,
  hashPassword,
  hashToken,
  hmacSha256Hex,
  newAgentSecret,
  newId,
  newResponseNonce,
  sha256Hex,
  verifyPassword,
} from '../src/lib/crypto.ts';

describe('HMAC-SHA256', () => {
  it('reproduit le vecteur 2 de la RFC 4231', () => {
    assert.equal(
      hmacSha256Hex('Jefe', 'what do ya want for nothing?'),
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    );
  });

  it("l'empreinte de la chaîne vide est la constante connue", () => {
    assert.equal(sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

describe('comparaison en temps constant', () => {
  it('accepte deux valeurs identiques', () => {
    assert.equal(constantTimeEqual('a'.repeat(64), 'a'.repeat(64)), true);
  });

  it('rejette une valeur différente', () => {
    assert.equal(constantTimeEqual('a'.repeat(64), `${'a'.repeat(63)}b`), false);
  });

  it('ne lève pas sur des longueurs différentes', () => {
    // timingSafeEqual lève si les longueurs diffèrent ; une exception non
    // rattrapée ici deviendrait un 500 au lieu d'un 401, donc une fuite
    // d'information sur la forme de la signature attendue.
    assert.doesNotThrow(() => constantTimeEqual('court', 'beaucoup plus long'));
    assert.equal(constantTimeEqual('court', 'beaucoup plus long'), false);
  });
});

describe('chiffrement des secrets au repos', () => {
  const key = randomBytes(32);

  it('fait un aller-retour fidèle', () => {
    const secret = newAgentSecret();
    assert.equal(decryptSecret(encryptSecret(secret, key), key), secret);
  });

  it('produit un chiffré différent à chaque appel (IV aléatoire)', () => {
    const a = encryptSecret('meme-secret', key);
    const b = encryptSecret('meme-secret', key);
    assert.notEqual(a.toString('hex'), b.toString('hex'));
  });

  it('détecte une altération du chiffré au lieu de déchiffrer en silence', () => {
    const envelope = encryptSecret('secret-agent', key);
    const last = envelope.length - 1;
    envelope.writeUInt8(envelope.readUInt8(last) ^ 0x01, last);
    assert.throws(() => decryptSecret(envelope, key));
  });

  it('détecte une altération du tag GCM', () => {
    const envelope = encryptSecret('secret-agent', key);
    envelope.writeUInt8(envelope.readUInt8(14) ^ 0xff, 14);
    assert.throws(() => decryptSecret(envelope, key));
  });

  it('refuse une mauvaise clé applicative', () => {
    const envelope = encryptSecret('secret-agent', key);
    assert.throws(() => decryptSecret(envelope, randomBytes(32)));
  });

  it('refuse une clé de mauvaise taille au lieu de la compléter', () => {
    assert.throws(() => encryptSecret('x', randomBytes(16)));
  });

  it('refuse une enveloppe tronquée', () => {
    assert.throws(() => decryptSecret(Buffer.alloc(8), key));
  });
});

describe('mots de passe', () => {
  it('vérifie un mot de passe correct', async () => {
    const stored = await hashPassword('correct horse battery staple');
    assert.equal(await verifyPassword('correct horse battery staple', stored), true);
  });

  it('rejette un mot de passe incorrect', async () => {
    const stored = await hashPassword('correct horse battery staple');
    assert.equal(await verifyPassword('correct horse battery stapl', stored), false);
  });

  it('ne stocke pas le mot de passe en clair', async () => {
    const stored = await hashPassword('correct horse battery staple');
    assert.equal(stored.includes('correct horse'), false);
    assert.match(stored, /^scrypt\$\d+\$\d+\$\d+\$/);
  });

  it('produit un hachage différent pour le même mot de passe (sel aléatoire)', async () => {
    const a = await hashPassword('correct horse battery staple');
    const b = await hashPassword('correct horse battery staple');
    assert.notEqual(a, b);
  });

  it('refuse un mot de passe trop court plutôt que de le hacher', async () => {
    await assert.rejects(() => hashPassword('court'));
  });

  it('rejette proprement un hachage stocké malformé', async () => {
    assert.equal(await verifyPassword('peu importe', 'pas-un-hachage'), false);
    assert.equal(await verifyPassword('peu importe', 'scrypt$1$2$3$$'), false);
  });
});

describe('identifiants et jetons', () => {
  it('respecte le format attendu par les contraintes SQL', () => {
    // Le schéma impose ^org_[0-9a-z]{26}$ : un générateur qui dérive produirait
    // une violation de contrainte au lieu d'un identifiant invalide silencieux.
    assert.match(newId('org'), /^org_[0-9a-z]{26}$/);
    assert.match(newId('srv'), /^srv_[0-9a-z]{26}$/);
  });

  it("n'utilise pas de caractères ambigus", () => {
    // Le préfixe de chaque identifiant contient lui-même des lettres exclues
    // de l'alphabet ('u' dans « usr_ ») : il faut le retirer de CHAQUE
    // identifiant, pas seulement du premier de la chaîne concaténée.
    const sample = Array.from({ length: 200 }, () => newId('usr').split('_')[1]!).join('');
    for (const character of ['i', 'l', 'o', 'u']) {
      assert.equal(sample.includes(character), false, `caractère ambigu : ${character}`);
    }
  });

  it('ne produit pas de collision sur un échantillon', () => {
    const seen = new Set(Array.from({ length: 5000 }, () => newId('al')));
    assert.equal(seen.size, 5000);
  });

  it('génère un secret d’agent au-dessus du minimum de 32 caractères exigé par l’agent', () => {
    assert.ok(newAgentSecret().length >= 32);
  });

  it('génère un nonce de réponse au format attendu par l’agent', () => {
    assert.match(newResponseNonce(), /^[0-9a-f]{32}$/);
  });

  it('hache les jetons de session de façon déterministe et non réversible', () => {
    const digest = hashToken('jeton-de-session');
    assert.equal(digest.length, 32);
    assert.equal(hashToken('jeton-de-session').toString('hex'), digest.toString('hex'));
    assert.equal(digest.toString('utf8').includes('jeton'), false);
  });
});
