/**
 * Test de conformité croisée Lua <-> Node.
 *
 * L'agent est déjà déployé chez des opérateurs. Si la plateforme construit la
 * chaîne canonique différemment, ne serait-ce que d'un séparateur, tous les
 * agents reçoivent un 401 et le message d'erreur ne dit rien d'utile. Ce test
 * est la seule protection contre cette classe de panne.
 *
 * Deux modes :
 *   - si `lua5.4` est disponible, les vecteurs sont régénérés en exécutant le
 *     vrai code de l'agent, ce qui détecte aussi une dérive de l'agent ;
 *   - sinon, les vecteurs figés dans `conformance/vectors.json` sont utilisés,
 *     ce qui détecte au moins une dérive de la plateforme.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { hmacSha256Hex, sha256Hex, constantTimeEqual } from '../src/lib/crypto.ts';
import { canonicalRequest, canonicalResponse, EMPTY_BODY_HASH } from '../src/agent-gateway/protocol.ts';

const here = dirname(fileURLToPath(import.meta.url));
const AGENT_ROOT = resolve(here, '../../../../zshield-agent');
const FIXTURE = resolve(here, 'conformance/agent_signature.lua');
const FROZEN = resolve(here, 'conformance/vectors.json');

interface RequestVector {
  name: string;
  method: string;
  path: string;
  query: string;
  agent_id: string;
  server_id: string;
  key_id: string;
  timestamp: number;
  nonce: string;
  body: string;
  body_hash: string;
  canonical: string;
  signature: string;
}

interface ResponseVector {
  status: number;
  request_id: string;
  timestamp: number;
  nonce: string;
  body: string;
  body_hash: string;
  canonical: string;
  signature: string;
}

interface Vectors {
  secret: string;
  cases: RequestVector[];
  responses: ResponseVector[];
}

function loadVectors(): { vectors: Vectors; source: 'lua' | 'frozen' } {
  try {
    const stdout = execFileSync('lua5.4', [FIXTURE, AGENT_ROOT], {
      encoding: 'utf8',
      timeout: 30_000,
    });
    return { vectors: JSON.parse(stdout) as Vectors, source: 'lua' };
  } catch {
    return { vectors: JSON.parse(readFileSync(FROZEN, 'utf8')) as Vectors, source: 'frozen' };
  }
}

const { vectors, source } = loadVectors();

describe(`conformité du protocole agent (vecteurs : ${source})`, () => {
  it('les vecteurs sont non vides', () => {
    assert.ok(vectors.cases.length >= 3, 'au moins trois cas de requête attendus');
    assert.ok(vectors.responses.length >= 2, 'au moins deux cas de réponse attendus');
  });

  for (const vector of vectors.cases) {
    describe(vector.name, () => {
      it('empreinte du corps identique', () => {
        assert.equal(sha256Hex(Buffer.from(vector.body, 'utf8')), vector.body_hash);
      });

      it('chaîne canonique identique, octet par octet', () => {
        const built = canonicalRequest({
          method: vector.method,
          path: vector.path,
          query: vector.query,
          agentId: vector.agent_id,
          serverId: vector.server_id,
          keyId: vector.key_id,
          timestamp: vector.timestamp,
          nonce: vector.nonce,
          bodyHash: vector.body_hash,
        });
        assert.equal(built, vector.canonical);
      });

      it('signature HMAC identique', () => {
        assert.equal(hmacSha256Hex(vectors.secret, vector.canonical), vector.signature);
      });

      it('une signature calculée avec un autre secret est rejetée', () => {
        const wrong = hmacSha256Hex(`${vectors.secret}x`, vector.canonical);
        assert.equal(constantTimeEqual(wrong, vector.signature), false);
      });
    });
  }

  for (const vector of vectors.responses) {
    it(`réponse ${vector.status} : chaîne canonique et signature identiques`, () => {
      const built = canonicalResponse({
        status: vector.status,
        requestId: vector.request_id,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
        bodyHash: vector.body_hash,
      });
      assert.equal(built, vector.canonical);
      assert.equal(hmacSha256Hex(vectors.secret, built), vector.signature);
    });
  }

  it('le corps vide a la même empreinte des deux côtés', () => {
    const getCase = vectors.cases.find((candidate) => candidate.body === '');
    assert.ok(getCase, 'un cas GET sans corps est attendu dans les vecteurs');
    assert.equal(getCase.body_hash, EMPTY_BODY_HASH);
    assert.equal(
      EMPTY_BODY_HASH,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      "l'empreinte SHA-256 de la chaîne vide est une constante connue",
    );
  });

  it('la méthode est signée : un POST rejoué en GET ne valide pas', () => {
    const vector = vectors.cases[0]!;
    const tampered = canonicalRequest({
      method: 'GET',
      path: vector.path,
      query: vector.query,
      agentId: vector.agent_id,
      serverId: vector.server_id,
      keyId: vector.key_id,
      timestamp: vector.timestamp,
      nonce: vector.nonce,
      bodyHash: vector.body_hash,
    });
    assert.notEqual(hmacSha256Hex(vectors.secret, tampered), vector.signature);
  });

  it('le chemin est signé : une requête rejouée sur un autre endpoint ne valide pas', () => {
    const vector = vectors.cases[0]!;
    const tampered = canonicalRequest({
      method: vector.method,
      path: '/v1/agents/credentials/rotate',
      query: vector.query,
      agentId: vector.agent_id,
      serverId: vector.server_id,
      keyId: vector.key_id,
      timestamp: vector.timestamp,
      nonce: vector.nonce,
      bodyHash: vector.body_hash,
    });
    assert.notEqual(hmacSha256Hex(vectors.secret, tampered), vector.signature);
  });

  it('la query est signée : passer version=3 à version=99 ne valide pas', () => {
    const vector = vectors.cases.find((candidate) => candidate.query !== '')!;
    const tampered = canonicalRequest({
      method: vector.method,
      path: vector.path,
      query: 'version=99',
      agentId: vector.agent_id,
      serverId: vector.server_id,
      keyId: vector.key_id,
      timestamp: vector.timestamp,
      nonce: vector.nonce,
      bodyHash: vector.body_hash,
    });
    assert.notEqual(hmacSha256Hex(vectors.secret, tampered), vector.signature);
  });

  describe('le corps brut est obligatoire, jamais une ré-sérialisation', () => {
    // Piège documenté dans ARCHITECTURE.md §1. Attention : sur un corps compact
    // sans échappement, JSON.stringify(JSON.parse(x)) rend souvent les mêmes
    // octets — y compris avec des accents, que Node n'échappe pas. C'est
    // précisément ce qui rend le bug dangereux : il passe les tests naïfs et
    // casse sur le premier encodeur qui ne fait pas les mêmes choix.
    const roundTrip = (raw: string) => JSON.stringify(JSON.parse(raw));

    it('un corps compact peut survivre au round-trip : ce test seul ne prouve rien', () => {
      const raw = '{"summary":"Téléportation détectée"}';
      assert.equal(roundTrip(raw), raw);
    });

    const divergences: Array<{ label: string; raw: string }> = [
      // Un encodeur qui échappe le non-ASCII (Python ensure_ascii, beaucoup de
      // bibliothèques Java) produit ceci ; Node le rend en UTF-8 littéral.
      { label: 'Unicode échappé', raw: '{"summary":"T\\u00e9l\\u00e9portation"}' },
      // Un proxy qui reformate, ou un encodeur avec indentation.
      { label: 'espaces insignifiants', raw: '{"severity": "HIGH", "occurrences": 50}' },
      // Lua écrit 1.0 là où Node écrit 1 : la valeur est égale, les octets non.
      { label: 'formatage numérique', raw: '{"confidence":1.0}' },
      // Un flottant dont la représentation courte diffère selon l'encodeur.
      { label: 'précision flottante', raw: '{"confidence":0.62000000000000001}' },
    ];

    for (const { label, raw } of divergences) {
      it(`${label} : le round-trip change les octets et invalide la signature`, () => {
        const rawHash = sha256Hex(Buffer.from(raw, 'utf8'));
        const reserialisedHash = sha256Hex(Buffer.from(roundTrip(raw), 'utf8'));
        assert.notEqual(reserialisedHash, rawHash);

        // Conséquence concrète : la vérification échoue alors que l'agent a
        // signé correctement.
        const signedByAgent = hmacSha256Hex(
          vectors.secret,
          canonicalRequest({
            method: 'POST',
            path: '/v1/agents/alerts',
            query: '',
            agentId: 'agt_x',
            serverId: 'srv_x',
            keyId: 'k1',
            timestamp: 1767225600,
            nonce: 'n',
            bodyHash: rawHash,
          }),
        );
        const recomputedByPlatform = hmacSha256Hex(
          vectors.secret,
          canonicalRequest({
            method: 'POST',
            path: '/v1/agents/alerts',
            query: '',
            agentId: 'agt_x',
            serverId: 'srv_x',
            keyId: 'k1',
            timestamp: 1767225600,
            nonce: 'n',
            bodyHash: reserialisedHash,
          }),
        );
        assert.notEqual(recomputedByPlatform, signedByAgent);
      });
    }
  });
});
