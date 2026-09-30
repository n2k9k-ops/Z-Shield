/**
 * Régression : la surface agent doit lire TOUT corps en brut (buffer), quel que
 * soit le Content-Type et même vide, sans jamais laisser le parseur JSON intégré
 * de Fastify répondre un 400 NON SIGNÉ (FST_ERR_CTP_EMPTY_JSON_BODY). Ce 400 non
 * signé poussait l'agent en boucle d'erreur (« response is missing signature
 * headers / status=400 »). Voir agent-gateway/routes.ts (removeAllContentTypeParsers
 * + parseur « * »).
 */
import { after, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';

// Réplique EXACTE de la configuration de corps de la surface agent.
function agentLikeApp() {
  const app = Fastify({ logger: false });
  return app.register(async (inst) => {
    inst.removeAllContentTypeParsers();
    inst.addContentTypeParser('*', { parseAs: 'buffer' }, (req, body, done) => {
      (req as unknown as { rawBody?: Buffer }).rawBody = body as Buffer;
      done(null, undefined);
    });
    inst.post('/v1/agents/handshake', async (req) => ({
      reached: true,
      rawLen: (req as unknown as { rawBody?: Buffer }).rawBody?.length ?? -1,
    }));
  }).then(() => app);
}

describe('surface agent — lecture brute du corps', () => {
  let app: Awaited<ReturnType<typeof agentLikeApp>>;
  after(async () => { if (app) await app.close(); });

  it('un corps VIDE avec charset atteint le handler (pas de 400 non signé)', async () => {
    app = await agentLikeApp();
    const r = await app.inject({
      method: 'POST', url: '/v1/agents/handshake',
      headers: { 'content-type': 'application/json; charset=utf-8' }, payload: '',
    });
    assert.equal(r.statusCode, 200, 'corps vide accepté');
    assert.equal(JSON.parse(r.body).rawLen, 0, 'le corps est lu en brut, longueur 0');
  });

  it('un corps JSON non vide atteint aussi le handler en brut', async () => {
    const r = await app.inject({
      method: 'POST', url: '/v1/agents/handshake',
      headers: { 'content-type': 'application/json; charset=utf-8' }, payload: '{"envelope":1}',
    });
    assert.equal(r.statusCode, 200);
    assert.ok(JSON.parse(r.body).rawLen > 0, 'le corps brut est transmis au handler');
  });

  it('un Content-Type inattendu est lu en brut, pas rejeté', async () => {
    const r = await app.inject({
      method: 'POST', url: '/v1/agents/handshake',
      headers: { 'content-type': 'text/plain' }, payload: 'x',
    });
    assert.equal(r.statusCode, 200, 'tout type est accepté (la signature décide ensuite)');
  });
});
