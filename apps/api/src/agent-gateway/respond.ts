/**
 * Émission des réponses signées.
 *
 * L'agent rejette **toute réponse non signée, y compris les erreurs, y compris
 * un 401**. Ce n'est pas une rigidité gratuite : sans cela, n'importe qui sur
 * le chemin réseau pourrait renvoyer un faux 401 et pousser l'agent dans l'état
 * « credential révoquée », qui coupe tout trafic jusqu'à intervention humaine.
 * Une réponse non signée est donc un déni de service à distance.
 *
 * Conséquence pratique : le gestionnaire d'erreurs global de Fastify NE DOIT
 * PAS répondre lui-même sur les routes `/v1/agents/*`. Tout passe par ici.
 *
 * Cas limite assumé : si la signature est impossible parce que la credential
 * n'a pas pu être résolue (clé inconnue), on ne peut pas signer. On renvoie
 * alors un 401 non signé, que l'agent traitera comme une réponse invalide et
 * réessaiera — ce qui est le comportement correct : mieux vaut qu'il réessaie
 * qu'il se verrouille sur la parole d'un inconnu.
 */
import type { FastifyReply } from 'fastify';
import { hmacSha256Hex, newResponseNonce, sha256Hex } from '../lib/crypto.ts';
import { RESPONSE_HEADER, canonicalResponse, type AgentErrorCode } from './protocol.ts';

export interface SignableContext {
  secret: string;
  requestId: string;
}

/**
 * Sérialise, signe et envoie. Le corps est sérialisé UNE fois et c'est cette
 * chaîne exacte qui est hachée puis envoyée : re-sérialiser après signature
 * (ce que ferait `reply.send(object)`) produirait une signature invalide.
 */
export function sendSigned(
  reply: FastifyReply,
  status: number,
  body: Record<string, unknown>,
  context: SignableContext,
): void {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = { ...body, server_time: timestamp, request_id: context.requestId };
  const serialised = JSON.stringify(payload);
  const nonce = newResponseNonce();

  const signature = hmacSha256Hex(
    context.secret,
    canonicalResponse({
      status,
      requestId: context.requestId,
      timestamp,
      nonce,
      bodyHash: sha256Hex(Buffer.from(serialised, 'utf8')),
    }),
  );

  reply
    .status(status)
    .header('Content-Type', 'application/json; charset=utf-8')
    .header(RESPONSE_HEADER.TIMESTAMP, String(timestamp))
    .header(RESPONSE_HEADER.NONCE, nonce)
    .header(RESPONSE_HEADER.SIGNATURE, signature)
    // Aucune raison de laisser un cache intermédiaire conserver une réponse
    // signée : elle est valable pour un seul request_id.
    .header('Cache-Control', 'no-store')
    .send(serialised);
}

export function sendSignedOk(
  reply: FastifyReply,
  data: Record<string, unknown>,
  context: SignableContext,
): void {
  sendSigned(reply, 200, { ok: true, ...data }, context);
}

export function sendSignedError(
  reply: FastifyReply,
  status: number,
  code: AgentErrorCode,
  message: string,
  context: SignableContext,
  retryAfter?: number,
): void {
  const body: Record<string, unknown> = { ok: false, error: code, message };
  if (typeof retryAfter === 'number') body.retry_after = retryAfter;
  sendSigned(reply, status, body, context);
}

/**
 * Dernier recours : erreur qu'on ne peut pas signer, faute de secret.
 * L'agent la traitera comme une réponse invalide et réessaiera, ce qui est
 * exactement ce qu'on veut.
 */
export function sendUnsignableError(
  reply: FastifyReply,
  status: number,
  code: AgentErrorCode,
  message: string,
  retryAfter?: number,
): void {
  const body: Record<string, unknown> = {
    ok: false,
    error: code,
    message,
    server_time: Math.floor(Date.now() / 1000),
  };
  if (typeof retryAfter === 'number') body.retry_after = retryAfter;

  reply
    .status(status)
    .header('Content-Type', 'application/json; charset=utf-8')
    .header('Cache-Control', 'no-store')
    .send(JSON.stringify(body));
}
