/**
 * Garde d'accès de la surface utilisateur `/api/*`.
 *
 * Trois responsabilités, volontairement séparées de la passerelle agent :
 *
 *   1. résoudre la session depuis le cookie ;
 *   2. résoudre le rôle EN BASE à chaque requête ;
 *   3. exiger un jeton CSRF sur les mutations.
 *
 * Le cookie de session est `HttpOnly`, donc illisible par JavaScript, ce qui
 * exclut le patron « double submit » classique où le script recopie le cookie
 * dans un en-tête. On émet donc un second cookie, lisible celui-là, contenant
 * un jeton CSRF distinct ; le client le renvoie dans `X-CSRF-Token`. Un site
 * tiers peut déclencher une requête avec les cookies mais ne peut pas lire le
 * cookie CSRF pour composer l'en-tête.
 */
import type { FastifyReply, FastifyRequest } from 'fastify';
import { randomBytes } from 'node:crypto';
import { constantTimeEqual } from '../lib/crypto.ts';
import type { AuthService, SessionContext } from '../auth/sessions.ts';
import {
  ForbiddenError,
  assertCan,
  type Permission,
  type Role,
} from '../rbac/permissions.ts';

export const SESSION_COOKIE = 'zshield_session';
export const CSRF_COOKIE = 'zshield_csrf';
export const CSRF_HEADER = 'x-csrf-token';

export class UnauthorizedError extends Error {
  constructor(message = 'authentication required') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export class MfaRequiredError extends Error {
  constructor() {
    super('second factor required');
    this.name = 'MfaRequiredError';
  }
}

export class CsrfError extends Error {
  constructor() {
    super('invalid CSRF token');
    this.name = 'CsrfError';
  }
}

export interface RequestActor {
  session: SessionContext['session'];
  user: SessionContext['user'];
  organizationId: string;
  role: Role;
}

export function cookieOptions(isProduction: boolean, maxAgeSeconds: number) {
  return {
    httpOnly: true,
    // `Lax` bloque les requêtes cross-site non idempotentes tout en laissant
    // fonctionner un lien entrant. `Strict` casserait tout lien depuis un email.
    sameSite: 'lax' as const,
    secure: isProduction,
    path: '/',
    maxAge: maxAgeSeconds,
  };
}

export function issueCsrfToken(reply: FastifyReply, isProduction: boolean): string {
  const token = randomBytes(32).toString('base64url');
  reply.setCookie(CSRF_COOKIE, token, {
    // Lisible par le client : c'est tout l'intérêt, il doit le recopier dans
    // l'en-tête. Sa valeur n'est pas un secret d'authentification.
    httpOnly: false,
    sameSite: 'lax',
    secure: isProduction,
    path: '/',
    maxAge: 60 * 60 * 12,
  });
  return token;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function verifyCsrf(request: FastifyRequest): void {
  if (SAFE_METHODS.has(request.method)) return;

  const cookie = request.cookies[CSRF_COOKIE];
  const header = request.headers[CSRF_HEADER];

  if (typeof cookie !== 'string' || typeof header !== 'string' || cookie.length < 16) {
    throw new CsrfError();
  }
  if (!constantTimeEqual(cookie, header)) throw new CsrfError();
}

export class Guard {
  private readonly auth: AuthService;
  private readonly isProduction: boolean;

  constructor(auth: AuthService, isProduction: boolean) {
    this.auth = auth;
    this.isProduction = isProduction;
  }

  /** Session valide, second facteur satisfait, organisation et rôle résolus. */
  async actor(request: FastifyRequest): Promise<RequestActor> {
    const token = request.cookies[SESSION_COOKIE];
    if (typeof token !== 'string' || token.length < 16) throw new UnauthorizedError();

    const context = await this.auth.resolveSession(token);
    if (!context) throw new UnauthorizedError();

    if (!context.session.mfaSatisfied) throw new MfaRequiredError();

    const organizationId = context.session.organizationId;
    if (!organizationId) {
      throw new UnauthorizedError('session is not attached to an organization');
    }

    // Résolution systématique en base : le rôle n'est pas mis en cache dans la
    // session, donc un retrait d'adhésion coupe l'accès à la requête suivante.
    const role = await this.auth.resolveRole(context.session.userId, organizationId);
    if (!role) {
      throw new UnauthorizedError('membership no longer exists');
    }

    return { session: context.session, user: context.user, organizationId, role };
  }

  /** Comme `actor`, mais tolère une session dont la MFA n'est pas encore faite. */
  async pendingActor(request: FastifyRequest): Promise<SessionContext> {
    const token = request.cookies[SESSION_COOKIE];
    if (typeof token !== 'string') throw new UnauthorizedError();

    const context = await this.auth.resolveSession(token);
    if (!context) throw new UnauthorizedError();
    return context;
  }

  async require(request: FastifyRequest, permission: Permission): Promise<RequestActor> {
    verifyCsrf(request);
    const actor = await this.actor(request);
    assertCan(actor.role, permission);
    return actor;
  }

  /** Lecture : pas de CSRF à vérifier, mais permission tout de même exigée. */
  async requireRead(request: FastifyRequest, permission: Permission): Promise<RequestActor> {
    const actor = await this.actor(request);
    assertCan(actor.role, permission);
    return actor;
  }

  get production(): boolean {
    return this.isProduction;
  }
}

/**
 * Traduction des erreurs en réponses HTTP.
 *
 * Les corps sont volontairement pauvres : « insufficient permissions » sans
 * dire laquelle, « not found » plutôt que « exists but forbidden ». Distinguer
 * les deux permettrait d'énumérer les ressources d'une autre organisation.
 */
export function toHttpError(error: unknown): { status: number; body: Record<string, unknown> } {
  if (error instanceof UnauthorizedError) {
    return { status: 401, body: { error: 'unauthorized' } };
  }
  if (error instanceof MfaRequiredError) {
    return { status: 403, body: { error: 'mfa_required' } };
  }
  if (error instanceof CsrfError) {
    return { status: 403, body: { error: 'csrf_failed' } };
  }
  if (error instanceof ForbiddenError) {
    return { status: 403, body: { error: 'forbidden' } };
  }
  return { status: 500, body: { error: 'internal' } };
}
