/**
 * Client HTTP.
 *
 * Trois choses qu'il fait et qui ne sont pas négociables :
 *
 *   1. `credentials: 'same-origin'` — la session est un cookie HttpOnly, il n'y
 *      a aucun jeton à stocker côté client. Rien de sensible ne transite par
 *      localStorage, où le moindre script tiers le lirait ;
 *   2. il recopie le cookie CSRF dans l'en-tête `X-CSRF-Token` sur toute
 *      mutation. Le cookie de session étant HttpOnly, c'est le second cookie,
 *      lisible, qui sert de preuve d'origine ;
 *   3. il ne masque pas les erreurs. Un 403 CSRF et un 403 de permission ne
 *      doivent pas produire le même message pour l'utilisateur.
 */
import type { Role } from './types';

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

function readCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match?.[1] ? decodeURIComponent(match[1]) : null;
}

/** Messages destinés à l'utilisateur : ce qui s'est passé, et quoi faire. */
function humanMessage(status: number, code: string): string {
  if (code === 'csrf_failed') return 'Session expirée. Rechargez la page et recommencez.';
  if (code === 'mfa_required') return 'Validez votre second facteur pour continuer.';
  if (code === 'forbidden') return 'Votre rôle ne permet pas cette action.';
  if (code === 'entitlement_exceeded') return 'Limite de votre offre atteinte.';
  if (code === 'validation') return 'Une valeur saisie est refusée.';
  if (code === 'account_locked') return 'Trop de tentatives. Réessayez dans quelques minutes.';
  if (code === 'invalid_credentials') return 'Adresse ou mot de passe incorrect.';
  if (status === 401) return 'Vous devez vous reconnecter.';
  if (status === 404) return 'Introuvable.';
  return 'Le serveur a renvoyé une erreur.';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);

  if (init.body !== undefined) headers.set('Content-Type', 'application/json');

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = readCookie('zshield_csrf');
    if (csrf) headers.set('X-CSRF-Token', csrf);
  }

  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' });

  if (response.status === 204) return undefined as T;

  let body: unknown = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }

  if (!response.ok) {
    const code = (body as { error?: string } | null)?.error ?? 'unknown';
    throw new ApiError(response.status, code, humanMessage(response.status, code));
  }

  return body as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, payload?: unknown) =>
    request<T>(path, { method: 'POST', body: payload === undefined ? undefined : JSON.stringify(payload) }),
  patch: <T>(path: string, payload: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(payload) }),
  put: <T>(path: string, payload: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(payload) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

/**
 * Les permissions viennent du serveur, qui seul décide. Le client s'en sert
 * uniquement pour ne pas afficher un bouton qui produirait un 403 — jamais
 * comme contrôle d'accès.
 */
export function hasPermission(permissions: string[] | undefined, permission: string): boolean {
  return Boolean(permissions?.includes(permission));
}

export const ROLE_LABEL: Record<Role, string> = {
  OWNER: 'Propriétaire',
  ADMIN: 'Administrateur',
  STAFF: 'Équipe',
  VIEWER: 'Lecture seule',
};
