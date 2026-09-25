/** Formatage. Séparé pour que les pages ne réinventent pas chacune leur version. */

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

/**
 * Âge relatif. Sur cette interface, « il y a 4 min » répond à la question que
 * se pose l'exploitant — « est-ce frais ? » — mieux qu'un horodatage absolu.
 */
export function formatAge(value: string | null | undefined): string {
  if (!value) return 'jamais';
  const then = new Date(value).getTime();
  if (Number.isNaN(then)) return '—';

  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (seconds < 60) return `il y a ${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `il y a ${hours} h`;
  return `il y a ${Math.round(hours / 24)} j`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} h ${minutes % 60} min`;
  return `${Math.floor(hours / 24)} j ${hours % 24} h`;
}

/**
 * Le protocole rend `players_online` ABSENT quand l'opérateur a désactivé la
 * métrique. Absent n'est pas zéro : afficher 0 joueur pour un serveur qui a
 * simplement coupé la remontée serait un mensonge sur le tableau de bord.
 */
export function formatPlayers(count: number | null | undefined): string {
  return count == null ? 'non mesuré' : String(count);
}

export function formatNumber(value: string | number | null | undefined): string {
  if (value == null) return '0';
  const numeric = typeof value === 'string' ? Number(value) : value;
  return Number.isFinite(numeric) ? numeric.toLocaleString('fr-FR') : '0';
}

export const SEVERITY_LABEL: Record<string, string> = {
  INFO: 'Info',
  LOW: 'Faible',
  MEDIUM: 'Moyenne',
  HIGH: 'Élevée',
  CRITICAL: 'Critique',
};

export const CATEGORY_LABEL: Record<string, string> = {
  event: 'Événement',
  entity: 'Entité',
  movement: 'Déplacement',
  economy: 'Économie',
  weapon: 'Arme',
  resource: 'Ressource',
  admin: 'Admin',
  agent: 'Agent',
  other: 'Autre',
};

export const STATE_LABEL: Record<string, string> = {
  ONLINE: 'En ligne',
  DEGRADED: 'Dégradé',
  OFFLINE: 'Hors ligne',
  UNKNOWN: 'Inconnu',
  HEALTHY: 'Sain',
  FAILED: 'En échec',
  OPEN: 'Ouverte',
  ACKNOWLEDGED: 'Prise en compte',
  RESOLVED: 'Résolue',
  INVESTIGATING: 'En analyse',
  MITIGATED: 'Contenu',
  CLOSED: 'Clos',
  PENDING: 'En attente',
  SENT: 'Envoyée',
  COMPLETED: 'Exécutée',
  REJECTED: 'Refusée par l’opérateur',
  EXPIRED: 'Expirée',
  DUPLICATE: 'Déjà exécutée',
};

export const DETECTION_LABEL: Record<string, string> = {
  teleport: 'Téléportation',
  speed: 'Vitesse anormale',
  godmode: 'Invincibilité (godmode)',
  noclip: 'Traversée de collision (noclip)',
  injected_event: 'Event injecté',
  firerate: 'Cadence de tir',
  entity_spam: 'Spawn d’entités',
  resource_tamper: 'Ressource altérée',
  economy: 'Anomalie d’économie',
  other: 'Autre',
};

export const DISPOSITION_LABEL: Record<string, string> = {
  OBSERVED: 'Observée',
  FLAGGED: 'Signalée',
  KICKED: 'Expulsé',
  BANNED: 'Banni',
  DISMISSED: 'Écartée',
};

export function threatColor(score: number): string {
  if (score >= 70) return 'var(--bad)';
  if (score >= 40) return 'var(--warn)';
  return 'var(--ok)';
}
