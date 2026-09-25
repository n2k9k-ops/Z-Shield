/**
 * Matrice de permissions.
 *
 * Source unique de vérité pour « qui peut faire quoi ». Le frontend masque des
 * boutons ; il n'autorise rien. Chaque route sensible appelle `assertCan` avec
 * le rôle résolu en base à cette requête, jamais un rôle lu dans un cookie ou
 * un JWT : une rétrogradation doit prendre effet immédiatement, pas à
 * l'expiration de la session.
 *
 * La matrice est déclarative et testée exhaustivement (test/rbac.test.ts) :
 * ajouter une permission sans l'attribuer à un rôle fait échouer le test, ce
 * qui est préférable à une permission qui n'autorise silencieusement personne.
 */

export const ROLES = ['OWNER', 'ADMIN', 'STAFF', 'VIEWER'] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  'server.read',
  'server.write',
  'server.delete',
  'credential.manage',
  'command.issue',
  'configuration.write',
  'alert.read',
  'alert.triage',
  'incident.read',
  'incident.write',
  'member.read',
  'member.manage',
  'owner.manage',
  'audit.read',
  'analytics.read',
  'billing.manage',
  'organization.delete',
  'notification.manage',
  'detection.read',
  'ban.read',
  'ban.manage',
  'rule.read',
  'rule.manage',
  'anticheat.configure',
] as const;

export type Permission = (typeof PERMISSIONS)[number];

/**
 * Attribution explicite, sans héritage implicite entre rôles.
 *
 * Un héritage « ADMIN hérite de STAFF » est pratique jusqu'au jour où une
 * permission ajoutée à STAFF arrive chez ADMIN sans que personne l'ait décidé.
 */
const MATRIX: Record<Role, ReadonlySet<Permission>> = {
  OWNER: new Set<Permission>([
    'detection.read',
    'ban.read',
    'ban.manage',
    'rule.read',
    'rule.manage',
    'anticheat.configure',
    'server.read',
    'server.write',
    'server.delete',
    'credential.manage',
    'command.issue',
    'configuration.write',
    'alert.read',
    'alert.triage',
    'incident.read',
    'incident.write',
    'member.read',
    'member.manage',
    'owner.manage',
    'audit.read',
    'analytics.read',
    'billing.manage',
    'organization.delete',
    'notification.manage',
  ]),
  ADMIN: new Set<Permission>([
    'detection.read',
    'ban.read',
    'ban.manage',
    'rule.read',
    'rule.manage',
    'anticheat.configure',
    'server.read',
    'server.write',
    'server.delete',
    'credential.manage',
    'command.issue',
    'configuration.write',
    'alert.read',
    'alert.triage',
    'incident.read',
    'incident.write',
    'member.read',
    'member.manage',
    'audit.read',
    'analytics.read',
    'notification.manage',
  ]),
  STAFF: new Set<Permission>([
    'detection.read',
    'ban.read',
    'ban.manage',
    'rule.read',
    'server.read',
    'alert.read',
    'alert.triage',
    'incident.read',
    'incident.write',
    'member.read',
    'analytics.read',
  ]),
  VIEWER: new Set<Permission>([
    'detection.read',
    'ban.read',
    'rule.read',
    'server.read',
    'alert.read',
    'incident.read',
    'member.read',
    'analytics.read',
  ]),
};

export class ForbiddenError extends Error {
  readonly permission: Permission;
  readonly role: Role;

  constructor(role: Role, permission: Permission) {
    // Le message envoyé au client ne nomme pas la permission interne.
    super('insufficient permissions');
    this.name = 'ForbiddenError';
    this.role = role;
    this.permission = permission;
  }
}

export function can(role: Role, permission: Permission): boolean {
  return MATRIX[role].has(permission);
}

export function assertCan(role: Role, permission: Permission): void {
  if (!can(role, permission)) throw new ForbiddenError(role, permission);
}

export function permissionsOf(role: Role): Permission[] {
  return [...MATRIX[role]].sort();
}

// ---------------------------------------------------------------------------
// Invariants sur les changements de rôle
// ---------------------------------------------------------------------------

export type RoleChangeRefusal =
  | 'self_elevation'
  | 'self_demotion_last_owner'
  | 'owner_requires_owner'
  | 'last_owner_removal'
  | 'insufficient_permission';

export interface RoleChangeContext {
  actorRole: Role;
  actorUserId: string;
  targetUserId: string;
  targetCurrentRole: Role;
  targetNewRole: Role;
  /** Nombre d'OWNER de l'organisation, cible incluse. */
  ownerCount: number;
}

const RANK: Record<Role, number> = { VIEWER: 0, STAFF: 1, ADMIN: 2, OWNER: 3 };

/**
 * Retourne null si le changement est autorisé, sinon le motif du refus.
 *
 * Les deux règles qui comptent :
 *   - personne ne s'élève soi-même, pas même un OWNER. C'est ce qui empêche un
 *     ADMIN dont la session est volée de se promouvoir OWNER ;
 *   - une organisation garde au moins un OWNER, sinon plus personne ne peut
 *     gérer la facturation ni supprimer l'organisation, et le support doit
 *     intervenir en base.
 */
export function checkRoleChange(ctx: RoleChangeContext): RoleChangeRefusal | null {
  const isSelf = ctx.actorUserId === ctx.targetUserId;

  if (!can(ctx.actorRole, 'member.manage')) return 'insufficient_permission';

  if (isSelf && RANK[ctx.targetNewRole] > RANK[ctx.targetCurrentRole]) {
    return 'self_elevation';
  }

  // Seul un OWNER peut créer ou retirer un OWNER : un ADMIN qui pourrait
  // nommer des OWNER contournerait la hiérarchie en une étape.
  if (
    (ctx.targetNewRole === 'OWNER' || ctx.targetCurrentRole === 'OWNER') &&
    !can(ctx.actorRole, 'owner.manage')
  ) {
    return 'owner_requires_owner';
  }

  if (ctx.targetCurrentRole === 'OWNER' && ctx.targetNewRole !== 'OWNER' && ctx.ownerCount <= 1) {
    return isSelf ? 'self_demotion_last_owner' : 'last_owner_removal';
  }

  return null;
}

export interface MemberRemovalContext {
  actorRole: Role;
  actorUserId: string;
  targetUserId: string;
  targetRole: Role;
  ownerCount: number;
}

export function checkMemberRemoval(ctx: MemberRemovalContext): RoleChangeRefusal | null {
  if (!can(ctx.actorRole, 'member.manage')) return 'insufficient_permission';

  if (ctx.targetRole === 'OWNER' && !can(ctx.actorRole, 'owner.manage')) {
    return 'owner_requires_owner';
  }
  if (ctx.targetRole === 'OWNER' && ctx.ownerCount <= 1) {
    return 'last_owner_removal';
  }
  return null;
}
