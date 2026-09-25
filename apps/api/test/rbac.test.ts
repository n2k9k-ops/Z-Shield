/**
 * Tests de la matrice de permissions.
 *
 * L'exhaustivité est vérifiée : une permission ajoutée à la liste sans être
 * attribuée à aucun rôle fait échouer le test. Sans cela, une permission
 * orpheline n'autorise personne et la fonctionnalité correspondante paraît
 * cassée sans raison visible.
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  PERMISSIONS,
  ROLES,
  can,
  assertCan,
  checkMemberRemoval,
  checkRoleChange,
  permissionsOf,
  ForbiddenError,
  type Permission,
  type Role,
} from '../src/rbac/permissions.ts';

describe('matrice de permissions', () => {
  it('chaque permission est attribuée à au moins un rôle', () => {
    const orphans = PERMISSIONS.filter(
      (permission) => !ROLES.some((role) => can(role, permission)),
    );
    assert.deepEqual(orphans, [], `permissions orphelines : ${orphans.join(', ')}`);
  });

  it('chaque rôle a au moins la lecture', () => {
    for (const role of ROLES) {
      assert.equal(can(role, 'server.read'), true, `${role} ne peut pas lire les serveurs`);
    }
  });

  it('VIEWER est strictement en lecture', () => {
    const writePermissions: Permission[] = [
      'server.write',
      'server.delete',
      'credential.manage',
      'command.issue',
      'configuration.write',
      'alert.triage',
      'incident.write',
      'member.manage',
      'billing.manage',
      'organization.delete',
    ];
    for (const permission of writePermissions) {
      assert.equal(can('VIEWER', permission), false, `VIEWER ne devrait pas avoir ${permission}`);
    }
  });

  it('STAFF peut trier les alertes mais pas toucher à l’infrastructure', () => {
    assert.equal(can('STAFF', 'alert.triage'), true);
    assert.equal(can('STAFF', 'incident.write'), true);
    assert.equal(can('STAFF', 'server.write'), false);
    assert.equal(can('STAFF', 'credential.manage'), false);
    assert.equal(can('STAFF', 'command.issue'), false);
    assert.equal(can('STAFF', 'audit.read'), false);
  });

  it('seul OWNER gère la facturation, la suppression et les autres OWNER', () => {
    const ownerOnly: Permission[] = ['billing.manage', 'organization.delete', 'owner.manage'];
    for (const permission of ownerOnly) {
      assert.equal(can('OWNER', permission), true);
      for (const role of ['ADMIN', 'STAFF', 'VIEWER'] as Role[]) {
        assert.equal(can(role, permission), false, `${role} ne devrait pas avoir ${permission}`);
      }
    }
  });

  it('les permissions ne décroissent pas de VIEWER vers OWNER', () => {
    // Pas d'héritage implicite dans le code, mais la matrice doit rester
    // cohérente : un rôle supérieur ne doit pas perdre une capacité.
    const ladder: Role[] = ['VIEWER', 'STAFF', 'ADMIN', 'OWNER'];
    for (let index = 1; index < ladder.length; index += 1) {
      const lower = permissionsOf(ladder[index - 1]!);
      const higher = new Set(permissionsOf(ladder[index]!));
      for (const permission of lower) {
        assert.equal(
          higher.has(permission),
          true,
          `${ladder[index]} a perdu ${permission} que ${ladder[index - 1]} possède`,
        );
      }
    }
  });

  it('assertCan lève une ForbiddenError qui ne divulgue pas la permission au client', () => {
    assert.throws(
      () => assertCan('VIEWER', 'server.delete'),
      (error: unknown) => {
        assert.ok(error instanceof ForbiddenError);
        assert.equal(error.message, 'insufficient permissions');
        assert.equal(error.permission, 'server.delete');
        return true;
      },
    );
  });
});

describe('invariants de changement de rôle', () => {
  const base = {
    actorRole: 'OWNER' as Role,
    actorUserId: 'usr_actor',
    targetUserId: 'usr_target',
    targetCurrentRole: 'STAFF' as Role,
    targetNewRole: 'ADMIN' as Role,
    ownerCount: 2,
  };

  it('autorise un OWNER à promouvoir un STAFF en ADMIN', () => {
    assert.equal(checkRoleChange(base), null);
  });

  it("interdit l'auto-élévation, y compris à un OWNER", () => {
    assert.equal(
      checkRoleChange({
        ...base,
        actorUserId: 'usr_same',
        targetUserId: 'usr_same',
        targetCurrentRole: 'ADMIN',
        targetNewRole: 'OWNER',
      }),
      'self_elevation',
    );
  });

  it("interdit à un ADMIN de nommer un OWNER", () => {
    assert.equal(
      checkRoleChange({ ...base, actorRole: 'ADMIN', targetNewRole: 'OWNER' }),
      'owner_requires_owner',
    );
  });

  it("interdit à un ADMIN de rétrograder un OWNER", () => {
    assert.equal(
      checkRoleChange({
        ...base,
        actorRole: 'ADMIN',
        targetCurrentRole: 'OWNER',
        targetNewRole: 'VIEWER',
      }),
      'owner_requires_owner',
    );
  });

  it('empêche de retirer le dernier OWNER', () => {
    assert.equal(
      checkRoleChange({
        ...base,
        targetCurrentRole: 'OWNER',
        targetNewRole: 'ADMIN',
        ownerCount: 1,
      }),
      'last_owner_removal',
    );
  });

  it("empêche le dernier OWNER de se rétrograder lui-même", () => {
    assert.equal(
      checkRoleChange({
        ...base,
        actorUserId: 'usr_same',
        targetUserId: 'usr_same',
        targetCurrentRole: 'OWNER',
        targetNewRole: 'ADMIN',
        ownerCount: 1,
      }),
      'self_demotion_last_owner',
    );
  });

  it('autorise la rétrogradation d’un OWNER quand il en reste un autre', () => {
    assert.equal(
      checkRoleChange({
        ...base,
        targetCurrentRole: 'OWNER',
        targetNewRole: 'ADMIN',
        ownerCount: 2,
      }),
      null,
    );
  });

  it('refuse tout changement à un STAFF ou un VIEWER', () => {
    for (const role of ['STAFF', 'VIEWER'] as Role[]) {
      assert.equal(
        checkRoleChange({ ...base, actorRole: role }),
        'insufficient_permission',
      );
    }
  });

  it('autorise une auto-rétrogradation volontaire hors dernier OWNER', () => {
    assert.equal(
      checkRoleChange({
        ...base,
        actorUserId: 'usr_same',
        targetUserId: 'usr_same',
        targetCurrentRole: 'ADMIN',
        targetNewRole: 'VIEWER',
      }),
      null,
    );
  });
});

describe('retrait de membre', () => {
  it('empêche le retrait du dernier OWNER', () => {
    assert.equal(
      checkMemberRemoval({
        actorRole: 'OWNER',
        actorUserId: 'usr_a',
        targetUserId: 'usr_b',
        targetRole: 'OWNER',
        ownerCount: 1,
      }),
      'last_owner_removal',
    );
  });

  it("empêche un ADMIN de retirer un OWNER", () => {
    assert.equal(
      checkMemberRemoval({
        actorRole: 'ADMIN',
        actorUserId: 'usr_a',
        targetUserId: 'usr_b',
        targetRole: 'OWNER',
        ownerCount: 3,
      }),
      'owner_requires_owner',
    );
  });

  it('autorise un ADMIN à retirer un STAFF', () => {
    assert.equal(
      checkMemberRemoval({
        actorRole: 'ADMIN',
        actorUserId: 'usr_a',
        targetUserId: 'usr_b',
        targetRole: 'STAFF',
        ownerCount: 1,
      }),
      null,
    );
  });

  it('refuse le retrait par un STAFF', () => {
    assert.equal(
      checkMemberRemoval({
        actorRole: 'STAFF',
        actorUserId: 'usr_a',
        targetUserId: 'usr_b',
        targetRole: 'VIEWER',
        ownerCount: 1,
      }),
      'insufficient_permission',
    );
  });
});
