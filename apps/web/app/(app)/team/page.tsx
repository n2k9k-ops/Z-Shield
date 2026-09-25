'use client';

/**
 * Équipe et rôles.
 *
 * Les refus viennent du serveur et sont traduits ici en langage clair : « une
 * organisation doit garder un propriétaire » plutôt que « last_owner_removal ».
 * L'interface masque les actions impossibles, mais c'est le serveur qui décide.
 */
import { useState } from 'react';
import { ApiError, ROLE_LABEL, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead } from '@/components/ui';
import { formatAge, formatDateTime } from '@/lib/format';
import type { Me, Member, Role } from '@/lib/types';

const ROLES: Role[] = ['OWNER', 'ADMIN', 'STAFF', 'VIEWER'];

const REFUSAL: Record<string, string> = {
  last_owner_removal: 'Une organisation doit garder au moins un propriétaire.',
  self_demotion_last_owner:
    'Vous êtes le dernier propriétaire. Nommez quelqu’un d’autre avant de changer votre rôle.',
  self_elevation: 'Personne ne peut augmenter son propre rôle.',
  owner_requires_owner: 'Seul un propriétaire peut nommer ou retirer un propriétaire.',
  insufficient_permission: 'Votre rôle ne permet pas de gérer les membres.',
};

interface RbacMatrix {
  roles: string[];
  permissions: string[];
  grants: Record<string, string[]>;
}

/** Regroupement lisible des permissions par domaine, avec libellés FR. */
const PERMISSION_GROUPS: Array<{ group: string; items: Array<[string, string]> }> = [
  { group: 'Surveillance', items: [
    ['detection.read', 'Voir les détections & joueurs'],
    ['alert.read', 'Voir les alertes'],
    ['alert.triage', 'Trier les alertes'],
    ['incident.read', 'Voir les incidents'],
    ['incident.write', 'Gérer les incidents'],
    ['analytics.read', 'Voir les statistiques'],
    ['audit.read', 'Voir le journal d’audit'],
  ]},
  { group: 'Défense', items: [
    ['ban.read', 'Voir les bans'],
    ['ban.manage', 'Bannir / trancher les sanctions'],
    ['rule.read', 'Voir les règles'],
    ['rule.manage', 'Gérer les règles'],
    ['anticheat.configure', 'Configurer l’anticheat'],
  ]},
  { group: 'Serveurs', items: [
    ['server.read', 'Voir les serveurs'],
    ['server.write', 'Modifier les serveurs'],
    ['server.delete', 'Supprimer un serveur'],
    ['credential.manage', 'Gérer les clés d’agent'],
    ['command.issue', 'Envoyer des commandes'],
    ['configuration.write', 'Écrire la configuration'],
  ]},
  { group: 'Organisation', items: [
    ['member.read', 'Voir les membres'],
    ['member.manage', 'Gérer les membres'],
    ['owner.manage', 'Gérer les propriétaires'],
    ['billing.manage', 'Gérer la facturation'],
    ['notification.manage', 'Gérer les notifications'],
    ['organization.delete', 'Supprimer l’organisation'],
  ]},
];

export default function TeamPage() {
  const members = useResource<{ members: Member[] }>('/api/members');
  const matrix = useResource<RbacMatrix>('/api/rbac/matrix');
  const me = useResource<Me>('/api/auth/me');
  const [message, setMessage] = useState<string | null>(null);

  const canManage = hasPermission(me.data?.permissions, 'member.manage');

  const changeRole = async (member: Member, role: Role) => {
    setMessage(null);
    try {
      await api.patch(`/api/memberships/${member.id}`, { role });
      members.reload();
    } catch (cause) {
      if (cause instanceof ApiError) {
        // Le serveur renvoie le motif exact du refus ; on le rend lisible.
        setMessage(REFUSAL[cause.code] ?? cause.message);
      } else {
        setMessage('Modification impossible.');
      }
    }
  };

  const remove = async (member: Member) => {
    setMessage(null);
    try {
      await api.del(`/api/memberships/${member.id}`);
      members.reload();
    } catch (cause) {
      if (cause instanceof ApiError) {
        setMessage(REFUSAL[cause.code] ?? cause.message);
      } else {
        setMessage('Retrait impossible.');
      }
    }
  };

  if (members.loading && !members.data) return <Loading />;

  const list = members.data?.members ?? [];
  const owners = list.filter((member) => member.role === 'OWNER').length;

  return (
    <>
      <PageHead
        title="Équipe"
        lede={`${list.length} membre${list.length > 1 ? 's' : ''} · ${owners} propriétaire${owners > 1 ? 's' : ''}`}
      />

      {message ? (
        <div className="notice notice--error" role="alert">
          {message}
        </div>
      ) : null}
      {members.error ? <ErrorNotice message={members.error} onRetry={members.reload} /> : null}

      <div className="strips">
        <div className="strips__head cols-team">
          <span>Membre</span>
          <span>Adresse e-mail</span>
          <span>Rôle</span>
          <span>Dernière connexion</span>
          <span />
        </div>

        {list.length === 0 ? (
          <Empty title="Vous êtes seul pour l’instant" />
        ) : (
          list.map((member) => {
            const isSelf = member.user_id === me.data?.user.id;
            const lastOwner = member.role === 'OWNER' && owners <= 1;

            return (
              <div key={member.id} className="strip cols-team">
                <span className="strip__primary">
                  {member.display_name}
                  {isSelf ? <span className="strip__secondary"> · vous</span> : null}
                </span>
                <span className="strip__secondary">{member.email}</span>

                {canManage && !lastOwner ? (
                  <select
                    className="field__select"
                    value={member.role}
                    aria-label={`Rôle de ${member.display_name}`}
                    onChange={(event) => void changeRole(member, event.target.value as Role)}
                  >
                    {ROLES.map((role) => (
                      <option key={role} value={role}>
                        {ROLE_LABEL[role]}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span className="strip__secondary">{ROLE_LABEL[member.role]}</span>
                )}

                <span className="strip__secondary">
                  {member.last_login_at ? formatAge(member.last_login_at) : 'jamais'}
                </span>

                {canManage && !isSelf && !lastOwner ? (
                  <button type="button" className="button button--danger" onClick={() => void remove(member)}>
                    Retirer
                  </button>
                ) : (
                  <span className="strip__secondary">
                    {lastOwner ? 'dernier propriétaire' : ''}
                  </span>
                )}
              </div>
            );
          })
        )}
      </div>

      <div className="panel" style={{ marginTop: 20 }}>
        <div className="panel__head"><h2>Qui a accès à quelle fonctionnalité</h2></div>
        <div className="panel__body panel__body--flush">
          {matrix.data ? (
            <table className="table matrix">
              <thead>
                <tr>
                  <th>Fonctionnalité</th>
                  {matrix.data.roles.map((role) => (
                    <th key={role} className="num">{ROLE_LABEL[role as Role] ?? role}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {PERMISSION_GROUPS.map((grp) => (
                  <RoleGroup key={grp.group} group={grp} matrix={matrix.data!} />
                ))}
              </tbody>
            </table>
          ) : (
            <p className="page__lede" style={{ padding: 16 }}>Chargement des accès…</p>
          )}
        </div>
      </div>
      <p className="page__lede" style={{ marginTop: 12 }}>
        Cette matrice est la même qui autorise réellement côté serveur : l’interface la montre,
        c’est le serveur qui décide. Un retrait de membre coupe ses sessions immédiatement.
      </p>
    </>
  );
}

function RoleGroup({
  group,
  matrix,
}: {
  group: { group: string; items: Array<[string, string]> };
  matrix: RbacMatrix;
}) {
  return (
    <>
      <tr>
        <td colSpan={matrix.roles.length + 1}
            style={{ fontSize: 11, letterSpacing: '0.07em', textTransform: 'uppercase',
                     color: 'var(--text-faint)', fontWeight: 700 }}>
          {group.group}
        </td>
      </tr>
      {group.items.map(([perm, label]) => (
        <tr key={perm}>
          <td>{label}</td>
          {matrix.roles.map((role) => {
            const has = matrix.grants[role]?.includes(perm);
            return (
              <td key={role} className="num" aria-label={has ? 'autorisé' : 'refusé'}>
                {has ? (
                  <span style={{ color: 'var(--signal)', fontWeight: 800 }}>✓</span>
                ) : (
                  <span style={{ color: 'var(--text-faint)' }}>·</span>
                )}
              </td>
            );
          })}
        </tr>
      ))}
    </>
  );
}
