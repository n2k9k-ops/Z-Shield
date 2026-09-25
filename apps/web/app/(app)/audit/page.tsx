'use client';

/**
 * Journal d'audit. En ajout seul côté base : le rôle applicatif n'a ni UPDATE
 * ni DELETE dessus, donc rien de ce qui s'affiche ici n'a pu être réécrit par
 * l'application qu'il surveille.
 */
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead } from '@/components/ui';
import { formatDateTime } from '@/lib/format';
import type { AuditEntry } from '@/lib/types';

const ACTION_LABEL: Record<string, string> = {
  'auth.login': 'Connexion',
  'auth.login_mfa_pending': 'Connexion, second facteur en attente',
  'auth.password_reset': 'Mot de passe réinitialisé',
  'organization.created': 'Organisation créée',
  'server.created': 'Serveur ajouté',
  'server.deleted': 'Serveur supprimé',
  'credential.created': 'Clé d’agent générée',
  'credential.revoked': 'Clé d’agent révoquée',
  'credential.rotation_started': 'Rotation de clé engagée',
  'configuration.updated': 'Configuration modifiée',
  'command.issued': 'Commande envoyée',
  'incident.created': 'Incident ouvert',
  'incident.updated': 'Incident mis à jour',
  'member.role_changed': 'Rôle modifié',
  'member.removed': 'Membre retiré',
  'agent.handshake': 'Handshake d’agent',
};

export default function AuditPage() {
  const entries = useResource<{ entries: AuditEntry[] }>('/api/audit-logs');

  if (entries.loading && !entries.data) return <Loading />;

  const list = entries.data?.entries ?? [];

  return (
    <>
      <PageHead
        title="Journal"
        lede="Deux cents dernières actions. Les entrées ne peuvent pas être modifiées ni supprimées."
      />

      {entries.error ? <ErrorNotice message={entries.error} onRetry={entries.reload} /> : null}

      <div className="strips">
        <div className="strips__head cols-audit">
          <span>Quand</span>
          <span>Action</span>
          <span>Auteur</span>
          <span>Cible</span>
        </div>

        {list.length === 0 ? (
          <Empty title="Journal vide" />
        ) : (
          list.map((entry) => (
            <div key={entry.id} className="strip cols-audit">
              <span className="strip__secondary">{formatDateTime(entry.created_at)}</span>
              <span className="strip__primary">{ACTION_LABEL[entry.action] ?? entry.action}</span>
              <span className="strip__secondary">
                {entry.actor_kind === 'agent'
                  ? `agent ${entry.actor_label ?? ''}`
                  : entry.actor_email ?? entry.actor_label ?? 'système'}
              </span>
              <span className="strip__secondary">
                {entry.target_id ? `${entry.target_kind ?? ''} ${entry.target_id}` : '—'}
              </span>
            </div>
          ))
        )}
      </div>
    </>
  );
}
