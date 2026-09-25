'use client';

import Link from 'next/link';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead, State } from '@/components/ui';
import { formatAge, formatDuration, formatNumber, formatPlayers } from '@/lib/format';
import { hasPermission } from '@/lib/api';
import type { Me, Server } from '@/lib/types';

export default function ServersPage() {
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const me = useResource<Me>('/api/auth/me');
  const { connected } = useRealtime(() => servers.reload());

  const canCreate = hasPermission(me.data?.permissions, 'server.write');

  if (servers.loading && !servers.data) return <Loading />;

  const list = servers.data?.servers ?? [];

  return (
    <>
      <PageHead
        title="Serveurs"
        lede="Un serveur par ligne. L’état vient du dernier battement reçu de son agent."
        actions={
          <span style={{ display: 'inline-flex', gap: 12, alignItems: 'center' }}>
            <LiveIndicator connected={connected} />
            {canCreate ? (
              <Link className="button" href="/servers/new">
                Ajouter un serveur
              </Link>
            ) : null}
          </span>
        }
      />

      {servers.error ? <ErrorNotice message={servers.error} onRetry={servers.reload} /> : null}

      <div className="strips">
        <div className="strips__head cols-servers">
          <span>Serveur</span>
          <span>État</span>
          <span className="strip__num">Joueurs</span>
          <span className="strip__num">Alertes</span>
          <span>Dernier battement</span>
          <span>Agent</span>
        </div>

        {list.length === 0 ? (
          <Empty title="Aucun serveur">
            {canCreate
              ? 'Ajoutez un serveur pour obtenir sa clé d’agent et les lignes à coller dans server.cfg.'
              : 'Demandez à un administrateur de votre organisation d’ajouter un serveur.'}
          </Empty>
        ) : (
          list.map((server) => (
            <Link key={server.id} href={`/servers/${server.id}`} className="strip cols-servers">
              <span className="strip__primary">
                {server.name}
                {server.environment !== 'production' ? (
                  <span className="strip__secondary"> · {server.environment}</span>
                ) : null}
              </span>
              <State value={server.state} />
              <span className="strip__num">{formatPlayers(server.players_online)}</span>
              <span className="strip__num">
                {Number(server.open_alerts) > 0 ? formatNumber(server.open_alerts) : '—'}
              </span>
              <span className="strip__secondary">{formatAge(server.last_heartbeat_at)}</span>
              <span className="strip__secondary">
                {server.agent_version ? `v${server.agent_version}` : 'jamais connecté'}
                {server.uptime_seconds != null
                  ? ` · ${formatDuration(server.uptime_seconds)}`
                  : ''}
              </span>
            </Link>
          ))
        )}
      </div>
    </>
  );
}
