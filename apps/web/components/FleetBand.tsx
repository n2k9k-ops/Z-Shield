'use client';

/**
 * Bande de flotte — l'élément le plus caractéristique de l'interface.
 *
 * Un segment par serveur. La LARGEUR suit la charge en joueurs, la couleur du
 * bandeau supérieur porte l'état. En un regard : où est le monde, et qu'est-ce
 * qui est tombé. C'est le seul endroit où l'interface se permet d'être
 * spectaculaire, et elle l'est en étant informative.
 *
 * Un serveur dont la métrique joueurs est désactivée garde une largeur
 * minimale : il ne doit pas disparaître visuellement sous prétexte qu'il ne
 * compte pas ses joueurs.
 */
import Link from 'next/link';
import type { Server } from '@/lib/types';
import { formatPlayers } from '@/lib/format';

const STATE_COLOR: Record<string, string> = {
  ONLINE: 'var(--green)',
  DEGRADED: 'var(--amber)',
  OFFLINE: 'var(--oxblood)',
  UNKNOWN: 'var(--rule-strong)',
};

export function FleetBand({ servers }: { servers: Server[] }) {
  if (servers.length === 0) {
    return (
      <div className="band band--empty">
        Aucun serveur connecté. Le premier apparaîtra ici dès son handshake.
      </div>
    );
  }

  const total = servers.reduce((sum, server) => sum + (server.players_online ?? 0), 0);

  return (
    <div className="band" role="list" aria-label="Flotte de serveurs">
      {servers.map((server) => {
        const players = server.players_online ?? 0;
        // Part de la largeur : proportionnelle à la charge, avec un plancher.
        const share = total > 0 ? players / total : 1 / servers.length;
        return (
          <Link
            key={server.id}
            href={`/servers/${server.id}`}
            role="listitem"
            className="band__seg"
            style={{
              flexGrow: Math.max(share * servers.length, 0.4),
              ['--state' as string]: STATE_COLOR[server.state] ?? STATE_COLOR.UNKNOWN,
            }}
          >
            <span className="band__name">{server.name}</span>
            <span className="band__players">{formatPlayers(server.players_online)}</span>
            <span className="band__meta">
              {server.max_players ? `sur ${server.max_players}` : server.environment}
            </span>
          </Link>
        );
      })}
    </div>
  );
}
