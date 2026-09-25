'use client';

/**
 * Joueurs à risque.
 *
 * Cette page remplace, dans l'esprit « anticheat », la liste de joueurs qu'un
 * produit comme WaveShield afficherait. La différence est de fond : ce ne sont
 * pas « tous les joueurs connectés » — le protocole ne les transporte pas — mais
 * les joueurs qui ont produit au moins une détection, classés par score de
 * menace. On montre les suspects, pas l'annuaire, et sans jamais capturer leur
 * machine.
 */
import { useCallback, useState } from 'react';
import { api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Risk } from '@/components/Risk';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead } from '@/components/ui';
import { DETECTION_LABEL, formatAge, formatDateTime } from '@/lib/format';
import type { Detection, Me, ThreatPlayer } from '@/lib/types';

export default function PlayersPage() {
  const players = useResource<{ players: ThreatPlayer[] }>('/api/players');
  const me = useResource<Me>('/api/auth/me');
  const [selected, setSelected] = useState<string | null>(null);

  const refresh = useCallback(() => players.reload(), [players]);
  const { connected } = useRealtime(refresh);

  const canBan = hasPermission(me.data?.permissions, 'ban.manage');
  const canObserve = hasPermission(me.data?.permissions, 'command.issue');

  if (players.loading && !players.data) return <Loading />;

  const list = players.data?.players ?? [];
  const flagged = list.filter((p) => p.threat_score >= 70).length;

  return (
    <>
      <PageHead
        title="Joueurs à risque"
        lede="Classés par score de menace, calculé à partir des détections côté serveur."
        actions={<LiveIndicator connected={connected} />}
      />

      <div className="notice">
        ZShield n’affiche que les joueurs ayant déclenché au moins une détection, et n’accède
        jamais à leur écran ni à leur machine. Le score agrège les détections observées par le
        serveur, pondérées par leur gravité et amorties dans le temps.
      </div>

      {players.error ? <ErrorNotice message={players.error} onRetry={players.reload} /> : null}

      <div className="readouts">
        <div className="readout">
          <div className="readout__label">Joueurs suivis</div>
          <div className="readout__value">{list.length}</div>
        </div>
        <div className={flagged > 0 ? 'readout readout--alarm' : 'readout'}>
          <div className="readout__label">Score élevé (≥ 70)</div>
          <div className="readout__value">{flagged}</div>
        </div>
        <div className="readout">
          <div className="readout__label">Détections 24 h</div>
          <div className="readout__value">
            {list.reduce((sum, p) => sum + Number(p.detections_24h), 0)}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel__body panel__body--flush">
          {list.length === 0 ? (
            <Empty title="Aucun joueur à risque">
              Tant qu’aucune triche n’est détectée, cette liste reste vide — c’est la situation
              normale sur un serveur sain.
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Joueur</th>
                  <th>Identifiant</th>
                  <th className="num">Détections</th>
                  <th className="num">24 h</th>
                  <th>Vu</th>
                  <th className="num">Menace</th>
                </tr>
              </thead>
              <tbody>
                {list.map((player) => (
                  <tr
                    key={player.player_identifier}
                    className="clickable"
                    onClick={() =>
                      setSelected(
                        selected === player.player_identifier ? null : player.player_identifier,
                      )
                    }
                  >
                    <td>{player.player_name ?? 'Inconnu'}</td>
                    <td className="mono">{player.player_identifier}</td>
                    <td className="num">{player.detection_count}</td>
                    <td className="num">{player.detections_24h}</td>
                    <td className="mono">{formatAge(player.last_seen_at)}</td>
                    <td className="num">
                      <Risk score={player.threat_score} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {selected ? (
        <PlayerDetail
          identifier={selected}
          canBan={canBan}
          canObserve={canObserve}
          onClose={() => setSelected(null)}
          onChange={refresh}
        />
      ) : null}
    </>
  );
}

function PlayerDetail({
  identifier,
  canBan,
  canObserve,
  onClose,
  onChange,
}: {
  identifier: string;
  canBan: boolean;
  canObserve: boolean;
  onClose: () => void;
  onChange: () => void;
}) {
  const detail = useResource<{
    player: ThreatPlayer | null;
    detections: Detection[];
    active_ban: { id: string; reason: string } | null;
    dossier: {
      confidence: number;
      ban_history: Array<{
        id: string; scope: string; reason: string; status: string;
        issued_by_auto: boolean; created_at: string; expires_at: string | null;
      }>;
      servers_seen: Array<{ id: string; name: string }>;
      possible_alts: Array<{
        player_identifier: string; player_name: string | null;
        detections: number; last_seen: string;
      }>;
    } | null;
  }>(`/api/players/${encodeURIComponent(identifier)}`);
  const [message, setMessage] = useState<string | null>(null);

  const ban = async () => {
    setMessage(null);
    try {
      await api.post('/api/bans', {
        scope: 'license',
        identifier,
        reason: `Score de menace élevé (${detail.data?.player?.threat_score ?? '?'})`,
        player_name: detail.data?.player?.player_name ?? null,
      });
      setMessage('Bannissement enregistré. L’agent l’appliquera sur le serveur.');
      detail.reload();
      onChange();
    } catch {
      setMessage('Bannissement impossible.');
    }
  };

  const servers = detail.data?.dossier?.servers_seen ?? [];
  const observe = async () => {
    const server = servers[0];
    if (!server) { setMessage('Aucun serveur connu pour ce joueur.'); return; }
    setMessage(null);
    try {
      await api.post(`/api/servers/${server.id}/spectate`, { identifier });
      setMessage(
        'Observation demandée : une caméra serveur va suivre ce joueur dans le jeu. ' +
        'Aucune capture de son écran ni de sa machine.',
      );
    } catch {
      setMessage('Observation impossible.');
    }
  };

  return (
    <div className="panel">
      <div className="panel__head">
        <h2>{detail.data?.player?.player_name ?? identifier}</h2>
        <button type="button" className="btn btn--ghost btn--sm" onClick={onClose}>
          Fermer
        </button>
      </div>
      <div className="panel__body">
        {message ? <div className="notice">{message}</div> : null}

        {detail.data?.active_ban ? (
          <div className="notice notice--error">
            Ce joueur est déjà banni : {detail.data.active_ban.reason}
          </div>
        ) : canBan ? (
          <button
            type="button"
            className="btn btn--danger"
            onClick={() => void ban()}
            style={{ marginBottom: 14 }}
          >
            Bannir ce joueur
          </button>
        ) : null}

        {canObserve && servers.length > 0 ? (
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={() => void observe()}
            style={{ marginBottom: 14, marginLeft: canBan ? 8 : 0 }}
            title="Caméra d’administration dans le jeu — jamais l’écran du joueur"
          >
            Observer (caméra serveur)
          </button>
        ) : null}

        {detail.data?.dossier ? <Dossier dossier={detail.data.dossier} /> : null}

        <h3 style={{ marginBottom: 8 }}>Détections récentes</h3>
        {(detail.data?.detections ?? []).length === 0 ? (
          <p className="page__lede">Chargement…</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Type</th>
                <th className="num">Confiance</th>
                <th>Preuve</th>
                <th>Quand</th>
              </tr>
            </thead>
            <tbody>
              {(detail.data?.detections ?? []).map((detection) => (
                <tr key={detection.id}>
                  <td>{DETECTION_LABEL[detection.kind] ?? detection.kind}</td>
                  <td className="num">{detection.confidence}</td>
                  <td className="mono">
                    {Object.entries(detection.evidence)
                      .map(([key, value]) => `${key}=${String(value)}`)
                      .join(' · ') || '—'}
                  </td>
                  <td className="mono">{formatDateTime(detection.occurred_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const BAN_STATUS_LABEL: Record<string, string> = {
  ACTIVE: 'Actif', LIFTED: 'Levé', EXPIRED: 'Expiré',
  PENDING: 'En attente', KICKED: 'Kick', DISMISSED: 'Faux positif',
};

interface PlayerDossier {
  confidence: number;
  ban_history: Array<{
    id: string; scope: string; reason: string; status: string;
    issued_by_auto: boolean; created_at: string; expires_at: string | null;
  }>;
  servers_seen: Array<{ id: string; name: string }>;
  possible_alts: Array<{
    player_identifier: string; player_name: string | null;
    detections: number; last_seen: string;
  }>;
}

function Dossier({ dossier }: { dossier: PlayerDossier }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <h3 style={{ marginBottom: 8 }}>Renseignement joueur</h3>

      <div className="readouts" style={{ marginBottom: 14 }}>
        <div className="readout">
          <div className="readout__label">Score de confiance</div>
          <div className="readout__value"><Risk score={dossier.confidence} /></div>
        </div>
        <div className="readout">
          <div className="readout__label">Serveurs (cette organisation)</div>
          <div className="readout__value">{dossier.servers_seen.length}</div>
        </div>
        <div className="readout">
          <div className="readout__label">Comptes alternatifs possibles</div>
          <div className="readout__value">{dossier.possible_alts.length}</div>
        </div>
      </div>

      <p className="page__lede" style={{ marginTop: 0 }}>
        Réputation calculée sur les serveurs de cette organisation. Pas de réseau
        inter-organisations : rien n’est inventé.
      </p>

      {dossier.possible_alts.length > 0 ? (
        <>
          <h4 style={{ margin: '12px 0 6px' }}>Comptes alternatifs possibles</h4>
          <p className="field__hint" style={{ marginTop: 0 }}>
            Même pseudo sur un autre identifiant — indice à corréler, pas une preuve.
          </p>
          <table className="table">
            <thead><tr><th>Pseudo</th><th>Identifiant</th><th className="num">Détections</th><th>Vu</th></tr></thead>
            <tbody>
              {dossier.possible_alts.map((alt) => (
                <tr key={alt.player_identifier}>
                  <td>{alt.player_name ?? 'Inconnu'}</td>
                  <td className="mono">{alt.player_identifier}</td>
                  <td className="num">{alt.detections}</td>
                  <td className="mono">{formatAge(alt.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      <h4 style={{ margin: '12px 0 6px' }}>Historique des sanctions</h4>
      {dossier.ban_history.length === 0 ? (
        <p className="field__hint" style={{ marginTop: 0 }}>Aucune sanction enregistrée.</p>
      ) : (
        <table className="table">
          <thead><tr><th>Motif</th><th>Par</th><th>État</th><th>Date</th></tr></thead>
          <tbody>
            {dossier.ban_history.map((b) => (
              <tr key={b.id}>
                <td>{b.reason}</td>
                <td className="mono">{b.issued_by_auto ? 'Z-Shield' : 'Manuel'}</td>
                <td><span className="tag" data-s={b.status}>{BAN_STATUS_LABEL[b.status] ?? b.status}</span></td>
                <td className="mono">{formatAge(b.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
