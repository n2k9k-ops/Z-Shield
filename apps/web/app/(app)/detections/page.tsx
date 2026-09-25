'use client';

/**
 * Détections.
 *
 * Le flux brut de ce que le serveur a observé. Chaque ligne est un fait
 * mesuré — jamais une image, jamais un flux de la machine du joueur. La colonne
 * « preuve » montre la mesure qui a déclenché la détection.
 */
import { useCallback, useMemo, useState } from 'react';
import { hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead } from '@/components/ui';
import { DETECTION_LABEL, DISPOSITION_LABEL, formatAge } from '@/lib/format';
import type { Detection, Me, Server } from '@/lib/types';

const KINDS = Object.keys(DETECTION_LABEL);
const DISPOSITIONS = ['OBSERVED', 'FLAGGED', 'KICKED', 'BANNED', 'DISMISSED'];

export default function DetectionsPage() {
  const [filters, setFilters] = useState({ server_id: '', kind: '', disposition: '' });

  const query = useMemo(() => {
    const params = new URLSearchParams({ limit: '100' });
    for (const [key, value] of Object.entries(filters)) if (value) params.set(key, value);
    return `/api/detections?${params.toString()}`;
  }, [filters]);

  const detections = useResource<{ detections: Detection[] }>(query);
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const me = useResource<Me>('/api/auth/me');

  const refresh = useCallback(() => detections.reload(), [detections]);
  const { connected } = useRealtime(refresh);

  const update = (key: keyof typeof filters) => (event: React.ChangeEvent<HTMLSelectElement>) =>
    setFilters((current) => ({ ...current, [key]: event.target.value }));

  const serverName = (id: string) =>
    servers.data?.servers.find((s) => s.id === id)?.name ?? id;

  if (!hasPermission(me.data?.permissions, 'detection.read') && !me.loading) {
    return (
      <>
        <PageHead title="Détections" />
        <Empty title="Accès non autorisé" />
      </>
    );
  }

  if (detections.loading && !detections.data) return <Loading />;

  const list = detections.data?.detections ?? [];
  const filtered = Object.values(filters).some(Boolean);

  return (
    <>
      <PageHead
        title="Détections"
        lede="Ce que le serveur a observé. Chaque ligne est une mesure, pas une capture."
        actions={<LiveIndicator connected={connected} />}
      />

      {detections.error ? <ErrorNotice message={detections.error} onRetry={detections.reload} /> : null}

      <div className="filters">
        <label className="field">
          <span className="field__label">Serveur</span>
          <select className="field__select" value={filters.server_id} onChange={update('server_id')}>
            <option value="">Tous</option>
            {(servers.data?.servers ?? []).map((server) => (
              <option key={server.id} value={server.id}>{server.name}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Type</span>
          <select className="field__select" value={filters.kind} onChange={update('kind')}>
            <option value="">Tous</option>
            {KINDS.map((kind) => (
              <option key={kind} value={kind}>{DETECTION_LABEL[kind]}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field__label">Suite donnée</span>
          <select className="field__select" value={filters.disposition} onChange={update('disposition')}>
            <option value="">Toutes</option>
            {DISPOSITIONS.map((d) => (
              <option key={d} value={d}>{DISPOSITION_LABEL[d]}</option>
            ))}
          </select>
        </label>
      </div>

      <div className="panel">
        <div className="panel__body panel__body--flush">
          {list.length === 0 ? (
            <Empty title={filtered ? 'Aucune détection pour ces filtres' : 'Aucune détection'}>
              {filtered
                ? 'Élargissez les filtres.'
                : 'Le moteur de détection n’a encore rien relevé.'}
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Joueur</th>
                  <th>Serveur</th>
                  <th className="num">Confiance</th>
                  <th>Preuve</th>
                  <th>Quand</th>
                  <th>Suite</th>
                </tr>
              </thead>
              <tbody>
                {list.map((detection) => (
                  <tr key={detection.id}>
                    <td>{DETECTION_LABEL[detection.kind] ?? detection.kind}</td>
                    <td>{detection.player_name ?? detection.player_identifier}</td>
                    <td className="mono">{serverName(detection.server_id)}</td>
                    <td className="num">{detection.confidence}</td>
                    <td className="mono">
                      {Object.entries(detection.evidence)
                        .map(([key, value]) => `${key}=${String(value)}`)
                        .join(' · ') || '—'}
                    </td>
                    <td className="mono">{formatAge(detection.created_at)}</td>
                    <td>
                      <span className="tag" data-s={detection.disposition === 'DISMISSED' ? 'CLOSED' : detection.disposition === 'OBSERVED' ? 'WATCH' : 'FLAGGED'}>
                        {DISPOSITION_LABEL[detection.disposition]}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
