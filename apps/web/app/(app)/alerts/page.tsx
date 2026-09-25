'use client';

/**
 * Alertes : la page de tri. Filtres en haut, lignes homogènes en dessous, et le
 * liseré de gravité à gauche pour que l'œil trouve le critique sans lire.
 */
import { useCallback, useMemo, useState } from 'react';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead, State } from '@/components/ui';
import { CATEGORY_LABEL, SEVERITY_LABEL, formatAge, formatDateTime } from '@/lib/format';
import type { Alert, AlertStatus, Me, Server } from '@/lib/types';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
const STATUSES: AlertStatus[] = ['OPEN', 'ACKNOWLEDGED', 'RESOLVED'];
const CATEGORIES = Object.keys(CATEGORY_LABEL);

export default function AlertsPage() {
  const [filters, setFilters] = useState({ server_id: '', severity: '', status: '', category: '' });
  const [message, setMessage] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const query = useMemo(() => {
    const params = new URLSearchParams({ limit: '100' });
    for (const [key, value] of Object.entries(filters)) {
      if (value) params.set(key, value);
    }
    return `/api/alerts?${params.toString()}`;
  }, [filters]);

  const alerts = useResource<{ alerts: Alert[] }>(query);
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const me = useResource<Me>('/api/auth/me');

  const refresh = useCallback(() => alerts.reload(), [alerts]);
  const { connected } = useRealtime(refresh);

  const canTriage = hasPermission(me.data?.permissions, 'alert.triage');
  const serverName = (id: string) =>
    servers.data?.servers.find((server) => server.id === id)?.name ?? id;

  const setStatus = async (alert: Alert, status: AlertStatus) => {
    setMessage(null);
    try {
      await api.patch(`/api/alerts/${alert.id}`, { status });
      alerts.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  const update = (key: keyof typeof filters) => (event: React.ChangeEvent<HTMLSelectElement>) =>
    setFilters((current) => ({ ...current, [key]: event.target.value }));

  if (alerts.loading && !alerts.data) return <Loading />;

  const list = alerts.data?.alerts ?? [];
  const filtered = Object.values(filters).some(Boolean);

  return (
    <>
      <PageHead
        title="Alertes"
        lede="Remontées par vos agents. Le compteur d’occurrences vient de la déduplication faite sur le serveur."
        actions={<LiveIndicator connected={connected} />}
      />

      {message ? <div className="notice">{message}</div> : null}
      {alerts.error ? <ErrorNotice message={alerts.error} onRetry={alerts.reload} /> : null}

      <div className="filters">
        <label className="field">
          <span className="field__label">Serveur</span>
          <select className="field__select" value={filters.server_id} onChange={update('server_id')}>
            <option value="">Tous</option>
            {(servers.data?.servers ?? []).map((server) => (
              <option key={server.id} value={server.id}>
                {server.name}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span className="field__label">Gravité</span>
          <select className="field__select" value={filters.severity} onChange={update('severity')}>
            <option value="">Toutes</option>
            {SEVERITIES.map((severity) => (
              <option key={severity} value={severity}>
                {SEVERITY_LABEL[severity]}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span className="field__label">Catégorie</span>
          <select className="field__select" value={filters.category} onChange={update('category')}>
            <option value="">Toutes</option>
            {CATEGORIES.map((category) => (
              <option key={category} value={category}>
                {CATEGORY_LABEL[category]}
              </option>
            ))}
          </select>
        </label>

        <label className="field">
          <span className="field__label">Statut</span>
          <select className="field__select" value={filters.status} onChange={update('status')}>
            <option value="">Tous</option>
            {STATUSES.map((status) => (
              <option key={status} value={status}>
                {status === 'OPEN' ? 'Ouverte' : status === 'ACKNOWLEDGED' ? 'Prise en compte' : 'Résolue'}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="strips">
        <div className="strips__head cols-alerts">
          <span>Gravité</span>
          <span>Résumé</span>
          <span>Serveur</span>
          <span className="strip__num">Occur.</span>
          <span>Reçue</span>
          <span>Statut</span>
        </div>

        {list.length === 0 ? (
          <Empty title={filtered ? 'Aucune alerte ne correspond à ces filtres' : 'Aucune alerte'}>
            {filtered
              ? 'Élargissez les filtres pour voir davantage.'
              : 'Vos agents n’ont encore rien signalé. C’est la situation normale sur un serveur sain.'}
          </Empty>
        ) : (
          list.map((alert) => (
            <div key={alert.id}>
              <div
                className="strip cols-alerts"
                data-severity={alert.severity}
                role="button"
                tabIndex={0}
                onClick={() => setExpanded(expanded === alert.id ? null : alert.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    setExpanded(expanded === alert.id ? null : alert.id);
                  }
                }}
              >
                <span className="strip__secondary">{SEVERITY_LABEL[alert.severity]}</span>
                <span className="strip__primary">{alert.summary}</span>
                <span className="strip__secondary">{serverName(alert.server_id)}</span>
                <span className="strip__num">{alert.occurrences > 1 ? `×${alert.occurrences}` : ''}</span>
                <span className="strip__secondary">{formatAge(alert.created_at)}</span>
                <State value={alert.status} />
              </div>

              {expanded === alert.id ? (
                <div style={{ padding: '12px 14px 16px 24px', borderBottom: '1px solid var(--rule)' }}>
                  <p className="page__lede">
                    {CATEGORY_LABEL[alert.category] ?? alert.category} · détectée{' '}
                    {formatDateTime(alert.occurred_at)}
                    {alert.occurrences > 1 && alert.last_occurrence_at
                      ? `, dernière occurrence ${formatDateTime(alert.last_occurrence_at)}`
                      : ''}
                    {alert.origin ? ` · signalée par ${alert.origin}` : ''}
                  </p>

                  {Object.keys(alert.metadata ?? {}).length > 0 ? (
                    <code className="code">
                      {Object.entries(alert.metadata)
                        .map(([key, value]) => `${key} = ${String(value)}`)
                        .join('\n')}
                    </code>
                  ) : null}

                  {canTriage ? (
                    <div style={{ display: 'flex', gap: 8 }}>
                      {alert.status === 'OPEN' ? (
                        <button type="button" className="button button--quiet"
                                onClick={() => void setStatus(alert, 'ACKNOWLEDGED')}>
                          Prendre en compte
                        </button>
                      ) : null}
                      {alert.status !== 'RESOLVED' ? (
                        <button type="button" className="button button--quiet"
                                onClick={() => void setStatus(alert, 'RESOLVED')}>
                          Marquer résolue
                        </button>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>
          ))
        )}
      </div>
    </>
  );
}
