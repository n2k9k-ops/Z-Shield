'use client';

/**
 * Statistiques. Les séries sont agrégées en base (GROUP BY jour, gravité) :
 * renvoyer les lignes brutes et compter dans le navigateur ne tient pas au-delà
 * de quelques milliers d'alertes.
 */
import { useCallback } from 'react';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, Loading, LiveIndicator, PageHead } from '@/components/ui';
import { SEVERITY_LABEL, formatNumber } from '@/lib/format';
import type { AlertSeriesPoint, DetectionHourPoint, Server } from '@/lib/types';

const SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

const SEVERITY_COLOR: Record<string, string> = {
  INFO: 'var(--rule-strong)',
  LOW: 'var(--petrol)',
  MEDIUM: 'var(--amber)',
  HIGH: 'var(--oxblood)',
  CRITICAL: '#6d1b17',
};

export default function AnalyticsPage() {
  const series = useResource<{ series: AlertSeriesPoint[] }>('/api/analytics/alerts-per-day');
  const hourly = useResource<{ series: DetectionHourPoint[] }>('/api/analytics/detections-per-hour');
  const servers = useResource<{ servers: Server[] }>('/api/servers');

  // Rafraîchissement temps réel : le websocket pousse un évènement, on recharge
  // les deux séries. C'est le même canal que le reste de la console.
  const refresh = useCallback(() => {
    hourly.reload();
    series.reload();
  }, [hourly, series]);
  const { connected } = useRealtime(refresh);

  if (series.loading && !series.data) return <Loading />;

  // Aire des détections sur 24 h (temps réel).
  const hours = hourly.data?.series ?? [];
  const hourPeak = Math.max(1, ...hours.map((p) => p.total));
  const hourTotal = hours.reduce((sum, p) => sum + p.total, 0);
  const CW = 720;
  const CH = 140;
  const hx = (i: number) => (hours.length <= 1 ? 0 : (i * CW) / (hours.length - 1));
  const hy = (v: number) => CH - (v / hourPeak) * (CH - 12) - 6;
  const linePath = hours.map((p, i) => `${i ? 'L' : 'M'}${hx(i).toFixed(1)} ${hy(p.total).toFixed(1)}`).join(' ');
  const areaPath = hours.length
    ? `M0 ${CH} ${hours.map((p, i) => `L${hx(i).toFixed(1)} ${hy(p.total).toFixed(1)}`).join(' ')} L${CW} ${CH} Z`
    : '';

  const points = series.data?.series ?? [];

  // Regroupement par jour, gravités empilées.
  const byDay = new Map<string, Record<string, number>>();
  for (const point of points) {
    const day = point.day.slice(0, 10);
    const bucket = byDay.get(day) ?? {};
    bucket[point.severity] = (bucket[point.severity] ?? 0) + point.total;
    byDay.set(day, bucket);
  }

  const days = [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b));
  const peak = Math.max(
    1,
    ...days.map(([, bucket]) => Object.values(bucket).reduce((sum, value) => sum + value, 0)),
  );
  const total = days.reduce(
    (sum, [, bucket]) => sum + Object.values(bucket).reduce((inner, value) => inner + value, 0),
    0,
  );

  const list = servers.data?.servers ?? [];

  return (
    <>
      <PageHead
        title="Statistiques"
        lede="Temps réel et trente derniers jours."
        actions={<LiveIndicator connected={connected} />}
      />

      {series.error ? <ErrorNotice message={series.error} onRetry={series.reload} /> : null}

      <div className="panel">
        <h2>Détections — 24 dernières heures (live)</h2>
        {hours.length === 0 || hourTotal === 0 ? (
          <Empty title="Aucune détection sur 24 h">
            Le graphe se met à jour en direct dès qu'une détection est remontée.
          </Empty>
        ) : (
          <>
            <svg viewBox={`0 0 ${CW} ${CH}`} preserveAspectRatio="none"
                 style={{ width: '100%', height: 150 }}
                 role="img" aria-label={`${formatNumber(hourTotal)} détections sur 24 heures`}>
              <path d={areaPath} fill="#2ee88a" opacity="0.14" />
              <path d={linePath} fill="none" stroke="#2ee88a" strokeWidth="2" />
            </svg>
            <div className="bars__axis">
              <span>-24 h</span>
              <span>{formatNumber(hourTotal)} détections</span>
              <span>maintenant</span>
            </div>
          </>
        )}
      </div>

      <div className="panel">
        <h2>Alertes par jour</h2>

        {days.length === 0 ? (
          <Empty title="Pas encore de données">
            Les courbes se remplissent au fil des alertes remontées par vos agents.
          </Empty>
        ) : (
          <>
            <div className="bars" role="img"
                 aria-label={`${formatNumber(total)} alertes sur ${days.length} jours`}>
              {days.map(([day, bucket]) => (
                <div key={day} className="bars__col" title={day}>
                  {SEVERITY_ORDER.map((severity) => {
                    const value = bucket[severity] ?? 0;
                    if (value === 0) return null;
                    return (
                      <span
                        key={severity}
                        className="bars__part"
                        style={{
                          height: `${(value / peak) * 100}%`,
                          background: SEVERITY_COLOR[severity],
                        }}
                      />
                    );
                  })}
                </div>
              ))}
            </div>

            <div className="bars__axis">
              <span>{days[0]?.[0]}</span>
              <span>{formatNumber(total)} alertes au total</span>
              <span>{days[days.length - 1]?.[0]}</span>
            </div>

            <div className="legend">
              {SEVERITY_ORDER.map((severity) => (
                <span key={severity} className="legend__key">
                  <span className="legend__swatch" style={{ background: SEVERITY_COLOR[severity] }} />
                  {SEVERITY_LABEL[severity]}
                </span>
              ))}
            </div>
          </>
        )}
      </div>

      <div className="panel">
        <h2>Disponibilité des agents</h2>
        <p className="page__lede">
          Un agent est considéré joignable si son dernier battement est récent. Un battement
          manquant veut dire que l’agent ne joint plus la plateforme, pas que le serveur est
          compromis.
        </p>

        <div className="strips" style={{ marginTop: 12 }}>
          <div className="strips__head cols-commands">
            <span>Serveur</span>
            <span>Configuration</span>
            <span>Protocole</span>
            <span>Alertes ouvertes</span>
          </div>
          {list.length === 0 ? (
            <Empty title="Aucun serveur" />
          ) : (
            list.map((server) => (
              <div key={server.id} className="strip cols-commands">
                <span className="strip__primary">{server.name}</span>
                <span className="strip__secondary">v{server.config_version}</span>
                <span className="strip__secondary">
                  {server.protocol_version ? `v${server.protocol_version}` : '—'}
                </span>
                <span className="strip__secondary">{formatNumber(server.open_alerts)}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}
