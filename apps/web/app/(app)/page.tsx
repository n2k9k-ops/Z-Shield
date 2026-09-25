'use client';

/**
 * Vue d'ensemble.
 *
 * Ordre choisi pour la question que se pose l'exploitant en arrivant : « est-ce
 * que tout tourne ? », puis « qu'est-ce qui vient de se passer ? ». La bande de
 * flotte répond à la première sans lecture.
 */
import Link from 'next/link';
import { useCallback } from 'react';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { FleetBand } from '@/components/FleetBand';
import { Empty, ErrorNotice, LiveIndicator, Loading, State } from '@/components/ui';
import { CATEGORY_LABEL, SEVERITY_LABEL, formatAge, formatNumber } from '@/lib/format';
import type { Alert, Me, Overview, Server } from '@/lib/types';

/** Petites icônes filigrane pour le fond des cartes KPI. */
function FigIcon({ d }: { d: string }) {
  return (
    <div className="figure__ic" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.4}
           strokeLinecap="round" strokeLinejoin="round">
        <path d={d} />
      </svg>
    </div>
  );
}

export default function OverviewPage() {
  const me = useResource<Me>('/api/auth/me');
  const overview = useResource<{ overview: Overview }>('/api/overview');
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const alerts = useResource<{ alerts: Alert[] }>('/api/alerts?limit=8');

  const refresh = useCallback(() => {
    overview.reload();
    servers.reload();
    alerts.reload();
  }, [overview, servers, alerts]);

  const { connected } = useRealtime(refresh);

  if (servers.loading && !servers.data) return <Loading />;

  const list = servers.data?.servers ?? [];
  const figures = overview.data?.overview;
  const recent = alerts.data?.alerts ?? [];

  const firstName = (me.data?.user.display_name ?? '').split(/[\s_]+/)[0] || '';

  return (
    <>
      <div className="welcome">
        <h1 className="hello">Bon retour{firstName ? `, ${firstName}` : ''}</h1>
        <p className="subline">Voici l’état de tes serveurs Z-Shield en temps réel.</p>
        <LiveIndicator connected={connected} />
      </div>

      {servers.error ? <ErrorNotice message={servers.error} onRetry={servers.reload} /> : null}

      <FleetBand servers={list} />

      <div className="figures">
        <div className="figure">
          <FigIcon d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z" />
          <div className="figure__label">serveurs en ligne</div>
          <div className="figure__value">{formatNumber(figures?.servers_online)}</div>
        </div>
        <div className="figure">
          <FigIcon d="M9 8a3 3 0 1 0 0-.01M3.5 20a5.5 5.5 0 0 1 11 0M16 5.2a3.2 3.2 0 0 1 0 5.9M18.5 20a5.5 5.5 0 0 0-3-4.9" />
          <div className="figure__label">joueurs connectés</div>
          <div className="figure__value">{formatNumber(figures?.players_online)}</div>
        </div>
        <div className={Number(figures?.alerts_critical ?? 0) > 0 ? 'figure figure--alarm' : 'figure'}>
          <FigIcon d="M6 8a6 6 0 1 1 12 0c0 7 3 7 3 9H3c0-2 3-2 3-9M10 21a2 2 0 0 0 4 0" />
          <div className="figure__label">alertes ouvertes</div>
          <div className="figure__value">{formatNumber(figures?.alerts_open)}</div>
          {Number(figures?.alerts_critical ?? 0) > 0 ? (
            <div className="figure__delta down">
              <span className="mut">dont {formatNumber(figures?.alerts_critical)} critiques</span>
            </div>
          ) : (
            <div className="figure__delta up"><span className="mut">rien de critique</span></div>
          )}
        </div>
        <div className="figure">
          <FigIcon d="M12 12a3 3 0 1 0 0-.01M12 3a9 9 0 0 1 9 9M12 7a5 5 0 0 1 5 5" />
          <div className="figure__label">incidents en cours</div>
          <div className="figure__value">{formatNumber(figures?.incidents_open)}</div>
        </div>
      </div>

      <h2 style={{ marginBottom: 12 }}>Dernières alertes</h2>

      <div className="strips">
        <div className="strips__head cols-alerts">
          <span>Gravité</span>
          <span>Résumé</span>
          <span>Catégorie</span>
          <span className="strip__num">Occur.</span>
          <span>Reçue</span>
          <span>Statut</span>
        </div>

        {recent.length === 0 ? (
          <Empty title="Aucune alerte reçue">
            Les alertes remontées par vos agents apparaîtront ici, de la plus récente à la
            plus ancienne.
          </Empty>
        ) : (
          recent.map((alert) => (
            <Link
              key={alert.id}
              href={`/alerts?server_id=${alert.server_id}`}
              className="strip cols-alerts"
              data-severity={alert.severity}
            >
              <span className="strip__secondary">{SEVERITY_LABEL[alert.severity]}</span>
              <span className="strip__primary">{alert.summary}</span>
              <span className="strip__secondary">
                {CATEGORY_LABEL[alert.category] ?? alert.category}
              </span>
              {/*
                Le compteur d'occurrences vient de la déduplication faite par
                l'agent : 50 détections identiques en 30 s arrivent comme UNE
                alerte. Afficher le compteur, pas 50 lignes.
              */}
              <span className="strip__num">{alert.occurrences > 1 ? `×${alert.occurrences}` : ''}</span>
              <span className="strip__secondary">{formatAge(alert.created_at)}</span>
              <State value={alert.status} />
            </Link>
          ))
        )}
      </div>
    </>
  );
}
