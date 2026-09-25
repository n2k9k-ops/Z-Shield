'use client';

/**
 * Incidents : regroupement de plusieurs alertes en un seul objet à suivre.
 * L'intérêt n'est pas la liste, c'est de pouvoir dire « ces trente alertes
 * sont la même histoire ».
 */
import { useState } from 'react';
import Link from 'next/link';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead, State } from '@/components/ui';
import { SEVERITY_LABEL, formatAge } from '@/lib/format';
import type { Incident, IncidentStatus, Me, Server } from '@/lib/types';

const STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'CLOSED'];

export default function IncidentsPage() {
  const incidents = useResource<{ incidents: Incident[] }>('/api/incidents');
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const me = useResource<Me>('/api/auth/me');

  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ title: '', description: '', severity: 'MEDIUM', server_id: '' });
  const [message, setMessage] = useState<string | null>(null);

  const canWrite = hasPermission(me.data?.permissions, 'incident.write');

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    setMessage(null);
    try {
      await api.post('/api/incidents', {
        title: form.title,
        severity: form.severity,
        ...(form.description ? { description: form.description } : {}),
        ...(form.server_id ? { server_id: form.server_id } : {}),
      });
      setCreating(false);
      setForm({ title: '', description: '', severity: 'MEDIUM', server_id: '' });
      incidents.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Création impossible.');
    }
  };

  const setStatus = async (incident: Incident, status: IncidentStatus) => {
    setMessage(null);
    try {
      await api.patch(`/api/incidents/${incident.id}`, { status });
      incidents.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  if (incidents.loading && !incidents.data) return <Loading />;

  const list = incidents.data?.incidents ?? [];
  const serverName = (id: string | null) =>
    id ? servers.data?.servers.find((server) => server.id === id)?.name ?? id : 'Toute la flotte';

  return (
    <>
      <PageHead
        title="Incidents"
        lede="Un incident rassemble les alertes qui racontent la même histoire."
        actions={
          canWrite ? (
            <button type="button" className="button" onClick={() => setCreating((value) => !value)}>
              {creating ? 'Annuler' : 'Ouvrir un incident'}
            </button>
          ) : undefined
        }
      />

      {message ? <div className="notice">{message}</div> : null}
      {incidents.error ? <ErrorNotice message={incidents.error} onRetry={incidents.reload} /> : null}

      {creating ? (
        <form className="panel" onSubmit={create}>
          <h2>Ouvrir un incident</h2>

          <label className="field">
            <span className="field__label">Titre</span>
            <input className="field__input" required maxLength={200} value={form.title}
                   onChange={(event) => setForm({ ...form, title: event.target.value })}
                   placeholder="Vague de téléportations sur le serveur principal" />
          </label>

          <label className="field">
            <span className="field__label">Ce que vous savez pour l’instant</span>
            <textarea className="field__input" rows={4} maxLength={20000} value={form.description}
                      onChange={(event) => setForm({ ...form, description: event.target.value })} />
          </label>

          <div style={{ display: 'flex', gap: 12 }}>
            <label className="field" style={{ flex: 1 }}>
              <span className="field__label">Gravité</span>
              <select className="field__select" value={form.severity}
                      onChange={(event) => setForm({ ...form, severity: event.target.value })}>
                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((severity) => (
                  <option key={severity} value={severity}>{SEVERITY_LABEL[severity]}</option>
                ))}
              </select>
            </label>

            <label className="field" style={{ flex: 1 }}>
              <span className="field__label">Serveur concerné</span>
              <select className="field__select" value={form.server_id}
                      onChange={(event) => setForm({ ...form, server_id: event.target.value })}>
                <option value="">Toute la flotte</option>
                {(servers.data?.servers ?? []).map((server) => (
                  <option key={server.id} value={server.id}>{server.name}</option>
                ))}
              </select>
            </label>
          </div>

          <button className="button" type="submit">Ouvrir l’incident</button>
        </form>
      ) : null}

      <div className="strips">
        <div className="strips__head cols-incidents">
          <span>Incident</span>
          <span>Gravité</span>
          <span>Serveur</span>
          <span className="strip__num">Alertes</span>
          <span>Statut</span>
        </div>

        {list.length === 0 ? (
          <Empty title="Aucun incident">
            {canWrite
              ? 'Depuis la page Alertes, rassemblez plusieurs alertes liées en un incident pour les suivre ensemble.'
              : 'Rien à suivre pour le moment.'}
          </Empty>
        ) : (
          list.map((incident) => (
            <div key={incident.id} className="strip cols-incidents" data-severity={incident.severity}>
              <span className="strip__primary">
                <Link href={`/incidents/${incident.id}`} style={{ textDecoration: 'none' }}>{incident.title}</Link>
                <span className="strip__secondary"> · ouvert {formatAge(incident.created_at)}</span>
              </span>
              <span className="strip__secondary">{SEVERITY_LABEL[incident.severity]}</span>
              <span className="strip__secondary">{serverName(incident.server_id)}</span>
              <span className="strip__num">{incident.alert_count}</span>
              {canWrite ? (
                <select
                  className="field__select"
                  value={incident.status}
                  aria-label={`Statut de ${incident.title}`}
                  onChange={(event) => void setStatus(incident, event.target.value as IncidentStatus)}
                >
                  {STATUSES.map((status) => (
                    <option key={status} value={status}>
                      {status === 'OPEN' ? 'Ouvert'
                        : status === 'INVESTIGATING' ? 'En analyse'
                        : status === 'MITIGATED' ? 'Contenu'
                        : status === 'RESOLVED' ? 'Résolu' : 'Clos'}
                    </option>
                  ))}
                </select>
              ) : (
                <State value={incident.status} />
              )}
            </div>
          ))
        )}
      </div>
    </>
  );
}
