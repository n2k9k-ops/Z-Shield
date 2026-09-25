'use client';

/**
 * Détail d'un incident.
 *
 * L'objectif : comprendre un incident en quelques secondes. On montre la
 * timeline (ce qui s'est passé, dans l'ordre), la chaîne de preuve (les alertes
 * rattachées — des faits serveur, jamais une capture), le niveau de preuve
 * E0–E5 dérivé de ces alertes, et une zone de révision pour tracer une décision.
 */
import { use, useState } from 'react';
import Link from 'next/link';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead, State } from '@/components/ui';
import { SEVERITY_LABEL, CATEGORY_LABEL, formatDateTime, formatAge } from '@/lib/format';
import type { IncidentDetail, IncidentStatus, Me } from '@/lib/types';

const STATUSES: IncidentStatus[] = ['OPEN', 'INVESTIGATING', 'MITIGATED', 'RESOLVED', 'CLOSED'];

const KIND_LABEL: Record<string, string> = {
  created: 'Incident ouvert',
  status_changed: 'Statut modifié',
  severity_changed: 'Gravité modifiée',
  assigned: 'Assigné',
  comment: 'Note de révision',
  alert_linked: 'Alerte rattachée',
  alert_unlinked: 'Alerte détachée',
};

const EVIDENCE_LABEL: Record<string, string> = {
  E0: 'Signal faible',
  E1: 'Signal',
  E2: 'Anomalie confirmée',
  E3: 'Recoupée',
  E4: 'Preuve solide',
  E5: 'Triche prouvée',
};

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const detail = useResource<IncidentDetail>(`/api/incidents/${id}`);
  const me = useResource<Me>('/api/auth/me');

  const [note, setNote] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const canWrite = hasPermission(me.data?.permissions, 'incident.write');

  const setStatus = async (status: IncidentStatus) => {
    setMessage(null);
    try {
      await api.patch(`/api/incidents/${id}`, { status });
      detail.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  const addNote = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!note.trim()) return;
    setMessage(null);
    try {
      await api.post(`/api/incidents/${id}/comment`, { body: note.trim() });
      setNote('');
      detail.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Envoi impossible.');
    }
  };

  if (detail.loading && !detail.data) return <Loading />;
  if (detail.error || !detail.data) {
    return (
      <>
        <PageHead title="Incident" />
        <ErrorNotice message={detail.error ?? 'Incident introuvable.'} onRetry={detail.reload} />
      </>
    );
  }

  const { incident, timeline, alerts, evidence_level } = detail.data;

  return (
    <>
      <PageHead
        title={incident.title}
        lede={`Incident ${incident.id}`}
        actions={<Link className="button button--quiet" href="/incidents">← Incidents</Link>}
      />

      {message ? <ErrorNotice message={message} /> : null}

      {/* Résumé */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 20 }}>
        <div className="panel"><div className="panel__body">
          <div className="field__label">Statut</div>
          <div style={{ marginTop: 6 }}><State value={incident.status} /></div>
        </div></div>
        <div className="panel"><div className="panel__body">
          <div className="field__label">Gravité</div>
          <div style={{ marginTop: 6, fontWeight: 600 }}>{SEVERITY_LABEL[incident.severity] ?? incident.severity}</div>
        </div></div>
        <div className="panel"><div className="panel__body">
          <div className="field__label">Niveau de certitude</div>
          <div style={{ marginTop: 6, fontWeight: 700, fontSize: 18 }}>
            {EVIDENCE_LABEL[evidence_level] ?? evidence_level}
          </div>
        </div></div>
        <div className="panel"><div className="panel__body">
          <div className="field__label">Preuves</div>
          <div style={{ marginTop: 6 }}><span className="mono" style={{ fontSize: 20, fontWeight: 700 }}>{alerts.length}</span> <span style={{ opacity: 0.6, fontSize: 12.5 }}>alerte(s)</span></div>
        </div></div>
      </div>

      {canWrite ? (
        <div className="filters" style={{ marginBottom: 20 }}>
          <span className="field__label" style={{ alignSelf: 'center' }}>Changer le statut :</span>
          {STATUSES.map((s) => (
            <button
              key={s}
              type="button"
              className="button button--quiet"
              disabled={s === incident.status}
              onClick={() => void setStatus(s)}
            >
              {s}
            </button>
          ))}
        </div>
      ) : null}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        {/* Timeline */}
        <div className="panel">
          <div className="panel__body">
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Déroulé</div>
            <div style={{ opacity: 0.65, fontSize: 13, marginBottom: 14 }}>Ce qui s'est passé, dans l'ordre.</div>
            {timeline.length === 0 ? (
              <Empty title="Aucun évènement" />
            ) : (
              <ol style={{ listStyle: 'none', margin: 0, padding: 0, borderLeft: '1px solid rgba(255,255,255,.1)' }}>
                {timeline.map((event, i) => (
                  <li key={i} style={{ position: 'relative', paddingLeft: 18, paddingBottom: 16 }}>
                    <span style={{ position: 'absolute', left: -4, top: 5, width: 7, height: 7, borderRadius: '50%', background: '#2ee88a' }} />
                    <div style={{ fontWeight: 600, fontSize: 14 }}>{KIND_LABEL[event.kind] ?? event.kind}</div>
                    {event.body ? <div style={{ fontSize: 13.5, opacity: 0.85, marginTop: 3 }}>{event.body}</div> : null}
                    <div className="mono" style={{ fontSize: 11.5, opacity: 0.55, marginTop: 3 }}>
                      {formatDateTime(event.created_at)}{event.actor_name ? ` · ${event.actor_name}` : ''}
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>

        {/* Chaîne de preuve */}
        <div className="panel">
          <div className="panel__body panel__body--flush">
            <div style={{ padding: '16px 18px 0' }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Preuves</div>
              <div style={{ opacity: 0.65, fontSize: 13, marginBottom: 8 }}>Ce que le serveur a réellement observé.</div>
            </div>
            {alerts.length === 0 ? (
              <div style={{ padding: '0 18px 16px' }}><Empty title="Aucune alerte rattachée" /></div>
            ) : (
              <table className="table">
                <thead><tr><th>Catégorie</th><th>Gravité</th><th>Résumé</th><th>Quand</th></tr></thead>
                <tbody>
                  {alerts.map((a) => (
                    <tr key={a.id}>
                      <td>{CATEGORY_LABEL[a.category] ?? a.category}</td>
                      <td>{SEVERITY_LABEL[a.severity] ?? a.severity}</td>
                      <td>{a.summary}</td>
                      <td className="mono">{formatAge(a.occurred_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {/* Révision / appel */}
      {canWrite ? (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel__body">
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Révision</div>
            <div style={{ opacity: 0.65, fontSize: 13, marginBottom: 12 }}>
              Trace une décision ou une contestation. Ajoutée à la timeline, horodatée et signée.
            </div>
            <form onSubmit={addNote} style={{ display: 'flex', gap: 10 }}>
              <input
                id="incident-note"
                className="field__input"
                style={{ flex: 1 }}
                placeholder="Ex : faux positif confirmé, latence élevée du joueur — statut passé à résolu."
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <button type="submit" className="button" disabled={!note.trim()}>Ajouter</button>
            </form>
          </div>
        </div>
      ) : null}
    </>
  );
}
