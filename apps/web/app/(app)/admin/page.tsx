'use client';

/**
 * Console vendeur (admin plateforme).
 *
 * Vue sur TOUS les clients et leurs serveurs, pour gérer les licences. Réservée
 * aux administrateurs plateforme. Chaque client garde son propre dashboard isolé
 * pour son serveur (joueurs, détections, bans) — ceci est la vue du vendeur.
 */
import { useState } from 'react';
import { ApiError, api } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead, State } from '@/components/ui';
import { formatAge } from '@/lib/format';
import type { AdminServer, Me } from '@/lib/types';

const PLANS = [
  { value: 'trial', label: 'Essai 7 j' },
  { value: 'starter', label: 'Starter 30 j' },
  { value: 'pro', label: 'Pro 30 j' },
  { value: 'enterprise', label: 'Enterprise 30 j' },
];

export default function AdminPage() {
  const me = useResource<Me>('/api/auth/me');
  const data = useResource<{ servers: AdminServer[] }>('/api/admin/servers');
  const [busy, setBusy] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ id: string; token: string } | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [filter, setFilter] = useState<'all' | 'unlicensed' | 'expired'>('all');

  if (me.data && me.data.is_platform_admin !== true) {
    return (
      <>
        <PageHead title="Console vendeur" />
        <Empty title="Accès réservé">Cette console est réservée à l’administrateur de la plateforme.</Empty>
      </>
    );
  }

  if (data.loading && !data.data) return <Loading />;

  const all = data.data?.servers ?? [];
  const servers = all.filter((s) =>
    filter === 'unlicensed' ? !s.license
      : filter === 'expired' ? s.license?.expired
      : true,
  );

  const issue = async (server: AdminServer, plan: string) => {
    setBusy(server.id);
    setMessage(null);
    setIssued(null);
    try {
      const res = await api.post<{ token: string }>(`/api/admin/servers/${server.id}/license`, { plan });
      setIssued({ id: server.id, token: res.token });
      data.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Émission impossible.');
    } finally {
      setBusy(null);
    }
  };

  const licenseCell = (s: AdminServer) => {
    if (!s.license) return <span className="tag" data-s="FLAGGED">Aucune licence</span>;
    if (s.license.expired) return <span className="tag" data-s="FLAGGED">Expirée</span>;
    return (
      <span className="tag" data-s="WATCH">
        {s.license.plan} · {s.license.days_left} j
      </span>
    );
  };

  const counts = {
    total: all.length,
    unlicensed: all.filter((s) => !s.license).length,
    expired: all.filter((s) => s.license?.expired).length,
  };

  return (
    <>
      <PageHead
        title="Console vendeur"
        lede="Tous tes clients et leurs serveurs. Émets et renouvelle les licences ici."
      />

      {message ? <ErrorNotice message={message} /> : null}
      {data.error ? <ErrorNotice message={data.error} onRetry={data.reload} /> : null}

      <div className="filters" style={{ marginBottom: 16 }}>
        <button type="button" className={`button ${filter === 'all' ? '' : 'button--quiet'}`} onClick={() => setFilter('all')}>
          Tous ({counts.total})
        </button>
        <button type="button" className={`button ${filter === 'unlicensed' ? '' : 'button--quiet'}`} onClick={() => setFilter('unlicensed')}>
          Sans licence ({counts.unlicensed})
        </button>
        <button type="button" className={`button ${filter === 'expired' ? '' : 'button--quiet'}`} onClick={() => setFilter('expired')}>
          Expirées ({counts.expired})
        </button>
      </div>

      <div className="panel">
        <div className="panel__body panel__body--flush">
          {servers.length === 0 ? (
            <Empty title="Aucun serveur ici" />
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>Serveur</th>
                  <th>État</th>
                  <th>Joueurs</th>
                  <th>Dernier signe</th>
                  <th>Licence</th>
                  <th>Émettre</th>
                </tr>
              </thead>
              <tbody>
                {servers.map((s) => (
                  <tr key={s.id}>
                    <td>{s.organization_name}</td>
                    <td>
                      {s.name}
                      {s.server_fingerprint ? (
                        <div className="mono" style={{ fontSize: 11, opacity: 0.5 }}>{s.server_fingerprint}</div>
                      ) : (
                        <div style={{ fontSize: 11, opacity: 0.45 }}>empreinte inconnue</div>
                      )}
                    </td>
                    <td><State value={s.state} /></td>
                    <td className="num">{s.players_online ?? '—'}</td>
                    <td className="mono">{formatAge(s.last_heartbeat_at)}</td>
                    <td>{licenseCell(s)}</td>
                    <td>
                      <select
                        className="field__select"
                        defaultValue=""
                        disabled={busy === s.id}
                        onChange={(e) => {
                          if (e.target.value) void issue(s, e.target.value);
                          e.target.value = '';
                        }}
                      >
                        <option value="">{busy === s.id ? '…' : 'Générer…'}</option>
                        {PLANS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {issued ? (
        <div className="panel" style={{ marginTop: 16 }}>
          <div className="panel__body">
            <div style={{ fontWeight: 600, marginBottom: 6 }}>Clé émise</div>
            <p className="page__lede" style={{ fontSize: 13, marginBottom: 8 }}>
              Livrée automatiquement au serveur via l’agent (rien à coller côté client). Copie possible si besoin.
            </p>
            <code className="code" style={{ wordBreak: 'break-all' }}>{issued.token}</code>
            <div style={{ marginTop: 10 }}>
              <button type="button" className="button button--quiet"
                      onClick={() => void navigator.clipboard.writeText(issued.token)}>
                Copier la clé
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
