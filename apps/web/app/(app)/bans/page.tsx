'use client';

/**
 * Bannissements & sanctions.
 *
 * Deux sous-vues :
 *   - Sanctions : la file de revue (status PENDING). Pour chacune, l'admin
 *     tranche — Confirmer le ban, Réduire en kick, ou Faux positif (l'anticheat
 *     apprend et relève le seuil du détecteur) ;
 *   - Bannissements : le registre appliqué (ACTIVE / LIFTED / EXPIRED / KICKED).
 *
 * L'exécution appartient à l'anticheat installé, qui lit ce registre et applique.
 * La plateforme n'agit jamais directement sur un joueur.
 */
import { useCallback, useMemo, useState } from 'react';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead } from '@/components/ui';
import { formatAge, formatDateTime } from '@/lib/format';
import type { Ban, Me } from '@/lib/types';

const SCOPE_LABEL: Record<string, string> = {
  license: 'License', discord: 'Discord', steam: 'Steam', ip: 'Adresse IP', fivem: 'FiveM',
};

type SubView = 'sanctions' | 'bannissements';

export default function BansPage() {
  const bans = useResource<{ bans: Ban[] }>('/api/bans');
  const me = useResource<Me>('/api/auth/me');
  const [sub, setSub] = useState<SubView>('sanctions');
  const [query, setQuery] = useState('');
  const [message, setMessage] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const refresh = useCallback(() => bans.reload(), [bans]);
  const { connected } = useRealtime(refresh);

  const canManage = hasPermission(me.data?.permissions, 'ban.manage');

  const list = bans.data?.bans ?? [];
  const pending = list.filter((b) => b.status === 'PENDING');
  const decided = list.filter((b) => b.status !== 'PENDING');

  const shown = useMemo(() => {
    const base = sub === 'sanctions' ? pending : decided;
    const q = query.trim().toLowerCase();
    if (!q) return base;
    return base.filter((b) =>
      (b.player_name ?? '').toLowerCase().includes(q) ||
      b.identifier.toLowerCase().includes(q) ||
      b.reason.toLowerCase().includes(q));
  }, [sub, pending, decided, query]);

  const act = async (ban: Ban, path: 'confirm' | 'kick' | 'false-positive', label: string) => {
    setMessage(null);
    setBusyId(ban.id);
    try {
      await api.post(`/api/bans/${ban.id}/${path}`, {});
      setMessage(label);
      await bans.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Action impossible.');
    } finally {
      setBusyId(null);
    }
  };

  const lift = async (ban: Ban) => {
    setMessage(null);
    setBusyId(ban.id);
    try {
      await api.post(`/api/bans/${ban.id}/lift`, { reason: 'Levé manuellement' });
      await bans.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Levée impossible.');
    } finally {
      setBusyId(null);
    }
  };

  if (bans.loading && !bans.data) return <Loading />;

  const active = decided.filter((b) => b.status === 'ACTIVE').length;
  const falsePositives = decided.filter((b) => b.status === 'DISMISSED').length;

  return (
    <>
      <PageHead
        title="Bans & sanctions"
        lede="Les sanctions en attente se tranchent ici. L’anticheat applique le registre ; la plateforme n’agit pas directement sur les joueurs."
        actions={<LiveIndicator connected={connected} />}
      />

      {message ? <div className="notice">{message}</div> : null}
      {bans.error ? <ErrorNotice message={bans.error} onRetry={bans.reload} /> : null}

      <div className="readouts">
        <div className="readout"><div className="readout__label">Sanctions à revoir</div><div className="readout__value">{pending.length}</div></div>
        <div className="readout"><div className="readout__label">Bans actifs</div><div className="readout__value">{active}</div></div>
        <div className="readout"><div className="readout__label">Faux positifs (appris)</div><div className="readout__value">{falsePositives}</div></div>
        <div className="readout"><div className="readout__label">Total enregistré</div><div className="readout__value">{list.length}</div></div>
      </div>

      <div className="seg" role="tablist" style={{ marginBottom: 16 }}>
        <button type="button" aria-pressed={sub === 'sanctions'} onClick={() => setSub('sanctions')}>
          Sanctions{pending.length ? ` · ${pending.length}` : ''}
        </button>
        <button type="button" aria-pressed={sub === 'bannissements'} onClick={() => setSub('bannissements')}>
          Bannissements
        </button>
      </div>

      <div className="searchbar">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth={2}>
          <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
        </svg>
        <input placeholder="Rechercher un joueur, un identifiant, une raison…"
               value={query} onChange={(e) => setQuery(e.target.value)} />
      </div>

      <div className="panel">
        <div className="panel__body panel__body--flush">
          {shown.length === 0 ? (
            <Empty title={sub === 'sanctions' ? 'Aucune sanction en attente' : 'Aucun bannissement'}>
              {sub === 'sanctions'
                ? 'Les détections à confiance moyenne arrivent ici pour validation.'
                : 'Les bannissements confirmés, automatiques et manuels apparaîtront ici.'}
            </Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Joueur</th><th>Raison</th><th>État</th><th>Preuve</th>
                  <th>Date</th><th className="col-shrink" />
                </tr>
              </thead>
              <tbody>
                {shown.map((ban) => (
                  <tr key={ban.id}>
                    <td>
                      <div style={{ fontWeight: 700 }}>{ban.player_name ?? '—'}</div>
                      <div className="mono" style={{ fontSize: 12, opacity: 0.6 }}>
                        {SCOPE_LABEL[ban.scope] ?? ban.scope} · {ban.identifier}
                      </div>
                    </td>
                    <td>
                      {ban.reason}
                      {ban.detection_category ? (
                        <div style={{ marginTop: 4 }}>
                          <span className="tag">{ban.detection_category}</span>
                        </div>
                      ) : null}
                    </td>
                    <td><BanState ban={ban} /></td>
                    <td>
                      <span className="tag" data-s={ban.evidence_kind === 'clip' ? 'ACTIVE' : undefined}>
                        {ban.evidence_kind === 'clip' ? '▶ Clip' : 'Capture'}
                      </span>
                    </td>
                    <td className="mono">{formatAge(ban.created_at)}</td>
                    <td className="num">
                      {canManage && ban.status === 'PENDING' ? (
                        <span style={{ display: 'inline-flex', gap: 6, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                          <button type="button" className="btn btn--sm" disabled={busyId === ban.id}
                                  onClick={() => void act(ban, 'confirm', `Ban confirmé pour ${ban.player_name ?? ban.identifier}`)}>
                            Confirmer
                          </button>
                          <button type="button" className="btn btn--ghost btn--sm" disabled={busyId === ban.id}
                                  onClick={() => void act(ban, 'kick', 'Réduit en kick')}>
                            Kick
                          </button>
                          <button type="button" className="btn btn--ghost btn--sm" disabled={busyId === ban.id}
                                  onClick={() => void act(ban, 'false-positive', 'Faux positif — l’anticheat apprend')}>
                            Faux positif
                          </button>
                        </span>
                      ) : canManage && ban.status === 'ACTIVE' ? (
                        <button type="button" className="btn btn--ghost btn--sm" disabled={busyId === ban.id}
                                onClick={() => void lift(ban)}>
                          Lever
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {sub === 'sanctions' && pending.length > 0 ? (
        <div className="notice" style={{ marginTop: 16 }}>
          Chaque décision entraîne l’anticheat : un « Faux positif » relève le seuil du
          détecteur concerné pour éviter de re-sanctionner ce comportement.
        </div>
      ) : null}
    </>
  );
}

function BanState({ ban }: { ban: Ban }) {
  if (ban.status === 'PENDING') return <span className="tag" data-s="PENDING">Sanction en attente</span>;
  const label =
    ban.status === 'ACTIVE' ? (ban.issued_by_auto ? 'Banni · Z-Shield' : 'Banni · Manuel')
    : ban.status === 'LIFTED' ? 'Levé'
    : ban.status === 'KICKED' ? 'Réduit en kick'
    : ban.status === 'DISMISSED' ? 'Faux positif'
    : 'Expiré';
  return <span className="tag" data-s={ban.status}>{label}</span>;
}
