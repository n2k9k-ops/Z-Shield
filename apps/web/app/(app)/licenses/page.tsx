'use client';

/**
 * Générateur de licences (panel admin).
 *
 * Émet une clé signée à coller dans le cœur (config/config.lua → license.key).
 * On choisit l'offre, la durée, et — pour empêcher le partage — l'empreinte du
 * serveur du client (affichée par le cœur au démarrage). « Aucune » = clé qui
 * marche partout.
 */
import { useState } from 'react';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, PageHead } from '@/components/ui';
import type { Me } from '@/lib/types';

const PLANS = [
  { value: 'trial', label: 'Essai (7 jours)', days: 7 },
  { value: 'starter', label: 'Starter (30 jours)', days: 30 },
  { value: 'pro', label: 'Pro (30 jours)', days: 30 },
  { value: 'enterprise', label: 'Enterprise (30 jours)', days: 30 },
];

interface Generated {
  token: string;
  plan: string;
  days: number;
  bound: boolean;
  expires_at: string;
}

export default function LicensesPage() {
  const me = useResource<Me>('/api/auth/me');
  const [plan, setPlan] = useState('trial');
  const [days, setDays] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [result, setResult] = useState<Generated | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const canGenerate = hasPermission(me.data?.permissions, 'billing.manage');

  if (!canGenerate && !me.loading) {
    return (
      <>
        <PageHead title="Licences" />
        <Empty title="Accès réservé" >Seul un propriétaire peut générer des licences.</Empty>
      </>
    );
  }

  const generate = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setResult(null);
    setCopied(false);
    try {
      const body: Record<string, unknown> = { plan };
      const d = Number(days);
      if (days.trim() && Number.isFinite(d) && d > 0) body.days = Math.floor(d);
      const fp = fingerprint.trim().toLowerCase();
      if (fp && fp !== 'any') body.server_fingerprint = fp;
      const res = await api.post<Generated>('/api/licenses/generate', body);
      setResult(res);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Génération impossible.');
    }
  };

  const copy = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <>
      <PageHead
        title="Licences"
        lede="Générez une clé à donner à un client. Il la colle dans son serveur, et la protection s'active."
      />

      <div className="panel">
        <div className="panel__body">
          <form onSubmit={generate} style={{ display: 'grid', gap: 16, maxWidth: 560 }}>
            <label className="field">
              <span className="field__label">Offre</span>
              <select className="field__select" value={plan} onChange={(e) => setPlan(e.target.value)}>
                {PLANS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </label>

            <label className="field">
              <span className="field__label">Durée personnalisée (jours) — optionnel</span>
              <input
                id="lic-days"
                className="field__input"
                inputMode="numeric"
                placeholder={`Par défaut : ${PLANS.find((p) => p.value === plan)?.days ?? 7} jours`}
                value={days}
                onChange={(e) => setDays(e.target.value)}
              />
            </label>

            <label className="field">
              <span className="field__label">Empreinte du serveur du client — optionnel</span>
              <input
                id="lic-fp"
                className="field__input"
                placeholder="Laisser vide = la clé marche partout"
                value={fingerprint}
                onChange={(e) => setFingerprint(e.target.value)}
              />
              <span style={{ fontSize: 12.5, opacity: 0.6, marginTop: 6 }}>
                16 caractères. Le client la voit au démarrage de son serveur :
                {' '}<span className="mono">[Z-Shield] Identifiant de ce serveur : …</span>.
                Renseignée, la clé ne marchera que sur SON serveur (anti-partage).
              </span>
            </label>

            <div>
              <button type="submit" className="button">Générer la clé</button>
            </div>
          </form>

          {error ? <div className="notice notice--error" style={{ marginTop: 16 }}>{error}</div> : null}

          {result ? (
            <div style={{ marginTop: 22 }}>
              <div className="field__label" style={{ marginBottom: 6 }}>
                Clé — offre {result.plan}, {result.days} jour(s),{' '}
                {result.bound ? 'liée à un serveur' : 'valable partout'} · expire le{' '}
                {new Date(result.expires_at).toLocaleDateString('fr-FR')}
              </div>
              <code className="code" style={{ wordBreak: 'break-all' }}>{result.token}</code>
              <div style={{ marginTop: 10, display: 'flex', gap: 10 }}>
                <button type="button" className="button button--quiet" onClick={() => void copy()}>
                  {copied ? 'Copié ✓' : 'Copier la clé'}
                </button>
              </div>
              <p className="page__lede" style={{ marginTop: 12, fontSize: 13 }}>
                Le client colle cette clé dans <code>zshield-ac/config/config.lua</code>
                {' '}(<code>license.key</code>) puis redémarre son serveur.
              </p>
            </div>
          ) : null}
        </div>
      </div>
    </>
  );
}
