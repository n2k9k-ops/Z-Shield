'use client';

/**
 * Protections pilotables.
 *
 * Le client choisit, pour chaque serveur, quelles protections sont actives et
 * dans quel mode : « Surveiller » (observe et prévient) ou « Bloquer » (agit
 * seul). Le catalogue vient du serveur ; on n'enregistre que les choix. À
 * l'enregistrement, l'agent redemande sa configuration à son prochain battement.
 */
import { useEffect, useMemo, useState } from 'react';
import { api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead } from '@/components/ui';
import type {
  Me,
  ProtectionSettings,
  ProtectionSettingsCategory,
  Server,
} from '@/lib/types';

export default function ProtectionsPage() {
  const me = useResource<Me>('/api/auth/me');
  const servers = useResource<{ servers: Server[] }>('/api/servers');

  const [serverId, setServerId] = useState<string | null>(null);
  useEffect(() => {
    const list = servers.data?.servers ?? [];
    const first = list[0];
    if (first && (serverId === null || !list.some((s) => s.id === serverId))) {
      setServerId(first.id);
    }
  }, [servers.data, serverId]);

  const path = serverId ? `/api/servers/${serverId}/protection-settings` : null;
  const data = useResource<ProtectionSettings>(path);

  // État éditable local, initialisé à chaque chargement / changement de serveur.
  const [cats, setCats] = useState<ProtectionSettingsCategory[]>([]);
  const [tab, setTab] = useState(0);
  const [query, setQuery] = useState('');
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (data.data) {
      setCats(structuredClone(data.data.categories));
      setDirty(false);
      setSaved(false);
    }
  }, [data.data]);

  const canEdit = hasPermission(me.data?.permissions, 'configuration.write');
  const totalActive = useMemo(
    () => cats.reduce((n, c) => n + c.items.filter((i) => i.enabled).length, 0),
    [cats],
  );
  const total = useMemo(() => cats.reduce((n, c) => n + c.items.length, 0), [cats]);

  const mutate = (catId: string, itemId: string, patch: { enabled?: boolean; mode?: 'watch' | 'block' }) => {
    if (!canEdit) return;
    setCats((prev) =>
      prev.map((c) =>
        c.id !== catId
          ? c
          : { ...c, items: c.items.map((it) => (it.id === itemId ? { ...it, ...patch } : it)) },
      ),
    );
    setDirty(true);
    setSaved(false);
  };

  const save = async () => {
    if (!path || saving) return;
    setSaving(true);
    try {
      const items = cats.flatMap((c) =>
        c.items.map((it) => ({ id: it.id, enabled: it.enabled, mode: it.mode })),
      );
      await api.put(path, { items });
      setDirty(false);
      setSaved(true);
    } catch {
      // L'erreur reste visible via l'état "non enregistré".
    } finally {
      setSaving(false);
    }
  };

  if (!hasPermission(me.data?.permissions, 'detection.read') && !me.loading) {
    return (
      <>
        <PageHead title="Protections" />
        <Empty title="Accès non autorisé" />
      </>
    );
  }

  const serverList = servers.data?.servers ?? [];

  return (
    <>
      <PageHead
        title="Protections"
        lede="Choisis, pour chaque serveur, ce que Z-Shield surveille ou bloque. On bloque d'abord, on analyse ensuite — et jamais de capture d'écran des joueurs."
        actions={
          serverList.length > 0 ? (
            <label style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12.5, color: 'var(--text-soft)' }}>Serveur</span>
              <select
                className="field__select"
                style={{ width: 'auto', minWidth: 180 }}
                value={serverId ?? ''}
                onChange={(e) => setServerId(e.target.value)}
              >
                {serverList.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </label>
          ) : null
        }
      />

      <div className="notice">
        <b>Surveiller</b> = Z-Shield observe et te prévient. <b>Bloquer</b> = Z-Shield agit tout seul.
        Choisis pour chaque protection. <span style={{ color: 'var(--signal)' }}>· {totalActive}/{total} actives</span>
      </div>

      {servers.error ? <ErrorNotice message={servers.error} onRetry={servers.reload} /> : null}
      {data.error ? <ErrorNotice message={data.error} onRetry={data.reload} /> : null}

      {serverList.length === 0 && !servers.loading ? (
        <Empty title="Aucun serveur">
          Ajoute d'abord un serveur pour régler ses protections.
        </Empty>
      ) : null}

      {data.loading && cats.length === 0 ? <Loading /> : null}

      {cats.length > 0 ? (
        <>
          {/* Barre d'action : recherche + enregistrer */}
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' }}>
            <div className="searchbar" style={{ flex: 1, minWidth: 220, marginBottom: 0 }}>
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
                <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
              </svg>
              <input
                placeholder="Rechercher un réglage…"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                aria-label="Rechercher un réglage"
              />
            </div>
            {canEdit ? (
              <button className="btn" onClick={() => void save()} disabled={!dirty || saving}>
                {saving ? 'Enregistrement…' : saved && !dirty ? 'Enregistré ✓' : 'Enregistrer'}
              </button>
            ) : null}
          </div>

          {!canEdit ? (
            <div className="notice notice--warn">
              Tu peux consulter les protections mais pas les modifier (rôle limité).
            </div>
          ) : null}

          {/* Onglets de catégories (masqués pendant une recherche) */}
          {query.trim() === '' ? (
            <div className="tabs">
              {cats.map((c, i) => (
                <button
                  key={c.id}
                  type="button"
                  className="tab"
                  aria-pressed={i === tab}
                  onClick={() => setTab(i)}
                >
                  {c.label}
                  <span className="n">{c.items.filter((x) => x.enabled).length}/{c.items.length}</span>
                </button>
              ))}
            </div>
          ) : null}

          {/* Panneau des réglages */}
          <div className="panel">
            <ProtectionRows
              cats={cats}
              tab={tab}
              query={query}
              onToggle={(catId, itemId, enabled) => mutate(catId, itemId, { enabled })}
              onMode={(catId, itemId, mode) => mutate(catId, itemId, { mode })}
            />
          </div>
        </>
      ) : null}
    </>
  );
}

function ProtectionRows({
  cats,
  tab,
  query,
  onToggle,
  onMode,
}: {
  cats: ProtectionSettingsCategory[];
  tab: number;
  query: string;
  onToggle: (catId: string, itemId: string, enabled: boolean) => void;
  onMode: (catId: string, itemId: string, mode: 'watch' | 'block') => void;
}) {
  const q = query.trim().toLowerCase();
  const rows: { catId: string; catLabel: string; item: ProtectionSettingsCategory['items'][number]; showCat: boolean }[] =
    [];

  if (q) {
    for (const c of cats) {
      for (const it of c.items) {
        if (`${it.name} ${it.description} ${c.label}`.toLowerCase().includes(q)) {
          rows.push({ catId: c.id, catLabel: c.label, item: it, showCat: true });
        }
      }
    }
  } else {
    const c = cats[Math.min(tab, cats.length - 1)];
    if (c) for (const it of c.items) rows.push({ catId: c.id, catLabel: c.label, item: it, showCat: false });
  }

  if (rows.length === 0) {
    return <div className="empty">Aucun réglage trouvé.</div>;
  }

  return (
    <>
      {rows.map(({ catId, catLabel, item, showCat }) => (
        <div className="prot" key={`${catId}:${item.id}`} data-off={!item.enabled}>
          <div className="prot__main">
            <div className="prot__name">
              {showCat ? <span className="catmini">{catLabel}</span> : null}
              {item.name}
              <span className="help" title={item.description}>?</span>
            </div>
            <div className="prot__desc">{item.description}</div>
          </div>

          <div className="mode">
            <button
              type="button"
              data-m="watch"
              data-on={item.mode === 'watch'}
              onClick={() => onMode(catId, item.id, 'watch')}
            >
              Surveiller
            </button>
            <button
              type="button"
              data-m="block"
              data-on={item.mode === 'block'}
              onClick={() => onMode(catId, item.id, 'block')}
            >
              Bloquer
            </button>
          </div>

          <div
            className="switch"
            role="switch"
            aria-checked={item.enabled}
            aria-label={item.name}
            tabIndex={0}
            data-on={item.enabled}
            onClick={() => onToggle(catId, item.id, !item.enabled)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onToggle(catId, item.id, !item.enabled);
              }
            }}
          />
        </div>
      ))}
    </>
  );
}
