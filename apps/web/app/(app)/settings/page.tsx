'use client';

/**
 * Réglages : configuration distante des agents, et sessions actives.
 *
 * La configuration est validée deux fois — ici par les bornes des champs, et
 * côté serveur par le schéma STRICT de l'agent. Cette double validation n'est
 * pas de la redondance : l'agent rejette le document ENTIER s'il contient un
 * champ qu'il ne connaît pas, donc un réglage accepté à tort ici produirait un
 * serveur qui ignore silencieusement toute sa configuration.
 */
import { useEffect, useState } from 'react';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { Empty, ErrorNotice, Loading, PageHead } from '@/components/ui';
import { formatAge, formatDateTime } from '@/lib/format';
import type { Me, Server } from '@/lib/types';

interface SessionRow {
  id: string;
  ip: string | null;
  user_agent: string | null;
  created_at: string;
  last_seen_at: string;
  expires_at: string;
  current: boolean;
}

/** Bornes reprises du protocole. Les dépasser ferait rejeter le document. */
const BOUNDS = {
  heartbeat_interval: { min: 15, max: 900, label: 'Battement (secondes)' },
  telemetry_interval: { min: 30, max: 3600, label: 'Télémétrie (secondes)' },
  alert_batch_size: { min: 1, max: 200, label: 'Alertes par envoi' },
  alert_flush_interval: { min: 1, max: 300, label: 'Envoi des alertes (secondes)' },
} as const;

type BoundKey = keyof typeof BOUNDS;

export default function SettingsPage() {
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const sessions = useResource<{ sessions: SessionRow[] }>('/api/auth/sessions');
  const me = useResource<Me>('/api/auth/me');

  const [target, setTarget] = useState('');
  const [config, setConfig] = useState<Record<string, number | boolean | string>>({
    heartbeat_interval: 30,
    telemetry_interval: 60,
    alert_batch_size: 25,
    alert_flush_interval: 10,
    telemetry_enabled: true,
    log_level: 'INFO',
  });
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const list = servers.data?.servers ?? [];

  useEffect(() => {
    if (!target && list[0]) setTarget(list[0].id);
  }, [list, target]);

  const canWrite = hasPermission(me.data?.permissions, 'configuration.write');

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.put<{ config_version: number }>(
        `/api/servers/${target}/configuration`,
        config,
      );
      setMessage(
        `Configuration enregistrée en version ${result.config_version}. L’agent l’appliquera à son prochain battement — il n’y a pas de push vers votre serveur.`,
      );
      servers.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Enregistrement impossible.');
    } finally {
      setBusy(false);
    }
  };

  const revokeSession = async (session: SessionRow) => {
    try {
      await api.del(`/api/auth/sessions/${session.id}`);
      sessions.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Révocation impossible.');
    }
  };

  if (servers.loading && !servers.data) return <Loading />;

  return (
    <>
      <PageHead title="Réglages" lede="Ce que vos agents remontent, et vos appareils connectés." />

      {message ? <div className="notice">{message}</div> : null}
      {servers.error ? <ErrorNotice message={servers.error} onRetry={servers.reload} /> : null}

      <form className="panel" onSubmit={save}>
        <h2>Ce que remonte un agent</h2>

        {list.length === 0 ? (
          <Empty title="Ajoutez un serveur pour régler son agent" />
        ) : (
          <>
            <label className="field">
              <span className="field__label">Serveur</span>
              <select className="field__select" value={target}
                      onChange={(event) => setTarget(event.target.value)}>
                {list.map((server) => (
                  <option key={server.id} value={server.id}>
                    {server.name} (configuration v{server.config_version})
                  </option>
                ))}
              </select>
            </label>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
              {(Object.keys(BOUNDS) as BoundKey[]).map((key) => (
                <label className="field" key={key} style={{ flex: '1 1 180px' }}>
                  <span className="field__label">{BOUNDS[key].label}</span>
                  <input
                    className="field__input"
                    type="number"
                    min={BOUNDS[key].min}
                    max={BOUNDS[key].max}
                    value={Number(config[key])}
                    disabled={!canWrite}
                    onChange={(event) =>
                      setConfig({ ...config, [key]: Number(event.target.value) })
                    }
                  />
                  <span className="field__label">
                    de {BOUNDS[key].min} à {BOUNDS[key].max}
                  </span>
                </label>
              ))}
            </div>

            <label className="field">
              <span className="field__label">Niveau de journalisation de l’agent</span>
              <select className="field__select" value={String(config.log_level)} disabled={!canWrite}
                      onChange={(event) => setConfig({ ...config, log_level: event.target.value })}>
                {['DEBUG', 'INFO', 'WARN', 'ERROR'].map((level) => (
                  <option key={level} value={level}>{level}</option>
                ))}
              </select>
            </label>

            <label className="field" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                type="checkbox"
                checked={Boolean(config.telemetry_enabled)}
                disabled={!canWrite}
                onChange={(event) =>
                  setConfig({ ...config, telemetry_enabled: event.target.checked })
                }
              />
              <span>Remonter la télémétrie (effectifs, performance, ressources)</span>
            </label>

            <p className="page__lede">
              ZShield ne peut régler que ces valeurs. L’identité du serveur, l’adresse de
              l’API, le secret, la taille de la file et la liste des commandes autorisées
              restent sous le contrôle exclusif de l’opérateur, dans son fichier de
              configuration local.
            </p>

            <button className="button" type="submit" disabled={busy || !canWrite || !target}>
              {busy ? 'Enregistrement…' : 'Enregistrer la configuration'}
            </button>
            {!canWrite ? (
              <p className="page__lede">Votre rôle ne permet pas de modifier ces réglages.</p>
            ) : null}
          </>
        )}
      </form>

      <div className="panel">
        <h2>Appareils connectés</h2>
        <p className="page__lede">
          Chaque session est révocable immédiatement. Un mot de passe réinitialisé révoque
          toutes les sessions, y compris celle-ci.
        </p>

        <div className="strips" style={{ marginTop: 12 }}>
          <div className="strips__head cols-commands">
            <span>Appareil</span>
            <span>Dernière activité</span>
            <span>Expire</span>
            <span />
          </div>

          {(sessions.data?.sessions ?? []).length === 0 ? (
            <Empty title="Aucune autre session" />
          ) : (
            (sessions.data?.sessions ?? []).map((session) => (
              <div key={session.id} className="strip cols-commands">
                <span className="strip__primary">
                  {session.user_agent?.slice(0, 60) ?? 'Appareil inconnu'}
                  {session.current ? <span className="strip__secondary"> · cet appareil</span> : null}
                </span>
                <span className="strip__secondary">{formatAge(session.last_seen_at)}</span>
                <span className="strip__secondary">{formatDateTime(session.expires_at)}</span>
                {session.current ? (
                  <span className="strip__secondary" />
                ) : (
                  <button type="button" className="button button--danger"
                          onClick={() => void revokeSession(session)}>
                    Déconnecter
                  </button>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      <div className="panel">
        <h2>Double authentification</h2>
        <p className="page__lede" style={{ margin: 0 }}>
          La vérification par application d’authentification est implémentée côté serveur mais
          son écran d’activation n’est pas encore ouvert. Elle arrivera avant l’ouverture des
          paiements.
        </p>
      </div>
    </>
  );
}
