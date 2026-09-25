'use client';

/**
 * Fiche serveur : état, configuration distante, commandes.
 *
 * Deux garde-fous exprimés dans l'interface plutôt que cachés :
 *   - une commande refusée par l'agent n'est pas une erreur, c'est une décision
 *     de l'opérateur du serveur, et elle est affichée comme telle ;
 *   - la liste des commandes possibles est fermée. Il n'existe aucun champ
 *     libre, parce qu'il n'existe aucun endpoint d'exécution derrière.
 */
import { useCallback, useState } from 'react';
import { useParams } from 'next/navigation';
import { ApiError, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { useRealtime } from '@/lib/useRealtime';
import { Empty, ErrorNotice, LiveIndicator, Loading, PageHead, State } from '@/components/ui';
import { STATE_LABEL, formatAge, formatDateTime, formatDuration, formatPlayers } from '@/lib/format';
import type { AgentCommand, AnticheatSettings, IssuedCredential, LicenseStatus, Me, Server } from '@/lib/types';

const LOCKDOWN_OPTIONS: Array<{ value: 'inactive' | 'relaxed' | 'strict'; label: string; help: string }> = [
  { value: 'inactive', label: 'Désactivé', help: 'Aucun blocage — le serveur fonctionne normalement.' },
  { value: 'relaxed', label: 'Recommandé', help: 'Bloque les objets et véhicules créés illégalement par un joueur.' },
  { value: 'strict', label: 'Maximum', help: 'Aucune création par un joueur. Protection la plus forte.' },
];

const COMMANDS: Array<{ type: string; label: string; help: string }> = [
  { type: 'ping', label: 'Tester la liaison', help: 'Vérifie que l’agent répond.' },
  { type: 'request_status', label: 'Demander l’état', help: 'Remonte l’état interne de l’agent.' },
  {
    type: 'request_health_check',
    label: 'Lancer un diagnostic',
    help: 'L’agent réexamine ses composants et renvoie le résultat.',
  },
  {
    type: 'refresh_configuration',
    label: 'Recharger la configuration',
    help: 'L’agent va relire la configuration que vous avez enregistrée ici.',
  },
  {
    type: 'flush_queue',
    label: 'Vider la file locale',
    help: 'L’agent tente d’envoyer immédiatement ce qu’il a en attente.',
  },
];

export default function ServerDetailPage() {
  const params = useParams<{ id: string }>();
  const serverId = params.id;

  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const commands = useResource<{ commands: AgentCommand[] }>(`/api/servers/${serverId}/commands`);
  const settings = useResource<{ settings: AnticheatSettings }>(`/api/servers/${serverId}/anticheat`);
  const license = useResource<LicenseStatus>(`/api/servers/${serverId}/license`);
  const me = useResource<Me>('/api/auth/me');

  const [issued, setIssued] = useState<IssuedCredential | null>(null);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    servers.reload();
    commands.reload();
  }, [servers, commands]);

  const { connected } = useRealtime(refresh);

  if (servers.loading && !servers.data) return <Loading />;

  const server = servers.data?.servers.find((candidate) => candidate.id === serverId);

  if (!server) {
    return (
      <>
        <PageHead title="Serveur introuvable" />
        <Empty title="Ce serveur n’existe pas, ou n’appartient pas à votre organisation" />
      </>
    );
  }

  const canIssue = hasPermission(me.data?.permissions, 'credential.manage');
  const canCommand = hasPermission(me.data?.permissions, 'command.issue');
  const canConfigure = hasPermission(me.data?.permissions, 'anticheat.configure');
  const lockdown = settings.data?.settings.onesync_lockdown ?? 'inactive';

  const setLockdown = async (mode: string) => {
    setMessage(null);
    try {
      await api.patch(`/api/servers/${serverId}/lockdown`, { mode });
      settings.reload();
      setMessage('Verrouillage OneSync enregistré. Il s’applique au prochain relevé de l’agent.');
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Modification impossible.');
    }
  };

  const issueLicense = async (plan: string) => {
    setMessage(null);
    try {
      const res = await api.post<{ token: string }>(`/api/servers/${serverId}/license`, { plan });
      setIssuedToken(res.token);
      license.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Émission impossible.');
    }
  };

  const issueCredential = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.post<IssuedCredential>(`/api/servers/${serverId}/credentials`);
      setIssued(result);
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Génération impossible.');
    } finally {
      setBusy(false);
    }
  };

  const sendCommand = async (type: string) => {
    setBusy(true);
    setMessage(null);
    try {
      await api.post(`/api/servers/${serverId}/commands`, { type });
      setMessage('Commande mise en file. L’agent la prendra à son prochain relevé.');
      commands.reload();
    } catch (cause) {
      setMessage(cause instanceof ApiError ? cause.message : 'Envoi impossible.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHead
        title={server.name}
        lede={`${STATE_LABEL[server.state]} · protocole v${server.protocol_version ?? '—'} · configuration v${server.config_version}`}
        actions={<LiveIndicator connected={connected} />}
      />

      {message ? <div className="notice">{message}</div> : null}

      {server.last_error ? (
        <div className="notice notice--error">
          Dernière erreur rapportée par l’agent, {formatAge(server.last_error_at)} :{' '}
          {server.last_error}
        </div>
      ) : null}

      <div className="figures">
        <div className="figure">
          <div className="figure__value">{formatPlayers(server.players_online)}</div>
          <div className="figure__label">joueurs connectés</div>
        </div>
        <div className="figure">
          <div className="figure__value">{formatDuration(server.uptime_seconds)}</div>
          <div className="figure__label">temps de fonctionnement</div>
        </div>
        <div className="figure">
          <div className="figure__value">{server.queue_size ?? 0}</div>
          <div className="figure__label">éléments en file chez l’agent</div>
        </div>
        <div className="figure">
          <div className="figure__value">{formatAge(server.last_heartbeat_at)}</div>
          <div className="figure__label">dernier battement</div>
        </div>
      </div>

      <div className="panel">
        <h2>Santé de l’agent</h2>
        <p className="page__lede" style={{ marginBottom: 10 }}>
          <State value={server.health} /> · agent{' '}
          {server.agent_version ? `v${server.agent_version}` : 'jamais connecté'} · premier
          handshake {formatDateTime(server.connected_at)}
        </p>
        <p className="page__lede" style={{ margin: 0 }}>
          Un battement manquant signifie que l’agent ne joint plus la plateforme. Cela
          n’indique pas que le serveur est compromis, et l’inverse est vrai aussi : un agent
          en ligne ne garantit pas que le serveur va bien.
        </p>
      </div>

      <div className="panel">
        <h2>Licence</h2>
        {license.data?.has_license ? (
          <p className="page__lede" style={{ marginBottom: 12 }}>
            Offre <strong>{license.data.plan}</strong> —{' '}
            {license.data.expired
              ? <span style={{ color: '#ef5b52' }}>expirée : la protection est coupée sur ce serveur.</span>
              : <>valide encore <strong>{license.data.days_left} jour(s)</strong>.</>}
          </p>
        ) : (
          <p className="page__lede" style={{ marginBottom: 12 }}>
            Aucune licence. Sans clé valide, l’anticheat démarre mais ne protège pas — un
            message s’affiche dans la console du serveur.
          </p>
        )}

        {canConfigure ? (
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button type="button" className="button" onClick={() => void issueLicense('trial')}>
              Démarrer l’essai (7 jours)
            </button>
            <button type="button" className="button button--quiet" onClick={() => void issueLicense('starter')}>Starter (30 j)</button>
            <button type="button" className="button button--quiet" onClick={() => void issueLicense('pro')}>Pro (30 j)</button>
            <button type="button" className="button button--quiet" onClick={() => void issueLicense('enterprise')}>Enterprise (30 j)</button>
          </div>
        ) : null}

        {issuedToken ? (
          <>
            <p className="page__lede" style={{ margin: '14px 0 6px' }}>
              Copiez cette clé dans <code>config/config.lua</code> du cœur (<code>license.key</code>),
              puis démarrez le serveur. Elle réactive la protection.
            </p>
            <code className="code" style={{ wordBreak: 'break-all' }}>{issuedToken}</code>
            <button type="button" className="button button--quiet"
                    onClick={() => void navigator.clipboard.writeText(issuedToken)}>
              Copier la clé
            </button>
          </>
        ) : null}
      </div>

      <div className="panel">
        <h2>Blocage des créations illégales</h2>
        <p className="page__lede" style={{ marginBottom: 12 }}>
          Empêche les joueurs de faire apparaître des véhicules ou objets qu’ils n’ont pas le droit
          de créer. C’est la protection la plus efficace et elle ne coûte rien en performances.
          Le changement s’applique au prochain relevé de l’agent.
        </p>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {LOCKDOWN_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              className={`button ${lockdown === opt.value ? '' : 'button--quiet'}`}
              disabled={!canConfigure}
              title={opt.help}
              onClick={() => void setLockdown(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <p className="page__lede" style={{ margin: '10px 0 0', fontSize: 13 }}>
          Actuel : <strong>{LOCKDOWN_OPTIONS.find((o) => o.value === lockdown)?.label ?? lockdown}</strong>
          {' — '}{LOCKDOWN_OPTIONS.find((o) => o.value === lockdown)?.help}
        </p>
      </div>

      {canIssue ? (
        <div className="panel">
          <h2>Clé d’agent</h2>
          {issued ? (
            <>
              <div className="notice notice--secret">
                Cette clé s’affiche une seule fois. Elle n’est pas relisible ensuite : si vous
                la perdez, il faudra en générer une nouvelle. Toute clé précédente de ce
                serveur vient d’être révoquée.
              </div>
              <p className="page__lede">{issued.installation.note}</p>
              <code className="code">{issued.installation.lines.join('\n')}</code>
              <button type="button" className="button button--quiet"
                      onClick={() => void navigator.clipboard.writeText(issued.installation.lines.join('\n'))}>
                Copier les lignes
              </button>
            </>
          ) : (
            <>
              <p className="page__lede">
                Générer une clé révoque celle en cours : l’agent installé cessera d’être
                accepté jusqu’à ce que vous mettiez à jour son server.cfg.
              </p>
              <button type="button" className="button" disabled={busy} onClick={() => void issueCredential()}>
                Générer une nouvelle clé
              </button>
            </>
          )}
        </div>
      ) : null}

      {canCommand ? (
        <div className="panel">
          <h2>Commandes</h2>
          <p className="page__lede">
            Liste fermée. Aucune commande ne permet d’exécuter du code, de lire un fichier ou
            d’expulser un joueur : ces actions n’existent pas dans le protocole. L’opérateur
            du serveur peut par ailleurs restreindre encore cette liste de son côté.
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12 }}>
            {COMMANDS.map((command) => (
              <button
                key={command.type}
                type="button"
                className="button button--quiet"
                title={command.help}
                disabled={busy}
                onClick={() => void sendCommand(command.type)}
              >
                {command.label}
              </button>
            ))}
          </div>
        </div>
      ) : null}

      <h2 style={{ marginBottom: 10 }}>Commandes envoyées</h2>

      <div className="strips">
        <div className="strips__head cols-commands">
          <span>Commande</span>
          <span>Statut</span>
          <span>Résultat</span>
          <span>Envoyée</span>
        </div>

        {(commands.data?.commands ?? []).length === 0 ? (
          <Empty title="Aucune commande envoyée à ce serveur" />
        ) : (
          (commands.data?.commands ?? []).map((command) => (
            <div key={command.id} className="strip cols-commands">
              <span className="strip__primary">
                {COMMANDS.find((entry) => entry.type === command.type)?.label ?? command.type}
              </span>
              <State value={command.status} />
              <span className="strip__secondary">
                {command.result ? STATE_LABEL[command.result] ?? command.result : '—'}
                {command.reason ? ` · ${command.reason}` : ''}
              </span>
              <span className="strip__secondary">{formatAge(command.created_at)}</span>
            </div>
          ))
        )}
      </div>
    </>
  );
}
