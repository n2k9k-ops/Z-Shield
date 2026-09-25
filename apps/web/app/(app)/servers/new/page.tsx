'use client';

/**
 * Assistant d'ajout de serveur, les six étapes de la spécification.
 *
 * Le point important est l'étape 4 : on **attend le vrai handshake**. Beaucoup
 * d'assistants s'arrêtent après avoir affiché les instructions et déclarent le
 * serveur « connecté », ce qui reporte la découverte du problème au premier
 * incident, quand personne ne pense plus à l'installation. Ici, la dernière
 * étape ne s'ouvre que lorsque la plateforme a effectivement reçu et vérifié un
 * handshake signé de cet agent.
 *
 * L'attente est un sondage court, pas un WebSocket : la page est éphémère et le
 * sondage échoue de façon lisible. Un `setTimeout` de 10 minutes affiche un
 * chemin de sortie plutôt que de tourner indéfiniment.
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { ApiError, api } from '@/lib/api';
import { PageHead } from '@/components/ui';
import type { IssuedCredential, Server } from '@/lib/types';

const STEPS = [
  'Nommer le serveur',
  'Générer la clé',
  'Installer la ressource',
  'Attendre l’agent',
  'Vérifier le handshake',
  'Terminer',
];

const WAIT_TIMEOUT_MS = 10 * 60 * 1000;
const POLL_MS = 4000;

export default function NewServerPage() {
  const [step, setStep] = useState(0);
  const [name, setName] = useState('');
  const [environment, setEnvironment] = useState('production');
  const [serverId, setServerId] = useState<string | null>(null);
  const [credential, setCredential] = useState<IssuedCredential | null>(null);
  const [server, setServer] = useState<Server | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [waitedTooLong, setWaitedTooLong] = useState(false);

  const createServer = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const created = await api.post<{ server: { id: string } }>('/api/servers', {
        name,
        environment,
      });
      setServerId(created.server.id);
      setStep(1);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Création impossible.');
    } finally {
      setBusy(false);
    }
  };

  const generateCredential = async () => {
    if (!serverId) return;
    setBusy(true);
    setError(null);
    try {
      const issued = await api.post<IssuedCredential>(`/api/servers/${serverId}/credentials`);
      setCredential(issued);
      setStep(2);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Génération impossible.');
    } finally {
      setBusy(false);
    }
  };

  const pollHandshake = useCallback(async () => {
    if (!serverId) return;
    try {
      const result = await api.get<{ servers: Server[] }>('/api/servers');
      const found = result.servers.find((candidate) => candidate.id === serverId);
      setServer(found ?? null);

      // `connected_at` n'est posé que par un handshake authentifié : signature
      // vérifiée, horloge dans la fenêtre, nonce neuf. C'est la seule preuve
      // acceptable que l'installation fonctionne.
      if (found?.connected_at) setStep(4);
    } catch {
      // Un sondage qui échoue n'a pas à interrompre l'assistant : le suivant
      // réessaiera dans quatre secondes.
    }
  }, [serverId]);

  useEffect(() => {
    if (step !== 3) return;

    const interval = setInterval(() => void pollHandshake(), POLL_MS);
    const giveUp = setTimeout(() => setWaitedTooLong(true), WAIT_TIMEOUT_MS);
    void pollHandshake();

    return () => {
      clearInterval(interval);
      clearTimeout(giveUp);
    };
  }, [step, pollHandshake]);

  return (
    <>
      <PageHead
        title="Ajouter un serveur"
        lede="Six étapes. La dernière ne s’ouvre qu’une fois l’agent réellement connecté."
      />

      <ol className="steps" style={{ listStyle: 'none', margin: '0 0 22px', padding: 0 }}>
        {STEPS.map((label, index) => (
          <li
            key={label}
            className="steps__item"
            data-done={index < step}
            aria-current={index === step ? 'step' : undefined}
          >
            <span className="steps__n">{index + 1}</span>
            {label}
          </li>
        ))}
      </ol>

      {error ? (
        <div className="notice notice--error" role="alert">
          {error}
        </div>
      ) : null}

      {step === 0 ? (
        <form className="panel" onSubmit={createServer}>
          <h2>Nommer le serveur</h2>
          <p className="page__lede">
            Ce nom n’est qu’un libellé d’affichage. Vous pourrez le changer plus tard.
          </p>

          <label className="field">
            <span className="field__label">Nom</span>
            <input
              className="field__input"
              required
              maxLength={120}
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Serveur principal"
            />
          </label>

          <label className="field">
            <span className="field__label">Environnement</span>
            <select
              className="field__select"
              value={environment}
              onChange={(event) => setEnvironment(event.target.value)}
            >
              <option value="production">Production</option>
              <option value="staging">Pré-production</option>
              <option value="development">Développement</option>
            </select>
          </label>

          <button className="button" type="submit" disabled={busy}>
            {busy ? 'Création…' : 'Créer le serveur'}
          </button>
        </form>
      ) : null}

      {step === 1 ? (
        <div className="panel">
          <h2>Générer la clé d’agent</h2>
          <p className="page__lede">
            La clé signe chaque requête de l’agent. Elle ne s’affichera qu’une fois : la
            plateforme n’en conserve qu’une version chiffrée et aucun écran ne permet de la
            relire.
          </p>
          <button className="button" type="button" disabled={busy} onClick={() => void generateCredential()}>
            {busy ? 'Génération…' : 'Générer la clé'}
          </button>
        </div>
      ) : null}

      {step === 2 && credential ? (
        <div className="panel">
          <h2>Installer la ressource</h2>

          <div className="notice notice--secret">
            Copiez ces lignes maintenant. Elles contiennent le secret, affiché une seule fois.
          </div>

          <p className="page__lede">
            Placez la ressource <code>zshield-agent</code> dans votre dossier{' '}
            <code>resources</code>, ajoutez <code>ensure zshield-agent</code> à votre
            server.cfg, puis collez ceci dans le même fichier :
          </p>

          <code className="code">{credential.installation.lines.join('\n')}</code>

          <p className="page__lede">
            Utilisez bien <code>set</code> et non <code>sets</code> : <code>sets</code>{' '}
            réplique la valeur à tous les joueurs connectés, ce qui publierait votre clé.
          </p>

          <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
            <button
              type="button"
              className="button button--quiet"
              onClick={() => void navigator.clipboard.writeText(credential.installation.lines.join('\n'))}
            >
              Copier les lignes
            </button>
            <button type="button" className="button" onClick={() => setStep(3)}>
              C’est installé, redémarrer mon serveur
            </button>
          </div>
        </div>
      ) : null}

      {step === 3 ? (
        <div className="panel" aria-live="polite">
          <h2>En attente de l’agent</h2>
          <p className="page__lede">
            Redémarrez votre serveur FiveM. Dès que l’agent démarre, il effectue un handshake
            signé et cette page continue d’elle-même.
          </p>

          {waitedTooLong ? (
            <>
              <div className="notice notice--error">
                Aucun handshake reçu depuis dix minutes.
              </div>
              <p className="page__lede">Trois causes, par ordre de fréquence :</p>
              <ul className="page__lede">
                <li>
                  la ressource n’est pas démarrée : cherchez <code>zshield-agent</code> dans
                  la console FXServer au démarrage ;
                </li>
                <li>
                  une convar est mal recopiée : l’agent journalise{' '}
                  <code>credential manquante</code> dans ce cas ;
                </li>
                <li>
                  l’horloge du serveur dérive de plus de cinq minutes : le protocole refuse
                  alors la requête, et l’agent journalise un écart d’horloge.
                </li>
              </ul>
              <Link className="button button--quiet" href={`/servers/${serverId}`}>
                Continuer sans attendre
              </Link>
            </>
          ) : (
            <p className="page__lede">
              Vérification toutes les quatre secondes. Vous pouvez laisser cette page ouverte.
            </p>
          )}
        </div>
      ) : null}

      {step === 4 && server ? (
        <div className="panel">
          <h2>Handshake vérifié</h2>
          <p className="page__lede">
            Signature valide, horloge dans la fenêtre, nonce neuf. L’agent{' '}
            {server.agent_version ? `v${server.agent_version}` : ''} parle protocole v
            {server.protocol_version} et remonte désormais son état.
          </p>
          <button type="button" className="button" onClick={() => setStep(5)}>
            Terminer
          </button>
        </div>
      ) : null}

      {step === 5 ? (
        <div className="panel">
          <h2>Serveur connecté</h2>
          <p className="page__lede">
            Prochaine étape utile : régler les cadences et les métriques que l’agent doit
            remonter, depuis la fiche du serveur.
          </p>
          <div style={{ display: 'flex', gap: 8 }}>
            <Link className="button" href={`/servers/${serverId}`}>
              Ouvrir la fiche du serveur
            </Link>
            <Link className="button button--quiet" href="/servers">
              Voir tous les serveurs
            </Link>
          </div>
        </div>
      ) : null}
    </>
  );
}
