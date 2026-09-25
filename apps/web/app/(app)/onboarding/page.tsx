'use client';

/**
 * Démarrage guidé.
 *
 * Un parcours en quatre étapes pour passer de « rien » à « serveur protégé ».
 * Les étapes qui sont vérifiables le sont en direct (un serveur existe, un agent
 * a battu) ; les autres sont des rappels. À la fin, un badge partageable.
 */
import { useState } from 'react';
import Link from 'next/link';
import { useResource } from '@/lib/useResource';
import { Loading, PageHead } from '@/components/ui';
import type { Server } from '@/lib/types';

const BADGE_SVG = `<a href="https://z-shield.gg"><svg xmlns="http://www.w3.org/2000/svg" width="228" height="56" viewBox="0 0 228 56" role="img" aria-label="Protégé par Z-Shield"><rect x="0.5" y="0.5" width="227" height="55" rx="11" fill="#0b0e13" stroke="#2b323d"/><g transform="translate(16,12) scale(0.125)"><path fill="#33e58a" d="M52 122 L200 40 L150 104 L116 152 L100 126 Z"/><path fill="#33e58a" d="M150 150 L214 122 L128 224 Z"/></g><text x="52" y="24" font-family="Segoe UI,Roboto,Arial,sans-serif" font-size="12" font-weight="700" fill="#6c7889" letter-spacing="1.5">PROTÉGÉ PAR</text><text x="52" y="42" font-family="Segoe UI,Roboto,Arial,sans-serif" font-size="18" font-weight="800" fill="#f3f6f9">Z-Shield</text><circle cx="208" cy="28" r="4" fill="#33e58a"/></svg></a>`;

function Check({ done }: { done: boolean }) {
  return (
    <span
      aria-hidden="true"
      style={{
        width: 26, height: 26, borderRadius: '50%', flex: 'none',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: done ? '#2ee88a' : 'transparent',
        border: done ? 'none' : '2px solid rgba(255,255,255,.18)',
        color: '#04140b', fontWeight: 800, fontSize: 14,
      }}
    >
      {done ? '✓' : ''}
    </span>
  );
}

export default function OnboardingPage() {
  const servers = useResource<{ servers: Server[] }>('/api/servers');
  const [copied, setCopied] = useState(false);

  if (servers.loading && !servers.data) return <Loading />;

  const list = servers.data?.servers ?? [];
  const hasServer = list.length > 0;
  const hasHeartbeat = list.some((s) => s.last_heartbeat_at != null);
  const firstServerId = list[0]?.id;

  const steps = [
    {
      done: hasServer,
      title: 'Créer un serveur',
      body: 'Déclarez votre serveur FiveM dans la console pour lui associer une identité.',
      action: <Link className="button" href="/servers/new">Ajouter un serveur</Link>,
    },
    {
      done: hasServer,
      title: 'Générer une clé d’agent',
      body: 'Depuis la fiche du serveur, générez une clé. Elle ne s’affiche qu’une fois.',
      action: firstServerId
        ? <Link className="button button--quiet" href={`/servers/${firstServerId}`}>Ouvrir la fiche</Link>
        : null,
    },
    {
      done: hasHeartbeat,
      title: 'Installer Z-Shield sur le serveur',
      body: 'Déposez les dossiers zshield-ac (l’anticheat) et zshield-agent (la liaison) dans vos resources, collez votre clé, puis démarrez. L’installateur vérifie tout seul.',
      action: null,
    },
    {
      done: hasHeartbeat,
      title: 'Vérifier le premier battement',
      body: 'Dès que l’agent joint la plateforme, son battement apparaît et la protection est visible ici.',
      action: null,
    },
  ];

  const doneCount = steps.filter((s) => s.done).length;

  const copyBadge = async () => {
    try {
      await navigator.clipboard.writeText(BADGE_SVG);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  };

  return (
    <>
      <PageHead
        title="Démarrage"
        lede={`De « rien » à « serveur protégé » en quatre étapes. ${doneCount}/4 fait.`}
      />

      <div className="panel">
        <div className="panel__body">
          <ol style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {steps.map((step, i) => (
              <li
                key={i}
                style={{
                  display: 'flex', gap: 14, padding: '18px 0',
                  borderBottom: i < steps.length - 1 ? '1px solid rgba(255,255,255,.08)' : 'none',
                }}
              >
                <Check done={step.done} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 600, fontSize: 15.5 }}>
                    <span className="mono" style={{ opacity: 0.5, marginRight: 8 }}>{String(i + 1).padStart(2, '0')}</span>
                    {step.title}
                  </div>
                  <div style={{ color: 'var(--muted, #8a94a3)', fontSize: 14, marginTop: 4, maxWidth: '68ch' }}>{step.body}</div>
                  {step.action ? <div style={{ marginTop: 12 }}>{step.action}</div> : null}
                </div>
              </li>
            ))}
          </ol>
        </div>
      </div>

      <div className="panel" style={{ marginTop: 16 }}>
        <div className="panel__body">
          <div style={{ fontWeight: 600, marginBottom: 4 }}>Badge « Protégé par Z-Shield »</div>
          <div style={{ opacity: 0.65, fontSize: 13.5, marginBottom: 16, maxWidth: '68ch' }}>
            Affichez-le sur votre site ou votre boutique. C’est un rappel de confiance pour vos joueurs — et un peu de pub pour vous.
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
            <span dangerouslySetInnerHTML={{ __html: BADGE_SVG }} />
            <button type="button" className="button button--quiet" onClick={() => void copyBadge()}>
              {copied ? 'Copié ✓' : 'Copier le code d’intégration'}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
