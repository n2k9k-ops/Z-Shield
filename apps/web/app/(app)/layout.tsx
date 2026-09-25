'use client';

/**
 * Coque de l'application : rail de navigation, sélecteur d'organisation, et la
 * garde côté client.
 *
 * La garde d'affichage ne protège rien : l'autorisation est entièrement côté
 * serveur. Elle évite seulement d'afficher une page vide à quelqu'un qui n'a
 * plus de session, et de proposer des liens qui répondraient 403.
 */
import type { ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ROLE_LABEL, api, hasPermission } from '@/lib/api';
import { useResource } from '@/lib/useResource';
import { formatNumber } from '@/lib/format';
import type { Me, Organization, Overview } from '@/lib/types';
import { ErrorNotice, Loading } from '@/components/ui';

interface NavEntry {
  href?: string;
  label?: string;
  section?: string; // en-tête de groupe, non cliquable
  icon?: string; // clé d'icône (voir NavIcon)
  permission?: string;
  adminOnly?: boolean; // réservé à l'admin plateforme (vendeur)
  badge?: (overview: Overview | null) => string | null;
}

/** Icônes de navigation, dans le trait fin de la DA console. */
function NavIcon({ name }: { name?: string }) {
  const p: Record<string, string> = {
    overview: 'M3 12h4l3 8 4-16 3 8h4',
    onboarding: 'M12 3v12m0 0 4-4m-4 4-4-4M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2',
    servers: 'M3 4h18v7H3zM3 13h18v7H3zM7 7.5h.01M7 16.5h.01',
    alerts: 'M6 8a6 6 0 1 1 12 0c0 7 3 7 3 9H3c0-2 3-2 3-9M10 21a2 2 0 0 0 4 0',
    incidents: 'M12 12a3 3 0 1 0 0-.01M12 3a9 9 0 0 1 9 9M12 7a5 5 0 0 1 5 5',
    protections: 'M4 8h16M4 8l3-3M4 8l3 3M20 16H4M20 16l-3-3M20 16l-3 3',
    players: 'M9 8a3 3 0 1 0 0-.01M3.5 20a5.5 5.5 0 0 1 11 0M16 5.2a3.2 3.2 0 0 1 0 5.9M18.5 20a5.5 5.5 0 0 0-3-4.9',
    detections: 'M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14M20 20l-3.5-3.5',
    bans: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M5.6 5.6l12.8 12.8',
    rules: 'M4 6h16M4 12h16M4 18h10',
    licenses: 'M15 7a4 4 0 1 0-3.9 5H14v2h2v2h3v-3l-4-4Z',
    analytics: 'M4 20V10M10 20V4M16 20v-7M22 20H2',
    team: 'M9 8a3 3 0 1 0 0-.01M3.5 20a5.5 5.5 0 0 1 11 0M16 5.2a3.2 3.2 0 0 1 0 5.9M18.5 20a5.5 5.5 0 0 0-3-4.9',
    audit: 'M6 2h9l5 5v15H6zM14 2v6h6',
    billing: 'M3 6h18v12H3zM3 10h18',
    settings: 'M4 8h9M17 8h3M8 8v-.01M4 16h3M11 16h9M8 16v-.01M8 6v4M8 14v4',
    admin: 'M5 7l4 4-4 4M11 15h6',
  };
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={p[name ?? 'overview'] ?? p.overview} />
    </svg>
  );
}

function initials(name: string): string {
  const parts = name.trim().split(/[\s_]+/).filter(Boolean).slice(0, 2);
  const out = parts.map((p) => p[0]).join('').toUpperCase();
  return out || '??';
}

const Chevrons = () => (
  <svg className="chev" width="16" height="16" viewBox="0 0 24 24" fill="none"
       stroke="currentColor" strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m8 9 4-4 4 4M8 15l4 4 4-4" />
  </svg>
);

/**
 * Navigation par sections, comme une console d'exploitation : d'abord la
 * supervision de la flotte, puis l'anticheat, puis l'administration. Les
 * entrées d'anticheat sont regroupées pour que l'opérateur retrouve d'un coup
 * d'œil les outils de modération.
 */
const NAV: NavEntry[] = [
  { section: 'Surveillance' },
  { href: '/', label: 'Vue d’ensemble', icon: 'overview' },
  { href: '/servers', label: 'Serveurs', icon: 'servers' },
  {
    href: '/incidents',
    label: 'Incidents',
    icon: 'incidents',
    permission: 'incident.read',
    badge: (overview) => {
      const open = Number(overview?.incidents_open ?? 0);
      return open > 0 ? formatNumber(open) : null;
    },
  },
  {
    href: '/players',
    label: 'Joueurs',
    icon: 'players',
    permission: 'detection.read',
  },

  { section: 'Défense' },
  { href: '/protections', label: 'Protections', icon: 'protections', permission: 'detection.read' },
  { href: '/bans', label: 'Bans & sanctions', icon: 'bans', permission: 'ban.read' },
  { href: '/detections', label: 'Détections', icon: 'detections', permission: 'detection.read' },
  { href: '/onboarding', label: 'Installation', icon: 'onboarding' },

  { section: 'Espace' },
  { href: '/licenses', label: 'Licences', icon: 'licenses', permission: 'billing.manage' },
  { href: '/analytics', label: 'Statistiques', icon: 'analytics', permission: 'analytics.read' },
  { href: '/team', label: 'Comptes & accès', icon: 'team', permission: 'member.read' },
  { href: '/audit', label: 'Journal', icon: 'audit', permission: 'audit.read' },
  { href: '/billing', label: 'Offre', icon: 'billing', permission: 'billing.manage' },
  { href: '/settings', label: 'Réglages', icon: 'settings' },

  { section: 'Plateforme', adminOnly: true },
  { href: '/admin', label: 'Console vendeur', icon: 'admin', adminOnly: true },
];

export default function AppLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const me = useResource<Me>('/api/auth/me');
  const organizations = useResource<{ organizations: Organization[] }>('/api/organizations');
  const overview = useResource<{ overview: Overview }>('/api/overview');

  if (me.loading) {
    return (
      <main className="main">
        <Loading label="Ouverture de la session" />
      </main>
    );
  }

  if (me.error || !me.data) {
    return (
      <main className="main">
        <ErrorNotice message={me.error ?? 'Session introuvable.'} onRetry={me.reload} />
      </main>
    );
  }

  const current = me.data;
  const list = organizations.data?.organizations ?? [];

  const switchOrganization = async (organizationId: string) => {
    await api.post('/api/auth/switch-organization', { organization_id: organizationId });
    // Rechargement complet : toutes les données affichées appartiennent à
    // l'ancienne organisation et doivent disparaître, pas se mélanger.
    window.location.href = '/';
  };

  const logout = async () => {
    await api.post('/api/auth/logout');
    window.location.href = '/login';
  };

  return (
    <div className="shell">
      <nav className="rail" aria-label="Navigation principale">
        <div className="rail__brand">
          <svg viewBox="0 0 256 256" aria-hidden="true"
               style={{ filter: 'drop-shadow(0 0 5px rgba(51,229,138,.6))' }}>
            <path fill="#ffffff" d="M52 122 L200 40 L150 104 L116 152 L100 126 Z" />
            <path fill="#ffffff" d="M150 150 L214 122 L128 224 Z" />
          </svg>
          <span>Z-Shield</span>
          <span className="rail__vtag">v2.4.1</span>
        </div>

        {/* Sélecteur d'organisation, présenté comme une carte de serveur. */}
        {list.length > 1 ? (
          <div className="rail__switch" style={{ paddingRight: 8 }}>
            <span className="si" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z" />
              </svg>
              <span className="on-dot" />
            </span>
            <label className="st" style={{ cursor: 'pointer' }}>
              <select
                className="field__select"
                style={{ padding: '4px 6px', background: 'transparent', border: 0, color: 'var(--text)', fontWeight: 700 }}
                value={current.organization_id}
                onChange={(event) => void switchOrganization(event.target.value)}
              >
                {list.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name}
                  </option>
                ))}
              </select>
            </label>
          </div>
        ) : (
          <button type="button" className="rail__switch" onClick={() => {}}>
            <span className="si" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path d="M12 3 5 6v6c0 4.5 3 7.5 7 9 4-1.5 7-4.5 7-9V6l-7-3Z" />
              </svg>
              <span className="on-dot" />
            </span>
            <span className="st">
              <b>{list[0]?.name ?? 'Votre organisation'}</b>
              <small>{ROLE_LABEL[current.role]}</small>
            </span>
            <Chevrons />
          </button>
        )}

        <div className="rail__search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} aria-hidden="true">
            <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
          </svg>
          <input placeholder="Rechercher" aria-label="Rechercher" readOnly />
          <span className="kbd">⌘K</span>
        </div>

        <div className="rail__nav">
          {NAV.filter(
            (entry) =>
              (!entry.adminOnly || current.is_platform_admin === true) &&
              (entry.section !== undefined ||
                !entry.permission ||
                hasPermission(current.permissions, entry.permission)),
          ).map((entry) => {
            if (entry.section !== undefined) {
              return (
                <div key={`section-${entry.section}`} className="rail__section">
                  {entry.section}
                </div>
              );
            }

            const href = entry.href ?? '/';
            const active = href === '/' ? pathname === '/' : pathname.startsWith(href);
            const badge = entry.badge?.(overview.data?.overview ?? null) ?? null;
            return (
              <Link
                key={href}
                href={href}
                className="rail__link"
                aria-current={active ? 'page' : undefined}
              >
                <NavIcon name={entry.icon} />
                <span>{entry.label}</span>
                {badge ? <span className="rail__badge">{badge}</span> : null}
              </Link>
            );
          })}
        </div>

        <div className="rail__foot">
          <button type="button" className="rail__user" onClick={() => void logout()}
                  title="Se déconnecter">
            <span className="rail__avatar">{initials(current.user.display_name)}</span>
            <span style={{ flex: 1, minWidth: 0 }}>
              <b>{current.user.display_name}</b>
              <small>{ROLE_LABEL[current.role]}</small>
            </span>
            <Chevrons />
          </button>
        </div>
      </nav>

      <main className="main">{children}</main>
    </div>
  );
}
