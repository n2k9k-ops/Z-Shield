'use client';

/**
 * Éléments partagés. Peu nombreux volontairement : chaque composant encode une
 * information, aucun n'est là pour décorer.
 */
import type { ReactNode } from 'react';
import { STATE_LABEL } from '@/lib/format';

/** Pastille d'état. La couleur vient du CSS via l'attribut data-state. */
export function State({ value }: { value: string | null | undefined }) {
  const state = value ?? 'UNKNOWN';
  return (
    <span className="state" data-state={state}>
      {STATE_LABEL[state] ?? state}
    </span>
  );
}

/**
 * Écran vide. Une invitation à agir, pas un constat de vide : c'est le premier
 * écran que voit un nouveau client, il doit dire quoi faire ensuite.
 */
export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

export function ErrorNotice({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="notice notice--error">
      {message}
      {onRetry ? (
        <>
          {' '}
          <button type="button" className="button button--quiet" onClick={onRetry}>
            Réessayer
          </button>
        </>
      ) : null}
    </div>
  );
}

export function Loading({ label = 'Chargement' }: { label?: string }) {
  return (
    <div className="empty" aria-live="polite">
      {label}…
    </div>
  );
}

export function PageHead({
  title,
  lede,
  actions,
}: {
  title: string;
  lede?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="page__head">
      <div>
        <h1>{title}</h1>
        {lede ? <p className="page__lede">{lede}</p> : null}
      </div>
      {actions ? <div>{actions}</div> : null}
    </div>
  );
}

export function LiveIndicator({ connected }: { connected: boolean }) {
  return (
    <span className="live" data-connected={connected} title={
      connected
        ? 'Les changements arrivent en direct.'
        : 'Direct interrompu : la page se rafraîchit toutes les 30 secondes.'
    }>
      {connected ? 'en direct' : 'rafraîchissement périodique'}
    </span>
  );
}
