'use client';

import { Suspense, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { ApiError, api } from '@/lib/api';

/** Messages honnêtes renvoyés par le parcours Discord (?e=...). */
const DISCORD_NOTICES: Record<string, string> = {
  discord_unavailable:
    'La connexion Discord n’est pas encore activée sur ce serveur. Utilisez votre e-mail pour l’instant.',
  discord_failed: 'La connexion Discord a échoué ou a été interrompue. Réessayez.',
  discord_no_email:
    'Discord n’a pas partagé votre adresse e-mail. Autorisez l’accès à l’e-mail, ou créez un compte par e-mail.',
  discord_email_taken:
    'Un compte existe déjà avec cette adresse e-mail. Connectez-vous par e-mail : vous pourrez lier Discord ensuite.',
  discord_already_linked:
    'Ce compte est déjà lié à un autre compte Discord. Connectez-vous par e-mail.',
  discord_account_disabled: 'Ce compte est désactivé. Contactez un propriétaire de votre organisation.',
  discord_mfa:
    'Discord vous a identifié, mais votre compte demande un second facteur. Connectez-vous par e-mail pour le valider.',
};

/** Logo Z-Shield (éclats blancs, halo vert), réutilisé depuis le rail. */
function BrandMark() {
  return (
    <svg className="auth__logo" viewBox="0 0 256 256" aria-hidden="true">
      <path fill="#ffffff" d="M52 122 L200 40 L150 104 L116 152 L100 126 Z" />
      <path fill="#ffffff" d="M150 150 L214 122 L128 224 Z" />
    </svg>
  );
}

/** Icône Discord officielle (mono, remplie). */
function DiscordMark() {
  return (
    <svg viewBox="0 0 127.14 96.36" fill="currentColor" aria-hidden="true">
      <path d="M107.7 8.07A105.15 105.15 0 0 0 81.47 0a72.06 72.06 0 0 0-3.36 6.83 97.68 97.68 0 0 0-29.11 0A72.37 72.37 0 0 0 45.64 0a105.89 105.89 0 0 0-26.25 8.09C2.79 32.65-1.71 56.6.54 80.21a105.73 105.73 0 0 0 32.17 16.15 77.7 77.7 0 0 0 6.89-11.11 68.42 68.42 0 0 1-10.85-5.18c.91-.66 1.8-1.34 2.66-2a75.57 75.57 0 0 0 64.32 0c.87.71 1.76 1.39 2.66 2a68.68 68.68 0 0 1-10.87 5.19 77 77 0 0 0 6.89 11.1 105.25 105.25 0 0 0 32.19-16.14c2.64-27.38-4.51-51.11-18.9-72.15ZM42.45 65.69C36.18 65.69 31 60 31 53s5-12.74 11.43-12.74S54 46 53.89 53s-5.05 12.69-11.44 12.69Zm42.24 0C78.41 65.69 73.25 60 73.25 53s5-12.74 11.44-12.74S96.23 46 96.12 53s-5.04 12.69-11.43 12.69Z" />
    </svg>
  );
}

function LoginForm() {
  const router = useRouter();
  const params = useSearchParams();
  const discordNotice = DISCORD_NOTICES[params.get('e') ?? ''] ?? null;
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const result = await api.post<{ status: string }>('/api/auth/login', { email, password });

      if (result.status === 'mfa_required') {
        // L'écran de saisie du second facteur n'est pas encore ouvert. Plutôt
        // qu'un lien mort, on le dit : la session existe mais ne donne accès à
        // rien tant que le facteur n'est pas validé.
        setError(
          'Votre compte demande un second facteur, dont l’écran de saisie n’est pas encore disponible. Contactez un propriétaire de votre organisation.',
        );
        return;
      }

      window.location.assign('/console.html');
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Connexion impossible.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="auth">
      <form className="auth__box" onSubmit={submit}>
        <div className="auth__brand">
          <BrandMark />
          <div>
            <h1>Se connecter à Z-Shield</h1>
            <p className="page__lede">Supervision de vos serveurs FiveM.</p>
          </div>
        </div>

        {error ? (
          <div className="notice notice--error" role="alert">
            {error}
          </div>
        ) : null}

        {discordNotice ? (
          <div className="notice notice--warn" role="status">
            {discordNotice}
          </div>
        ) : null}

        {/* Connexion Discord — chemin principal pour les gérants de serveurs FiveM. */}
        <a className="auth__discord" href="/api/auth/discord/start">
          <DiscordMark />
          Continuer avec Discord
        </a>

        <div className="auth__or">ou par e-mail</div>

        <label className="field">
          <span className="field__label">Adresse e-mail</span>
          <input
            className="field__input"
            type="email"
            autoComplete="username"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
        </label>

        <label className="field">
          <span className="field__label">Mot de passe</span>
          <input
            className="field__input"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>

        <button className="button" type="submit" disabled={busy}>
          {busy ? 'Connexion…' : 'Se connecter'}
        </button>

        <p className="auth__note">
          Accès sur invitation uniquement. Contacte l'administrateur pour un compte.
        </p>
      </form>
    </main>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={<main className="auth" />}>
      <LoginForm />
    </Suspense>
  );
}
