'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ApiError, api } from '@/lib/api';

/**
 * Inscription publique désactivée (dashboard sur invitation / compte démo).
 * On renvoie vers la connexion. Pour créer le compte admin initial, voir
 * docs : activer ALLOW_REGISTRATION le temps d'une inscription, puis désactiver.
 */
function RegistrationDisabledRedirect() {
  useEffect(() => { window.location.replace('/login'); }, []);
  return null;
}

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

export default function RegisterPage() {
  return <RegistrationDisabledRedirect />;
}

function RegisterPageDisabled() {
  const [form, setForm] = useState({
    organization_name: '',
    display_name: '',
    email: '',
    password: '',
  });
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const update = (key: keyof typeof form) => (event: React.ChangeEvent<HTMLInputElement>) =>
    setForm((current) => ({ ...current, [key]: event.target.value }));

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post('/api/auth/register', form);
      setDone(true);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : 'Création impossible.');
    } finally {
      setBusy(false);
    }
  };

  if (done) {
    return (
      <main className="auth">
        <div className="auth__box">
          <div className="auth__brand">
            <BrandMark />
            <h1>Vérifiez votre boîte e-mail</h1>
          </div>
          {/*
            Message identique que l'adresse soit déjà prise ou non : l'API
            répond la même chose dans les deux cas, pour ne pas transformer ce
            formulaire en oracle d'énumération de comptes. L'interface ne doit
            donc pas prétendre en savoir plus.
          */}
          <p className="page__lede" style={{ textAlign: 'center' }}>
            Si cette adresse peut créer une organisation, un lien de vérification vient de
            partir. Il expire dans une heure.
          </p>
          <p className="auth__note">
            <Link href="/login">Retour à la connexion</Link>
          </p>
        </div>
      </main>
    );
  }

  return (
    <main className="auth">
      <form className="auth__box" onSubmit={submit}>
        <div className="auth__brand">
          <BrandMark />
          <div>
            <h1>Créer une organisation</h1>
            <p className="page__lede">Vous en serez le propriétaire.</p>
          </div>
        </div>

        {error ? (
          <div className="notice notice--error" role="alert">
            {error}
          </div>
        ) : null}

        {/* Inscription Discord — chemin principal pour les gérants FiveM. */}
        <a className="auth__discord" href="/api/auth/discord/start">
          <DiscordMark />
          Continuer avec Discord
        </a>

        <div className="auth__or">ou par e-mail</div>

        <label className="field">
          <span className="field__label">Nom de l’organisation</span>
          <input className="field__input" required maxLength={120}
                 value={form.organization_name} onChange={update('organization_name')} />
        </label>

        <label className="field">
          <span className="field__label">Votre nom</span>
          <input className="field__input" required maxLength={80}
                 value={form.display_name} onChange={update('display_name')} />
        </label>

        <label className="field">
          <span className="field__label">Adresse e-mail</span>
          <input className="field__input" type="email" autoComplete="username" required
                 value={form.email} onChange={update('email')} />
        </label>

        <label className="field">
          <span className="field__label">Mot de passe</span>
          <input className="field__input" type="password" autoComplete="new-password"
                 required minLength={12} value={form.password} onChange={update('password')} />
          <span className="field__hint">12 caractères minimum.</span>
        </label>

        <button className="button" type="submit" disabled={busy}>
          {busy ? 'Création…' : 'Créer l’organisation'}
        </button>

        <p className="auth__note">
          Déjà inscrit ? <Link href="/login">Se connecter</Link>
        </p>
      </form>
    </main>
  );
}
