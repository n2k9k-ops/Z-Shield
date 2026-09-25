'use client';

/**
 * Chargement d'une ressource avec ses trois états visibles : chargement,
 * erreur, contenu. Écrit une fois ici pour que chaque page n'invente pas sa
 * propre gestion — et surtout pour qu'aucune page n'oublie l'état d'erreur.
 */
import { useCallback, useEffect, useState } from 'react';
import { ApiError, api } from './api';

export interface Resource<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

export function useResource<T>(path: string | null): Resource<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(path !== null);

  const load = useCallback(async () => {
    if (path === null) return;
    setError(null);
    setLoading(true);
    // Tolérance au « réveil » du serveur (plans qui s'endorment après inactivité) :
    // une panne réseau ou un 5xx n'est PAS une déconnexion — on patiente et on
    // réessaie plusieurs fois avant d'afficher une erreur. Seul un vrai 401 renvoie
    // vers la connexion.
    const attempts = 6;
    for (let i = 0; i < attempts; i += 1) {
      try {
        const result = await api.get<T>(path);
        setData(result);
        setLoading(false);
        return;
      } catch (cause) {
        if (cause instanceof ApiError && cause.status === 401) {
          window.location.href = '/login';
          return;
        }
        if (i === attempts - 1) {
          setError(cause instanceof Error ? cause.message : 'Erreur inattendue.');
          setLoading(false);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, i < 2 ? 1500 : 4000));
      }
    }
  }, [path]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, error, loading, reload: () => void load() };
}
