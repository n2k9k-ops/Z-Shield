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
    try {
      setError(null);
      const result = await api.get<T>(path);
      setData(result);
    } catch (cause) {
      // Une erreur d'authentification renvoie vers la connexion : rester sur
      // une page vide avec un message serait un cul-de-sac.
      if (cause instanceof ApiError && cause.status === 401) {
        window.location.href = '/login';
        return;
      }
      setError(cause instanceof Error ? cause.message : 'Erreur inattendue.');
    } finally {
      setLoading(false);
    }
  }, [path]);

  useEffect(() => {
    void load();
  }, [load]);

  return { data, error, loading, reload: () => void load() };
}
