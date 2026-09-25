'use client';

/**
 * Abonnement temps réel.
 *
 * Le WebSocket est un ACCÉLÉRATEUR, jamais la source de vérité. Une socket
 * morte en silence produirait un tableau de bord faussement calme, ce qui est
 * le pire état possible pour un outil de supervision. D'où :
 *
 *   - un rafraîchissement de secours périodique qui tourne même socket ouverte ;
 *   - une reconnexion en backoff exponentiel avec jitter (le jitter évite que
 *     tous les navigateurs reviennent à la même seconde après une coupure) ;
 *   - un indicateur d'état affiché à l'utilisateur, pour qu'il sache si ce
 *     qu'il regarde est vivant.
 */
import { useEffect, useRef, useState } from 'react';
import type { RealtimeEvent } from './types';

const FALLBACK_POLL_MS = 30_000;
const MAX_BACKOFF_MS = 30_000;

export function useRealtime(
  onEvent: (event: RealtimeEvent) => void,
  options: { fallbackIntervalMs?: number } = {},
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const handler = useRef(onEvent);
  handler.current = onEvent;

  useEffect(() => {
    let socket: WebSocket | null = null;
    let attempt = 0;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      if (closed) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      socket = new WebSocket(`${protocol}//${window.location.host}/ws`);

      socket.onopen = () => {
        attempt = 0;
        setConnected(true);
      };

      socket.onmessage = (message) => {
        try {
          const parsed = JSON.parse(String(message.data)) as RealtimeEvent;
          if (parsed.type === 'pong') return;
          handler.current(parsed);
        } catch {
          // Message illisible : ignoré. Une socket bavarde ne doit pas pouvoir
          // faire tomber l'interface.
        }
      };

      socket.onclose = () => {
        setConnected(false);
        if (closed) return;

        attempt += 1;
        const base = Math.min(1000 * 2 ** (attempt - 1), MAX_BACKOFF_MS);
        const delay = base / 2 + Math.random() * (base / 2);
        reconnectTimer = setTimeout(connect, delay);
      };

      socket.onerror = () => {
        socket?.close();
      };
    };

    connect();

    // Rafraîchissement de secours : signalé comme un événement synthétique, de
    // sorte que les pages n'ont qu'un seul chemin de mise à jour à gérer.
    const poll = setInterval(
      () => handler.current({ type: 'poll.tick', payload: {} }),
      options.fallbackIntervalMs ?? FALLBACK_POLL_MS,
    );

    return () => {
      closed = true;
      clearInterval(poll);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [options.fallbackIntervalMs]);

  return { connected };
}
