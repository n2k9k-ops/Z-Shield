'use client';

/**
 * L'accueil du dashboard EST la console Z-Shield (design de la maquette).
 * La console est servie en statique depuis /public/console.html ; on y renvoie
 * dès l'arrivée. La garde d'authentification de la console renvoie vers /login
 * si la session n'est pas valide.
 */
import { useEffect } from 'react';

export default function Home() {
  useEffect(() => {
    window.location.replace('/console.html');
  }, []);
  return null;
}
