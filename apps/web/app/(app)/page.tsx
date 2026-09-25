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
    // Cache-busting : le navigateur met agressivement en cache le HTML statique,
    // ce qui masque les mises à jour. Un paramètre horodaté force une version fraîche.
    window.location.replace('/console.html?v=' + Date.now());
  }, []);
  return null;
}
