/**
 * Le frontend est servi sur la même origine que l'API grâce à ce proxy.
 *
 * Ce n'est pas un détail de confort : le cookie de session est `SameSite=Lax`
 * et le jeton CSRF est un second cookie lu par le client. En origine croisée,
 * `SameSite=Lax` bloquerait les mutations et il faudrait passer les cookies en
 * `SameSite=None`, c'est-à-dire renoncer à la protection CSRF native du
 * navigateur. Le proxy évite ce compromis.
 *
 * En production, le même effet s'obtient par le reverse proxy en amont
 * (le frontend et /api sur le même nom de domaine).
 */
const apiOrigin = process.env.ZSHIELD_API_ORIGIN ?? 'http://127.0.0.1:4000';

/** @type {import('next').NextConfig} */
export default {
  reactStrictMode: true,
  poweredByHeader: false,
  async rewrites() {
    return [
      { source: '/api/:path*', destination: `${apiOrigin}/api/:path*` },
      { source: '/ws', destination: `${apiOrigin}/ws` },
    ];
  },
};
