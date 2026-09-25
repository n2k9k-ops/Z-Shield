# Z-Shield Dashboard — démarrer et se connecter

Comment « allumer » le dashboard, en local d'abord, puis en production.

## Ce qu'il te faut

- **Node.js 20+** et **npm**
- **Docker** (le plus simple pour PostgreSQL + Redis) — ou un PostgreSQL 15+/Redis 7+ à toi

## Démarrage local (5 minutes)

Depuis le dossier `zshield-dashboard/` :

```bash
# 1) Dépendances
npm install

# 2) Configuration
cp .env.example .env
```

Ouvre `.env` et remplis les **trois secrets** (les autres valeurs par défaut vont bien
en local) :

```bash
# une valeur chacun :
openssl rand -base64 32      # -> ZSHIELD_CREDENTIAL_KEY
openssl rand -base64 32      # -> SESSION_SECRET
```

Et ajoute le secret de licence (le MÊME que dans `zshield-ac/server/license.lua`) :

```
LICENSE_SIGNING_SECRET=ton-secret-de-licence
```

Puis :

```bash
# 3) Base de données (PostgreSQL + Redis via Docker)
npm run db:up

# 4) Créer les tables
npm run migrate

# 5) Lancer l'API + le site
npm run dev
```

- Le **site** tourne sur http://localhost:3000
- L'**API** tourne sur http://localhost:4000

Ouvre **http://localhost:3000**.

## Se connecter (premier compte)

Sur la page d'accueil, **crée un compte** (Register) : ton email, un mot de passe, et le
nom de ton organisation. Ce premier compte devient **propriétaire (OWNER)** — c'est lui
qui a accès au panel **Licences** et à tous les réglages.

Ensuite : **Ajouter un serveur → générer une clé d'agent → installer** (le parcours
**Démarrage** dans le menu te guide pas à pas).

> Astuce dev : un jeu de données de test existe (`db/seed.dev.sql`). Si tu l'appliques,
> tu peux te connecter avec `owner@acme.test` / `development-password-1`. À ne jamais
> utiliser en production.

## Les deux dashboards (important)

Il y a **deux niveaux**, dans la même application :

- **Le dashboard du client** — chaque client a son compte (son organisation) et voit
  **seulement son serveur** : joueurs connectés, détections, bans, réglages. Il ne voit
  jamais les autres clients. C'est l'isolation par organisation (RLS).
- **Ta console vendeur** — menu **Plateforme → Console vendeur**. Tu y vois **tous les
  clients et tous leurs serveurs** au même endroit, avec leur état de licence, et tu
  **émets / renouvelles** les licences. Filtres « sans licence » et « expirées » pour t'y
  retrouver quand il y a beaucoup de serveurs.

Donc non, tu ne reçois pas un flot anonyme : chaque serveur est rattaché à un client
(nom de l'organisation) et porte son empreinte. Tu émets la licence sur la bonne ligne,
et elle se lie automatiquement au bon serveur.

### Te donner l'accès vendeur

L'accès « admin plateforme » ne s'active pas depuis l'interface (c'est plus sûr). Une
fois ton compte créé, exécute une fois en base :

```sql
UPDATE users SET is_platform_admin = true WHERE email = 'ton-email@exemple.com';
```

Reconnecte-toi : le menu **Plateforme** apparaît. (En dev, le compte `owner@acme.test`
du jeu de données de test est déjà admin plateforme.)

## Mettre en production (les grandes lignes)

1. Héberge **PostgreSQL** et **Redis** (managés, c'est plus simple).
2. Déploie l'**API** (`apps/api`) et le **site** (`apps/web`) — chacun a un `Dockerfile`.
   Build du site : `npm run build`.
3. Variables d'environnement en prod :
   - `NODE_ENV=production`
   - `DATABASE_URL` / `DATABASE_MIGRATION_URL` vers ta base
   - `REDIS_URL` vers ton Redis
   - `CORS_ORIGINS` = l'URL publique de ton site (jamais `*`)
   - `ZSHIELD_CREDENTIAL_KEY`, `SESSION_SECRET`, `LICENSE_SIGNING_SECRET` (secrets forts,
     sauvegardés à part)
4. Applique les migrations une fois : `npm run migrate`.
5. Mets un **HTTPS** devant (reverse proxy). Les cookies de session sont sécurisés en prod.

## Rappels sécurité

- Ne committe jamais `.env`.
- `ZSHIELD_CREDENTIAL_KEY` chiffre les secrets d'agent : la perdre oblige à regénérer
  toutes les clés d'agent. Sauvegarde-la séparément de la base.
- `LICENSE_SIGNING_SECRET` doit être **identique** à celui du cœur, et rester privé.
