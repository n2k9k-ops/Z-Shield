# Z-Shield Dashboard — déployer GRATUITEMENT (pour tester)

But : mettre ta plateforme en ligne, en HTTPS, **sans payer**, pour tester avec
quelques serveurs. On utilise trois services gratuits :

- **Render** — héberge l'app (l'API + le site), directement depuis GitHub.
- **Neon** — la base de données (PostgreSQL), gratuite.
- **Upstash** — Redis (temps réel, sessions), gratuit.

> ⚠️ À lire avant : le gratuit a des limites (voir la fin). C'est parfait pour
> tester et montrer le produit. Pour de vrais clients payants, prends un petit
> VPS (voir `DEPLOY.md`) — c'est plus fiable et ça ne « dort » pas.

Temps : ~20 minutes. Aucune carte bancaire nécessaire.

---

## Étape 0 — Ce qu'il te faut

- Un compte **GitHub** (gratuit).
- **Node.js** installé sur ton PC (pour lancer les migrations une seule fois).
  Vérifie avec `node --version` (il faut la v22+).

---

## Étape 1 — La base de données (Neon)

1. Va sur **https://neon.tech** → **Sign up** (avec GitHub, c'est le plus simple).
2. **Create project** : donne un nom (ex : `zshield`), garde la région la plus proche.
3. Une fois créé, ouvre **Connection string** (ou « Connect »).
4. Copie l'URL qui ressemble à :
   ```
   postgresql://user:MOTDEPASSE@ep-xxxx.eu-central-1.aws.neon.tech/neondb?sslmode=require
   ```
   **Garde-la de côté** — c'est ton `DATABASE_URL`.

---

## Étape 2 — Redis (Upstash)

1. Va sur **https://upstash.com** → **Sign up**.
2. **Create Database** → type **Redis** → une région proche → **Create**.
3. Dans la page de la base, section **Connect**, choisis **`rediss://` (TLS)** et copie l'URL :
   ```
   rediss://default:MOTDEPASSE@xxxx.upstash.io:6379
   ```
   **Garde-la de côté** — c'est ton `REDIS_URL`. (Bien le `rediss://` avec deux « s ».)

---

## Étape 3 — Appliquer les migrations (une seule fois, depuis ton PC)

C'est ce qui crée les tables dans Neon. On le fait depuis ton ordinateur.

Ouvre un terminal dans le dossier `zshield-dashboard/`, puis :

```bash
# 1) installe les dépendances de l'API
cd apps/api
npm install --no-audit --no-fund

# 2) lance les migrations contre Neon (colle TON URL Neon)
DATABASE_MIGRATION_URL="postgresql://user:MOTDEPASSE@ep-xxxx.aws.neon.tech/neondb?sslmode=require" \
  node --experimental-strip-types src/lib/migrate.ts
```

Tu dois voir défiler les migrations (`0001_…` jusqu'à `0009_…`) puis « OK ».
Si ça bloque, vérifie que l'URL Neon est bien entre guillemets et complète.

---

## Étape 4 — Mettre le projet sur GitHub

Render déploie depuis un dépôt GitHub.

1. Sur GitHub : **New repository** → nom `zshield-dashboard` → **Private** → **Create**.
2. Sur ton PC, dans le dossier `zshield-dashboard/` :

```bash
git init
git add .
git commit -m "Z-Shield dashboard"
git branch -M main
git remote add origin https://github.com/TON-PSEUDO/zshield-dashboard.git
git push -u origin main
```

---

## Étape 5 — Déployer sur Render (Blueprint)

Le fichier `render.yaml` (déjà dans le projet) décrit les deux services. Render le lit tout seul.

1. Va sur **https://render.com** → **Sign up** (avec GitHub).
2. **New +** → **Blueprint**.
3. Sélectionne ton dépôt `zshield-dashboard` → **Connect**.
4. Render détecte `render.yaml` et propose de créer **zshield-api** et **zshield-web**.
5. Il va te demander les valeurs marquées « secret » (`sync: false`). Remplis :

   **Pour `zshield-api` :**
   | Variable | Valeur |
   |---|---|
   | `DATABASE_URL` | ton URL **Neon** (étape 1) |
   | `REDIS_URL` | ton URL **Upstash** `rediss://…` (étape 2) |
   | `ZSHIELD_CREDENTIAL_KEY` | une clé au hasard — voir ci-dessous |
   | `SESSION_SECRET` | une clé au hasard — voir ci-dessous |
   | `LICENSE_SIGNING_SECRET` | **le même** que dans `zshield-ac/server/license.lua` |
   | `CORS_ORIGINS` | *(on la remplira à l'étape 6)* — mets `https://zshield-web.onrender.com` pour l'instant |

   **Pour `zshield-web` :**
   | Variable | Valeur |
   |---|---|
   | `ZSHIELD_API_ORIGIN` | *(on la remplira à l'étape 6)* — mets `https://zshield-api.onrender.com` pour l'instant |

   Pour générer les clés au hasard, sur ton PC :
   ```bash
   openssl rand -base64 32   # -> ZSHIELD_CREDENTIAL_KEY
   openssl rand -base64 32   # -> SESSION_SECRET
   ```
   (Sous Windows sans `openssl` : `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`.)

6. **Apply / Create** → Render construit les deux services (ça prend quelques minutes).

---

## Étape 6 — Relier le site à l'API (les vraies URL)

Une fois les deux services créés, Render leur donne leurs URL définitives
(en haut de chaque service). Elles ressemblent à `https://zshield-api-xxxx.onrender.com`.

1. Note l'URL de **zshield-api** et celle de **zshield-web**.
2. Dans **zshield-web** → **Environment** : mets
   `ZSHIELD_API_ORIGIN = <URL exacte de zshield-api>`.
3. Dans **zshield-api** → **Environment** : mets
   `CORS_ORIGINS = <URL exacte de zshield-web>`.
4. Render redéploie tout seul après chaque changement (sinon **Manual Deploy**).

Ouvre l'URL de **zshield-web** → tu dois voir la page de connexion. 🎉

---

## Étape 7 — Ton compte vendeur (admin plateforme)

1. Sur le site, **Register** : crée ton compte (email + mot de passe).
2. Rends ce compte **admin plateforme**, une seule fois. Dans **Neon** :
   ouvre ton projet → **SQL Editor** → colle et exécute :
   ```sql
   UPDATE users SET is_platform_admin = true WHERE email = 'ton-email@exemple.com';
   ```
3. Déconnecte-toi / reconnecte-toi → le menu **Plateforme → Console vendeur** apparaît.

À partir de là : tu ajoutes un serveur, tu génères une clé d'agent, le client la
colle dans `zshield-agent` et met ton URL Render dans sa config. Son serveur
remonte dans ta **Console vendeur**, tu émets sa licence → livrée automatiquement.

---

## Les limites du gratuit (important)

- **Render (free) « s'endort »** après ~15 min sans trafic. Le premier accès
  après une sieste met ~30–60 s à répondre. Les agents des serveurs (heartbeats)
  le réveillent régulièrement, donc en pratique il reste souvent éveillé, mais
  ce n'est pas garanti.
- **Le temps réel (`/ws`)** peut se couper quand un service dort. Le dashboard se
  reconnecte tout seul ; au pire, rafraîchis la page.
- **Neon / Upstash gratuits** ont des quotas (nombre de requêtes / stockage).
  Largement suffisant pour tester avec quelques serveurs.
- **Pas de sauvegardes automatiques** sur les offres gratuites.

➡️ Pour vendre pour de vrai (clients payants, dispo 24/7, pas de « réveil »),
passe sur un petit VPS avec `DEPLOY.md` (~4–6 €/mois). Le code est le même,
tu ne perds rien.

---

## Mettre à jour plus tard

Tu changes le code, puis :

```bash
git add . && git commit -m "maj" && git push
```

Render redéploie tout seul. Si une migration a été ajoutée, relance l'étape 3
(les migrations déjà appliquées sont ignorées).
