# Z-Shield Dashboard — déployer en ligne

Objectif : ton dashboard en HTTPS sur ton domaine, en une poignée de commandes.
Approche : **un serveur (VPS) + Docker**. Tout est fourni (Postgres, Redis, API, site,
HTTPS automatique). Tu n'installes rien à la main à part Docker.

## Ce qu'il te faut

- Un **VPS** (Ubuntu 22.04+). Un petit suffit pour commencer (2 vCPU / 2–4 Go RAM).
  Hébergeurs simples et pas chers : **Hetzner**, **OVH**, **Contabo**, **DigitalOcean**.
- Un **nom de domaine** (ex : `dashboard.mon-anticheat.com`).
- 15 minutes.

## Étape 1 — Le domaine pointe vers le serveur

Chez ton registrar (là où tu as acheté le domaine), crée un enregistrement **A** :

```
dashboard.mon-anticheat.com   →   <IP publique de ton VPS>
```

Attends quelques minutes que ça se propage.

## Étape 2 — Installer Docker sur le VPS

Connecte-toi en SSH, puis :

```bash
curl -fsSL https://get.docker.com | sh
```

(Docker Compose v2 est inclus.)

## Étape 3 — Envoyer le projet sur le serveur

Copie le dossier `zshield-dashboard/` sur le VPS (via `git clone` de ton dépôt, ou `scp`).
Place-toi dedans :

```bash
cd zshield-dashboard
```

## Étape 4 — Configurer les secrets

```bash
cp .env.prod.example .env
```

Génère les secrets :

```bash
openssl rand -base64 32   # -> ZSHIELD_CREDENTIAL_KEY
openssl rand -base64 32   # -> SESSION_SECRET
```

Ouvre `.env` et remplis **tout** :

- `DOMAIN` = ton domaine (celui de l'étape 1)
- `ACME_EMAIL` = ton email (pour le certificat HTTPS)
- `POSTGRES_PASSWORD` et `APP_DB_PASSWORD` = deux mots de passe **alphanumériques** différents
- `ZSHIELD_CREDENTIAL_KEY`, `SESSION_SECRET` = les valeurs générées ci-dessus
- `LICENSE_SIGNING_SECRET` = **le même** que dans `zshield-ac/server/license.lua`

## Étape 5 — Lancer

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Ça construit et démarre tout, applique les migrations, et obtient le certificat HTTPS.
Suis les logs si tu veux :

```bash
docker compose -f docker-compose.prod.yml logs -f
```

Ouvre **https://dashboard.mon-anticheat.com** → tu dois voir la page de connexion. 🎉

## Étape 6 — Ton compte vendeur

1. **Crée ton compte** (Register) sur le site.
2. Rends-le **admin plateforme** (une seule fois), en base :

```bash
docker compose -f docker-compose.prod.yml exec postgres \
  psql -U postgres -d zshield \
  -c "UPDATE users SET is_platform_admin = true WHERE email = 'ton-email@exemple.com';"
```

3. Reconnecte-toi → le menu **Plateforme → Console vendeur** apparaît.

## Étape 7 — Brancher les serveurs de tes clients

Pour chaque client :

1. Dans le dashboard : **Serveurs → Ajouter**, puis génère une **clé d'agent**.
2. Le client installe `zshield-ac` et `zshield-agent`, colle la clé d'agent, et met l'URL
   de ta plateforme (**https://dashboard.mon-anticheat.com**) dans la config de l'agent.
3. Le serveur apparaît dans ta **Console vendeur**. Tu émets sa licence → livrée
   automatiquement, protection active.

## Mettre à jour plus tard

```bash
git pull            # récupère la nouvelle version
docker compose -f docker-compose.prod.yml up -d --build
```

Les migrations s'appliquent toutes seules au redémarrage.

## Sauvegardes

Les données vivent dans le volume Docker `pgdata`. Sauvegarde régulièrement :

```bash
docker compose -f docker-compose.prod.yml exec postgres \
  pg_dump -U postgres zshield > backup-$(date +%F).sql
```

## Dépannage

- **Le certificat HTTPS n'arrive pas** : vérifie que le domaine pointe bien vers l'IP
  du VPS et que les ports **80** et **443** sont ouverts (pare-feu).
- **Voir l'état** : `docker compose -f docker-compose.prod.yml ps`
- **Logs d'un service** : `docker compose -f docker-compose.prod.yml logs -f api`

## Alternative sans VPS (managé)

Si tu préfères ne pas gérer de serveur : héberge sur **Railway** ou **Render**
(Postgres + Redis en add-ons, déploiement depuis GitHub). Le principe est le même —
API et site sur le même domaine, mêmes variables d'environnement qu'ici. Demande-moi si
tu veux la marche à suivre pour l'un d'eux.
