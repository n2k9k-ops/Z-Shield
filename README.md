# ZShield Dashboard

SaaS multi-tenant de supervision de serveurs FiveM. Reçoit les battements, la
télémétrie et les alertes de l'agent `zshield-agent`, et permet à plusieurs
organisations d'administrer plusieurs serveurs.

**État : étapes 1 à 3 livrées, plus la couche anticheat (détections, bans,
règles).** Découpage détaillé dans
`docs/ARCHITECTURE.md` §9.

## Ce qui est livré

| Élément | Emplacement |
|---|---|
| Architecture, modèle de données, permissions, endpoints, realtime, sécurité | `docs/ARCHITECTURE.md` |
| Schéma PostgreSQL, RLS, FK composites, partitionnement, 3 migrations | `db/migrations/` |
| Passerelle agent : les 8 endpoints du protocole | `apps/api/src/agent-gateway/` |
| Sessions, MFA/TOTP, reset de mot de passe, verrouillage de compte | `apps/api/src/auth/` |
| Matrice RBAC et invariants de rôle | `apps/api/src/rbac/permissions.ts` |
| API utilisateur : serveurs, credentials, alertes, incidents, commandes, audit, quotas | `apps/api/src/api/routes.ts` |
| Temps réel WebSocket, un canal par organisation | `apps/api/src/realtime/` |
| Frontend Next.js : 11 routes, assistant d'ajout de serveur, temps réel | `apps/web/` |
| 118 tests Node + 16 vérifications SQL d'isolation | `apps/api/test/`, `db/tests/` |

## Couche anticheat

Ajoutée par-dessus le dashboard, dans le même esprit qu'un produit comme
WaveShield, mais sans jamais accéder à la machine des joueurs.

| Élément | Emplacement |
|---|---|
| Tables détections, bans, règles, réglages + vue de score de menace | `db/migrations/0004_anticheat.sql` |
| 8 endpoints (détections, joueurs à risque, bans, règles, réglages) | `apps/api/src/api/routes.ts` |
| 6 permissions RBAC réparties sur les 4 rôles | `apps/api/src/rbac/permissions.ts` |
| 4 écrans : Joueurs à risque, Détections, Bannissements, Règles | `apps/web/app/(app)/{players,detections,bans,rules}/` |

Vérifié au niveau de l'API : isolation multi-tenant de la vue de score sous le
rôle applicatif (une organisation ne voit jamais le score d'une autre),
idempotence des bans (re-bannir met à jour au lieu d'empiler), levée de ban,
défauts de configuration renvoyés par l'API comme source unique de vérité.

**Ce que l'anticheat ne fait pas, par conception** : aucune capture d'écran,
aucun flux, aucun accès à la machine du joueur. Une détection est un fait
observé côté serveur (« vitesse 148 là où le plafond est 62 »), pas une image.
La page « Joueurs à risque » ne liste que les joueurs ayant déclenché une
détection, pas l'annuaire complet — le protocole ne transporte aucun identifiant
de joueur ordinaire. Le bannissement est une entrée de registre que l'agent
applique côté serveur ; la plateforme n'a aucun endpoint pour agir directement
sur un joueur. C'est le même principe que le reste du système : un dashboard
compromis ne devient jamais un accès aux machines des clients.

Reste à faire pour rendre ces écrans pleinement vivants : le core `zshield_ac`,
le moteur côté serveur qui *produit* réellement ces détections (mouvement
impossible, godmode, events injectés). C'est le document 1 de la spécification,
le plus volumineux, à traiter dans un dépôt séparé.

## Ce qui n'est pas fait

Étape 4 : intégration d'un prestataire de paiement, envoi réel des emails et
des webhooks, observabilité.

Manques assumés et dits dans l'interface, plutôt que masqués : la remise des
emails n'est pas branchée (les jetons sont produits et stockés), la vérification
d'adresse n'est pas exigée à la connexion, l'écran d'activation du second
facteur n'est pas ouvert alors que sa vérification l'est côté serveur, et les
invitations de membres ont leur table sans leurs endpoints d'acceptation.

## Démarrage

```bash
cp .env.example .env
echo "ZSHIELD_CREDENTIAL_KEY=$(openssl rand -base64 32)" >> .env
echo "SESSION_SECRET=$(openssl rand -base64 48)" >> .env

npm install
npm run db:up            # Postgres + Redis
npm run migrate
psql "$DATABASE_MIGRATION_URL" -f db/seed.dev.sql   # optionnel
npm run dev
```

`ZSHIELD_CREDENTIAL_KEY` chiffre les secrets HMAC des agents. **La perdre rend
toutes les credentials illisibles** et oblige chaque opérateur à réinstaller une
clé sur son serveur FiveM. À sauvegarder séparément de la base : la stocker au
même endroit annule l'intérêt du chiffrement.

## Vérification

```bash
npm run typecheck        # API et frontend, 0 erreur
npm run build            # next build, 16 routes

# Tests unitaires et de conformité, sans dépendance externe
npm test

# Tests d'intégration : nécessitent Postgres et Redis
TEST_DATABASE_URL="postgres://zshield_app:...@localhost:5432/zshield" \
TEST_DATABASE_ADMIN_URL="postgres://zshield_migrator:...@localhost:5432/zshield" \
TEST_REDIS_URL="redis://localhost:6379" \
npm test

# Isolation multi-tenant, à exécuter SOUS LE RÔLE APPLICATIF
psql "postgres://zshield_app:...@localhost:5432/zshield" \
     -v ON_ERROR_STOP=1 -f db/tests/isolation.sql
```

Sans les variables `TEST_*`, la suite d'intégration est **ignorée** : elle
apparaît marquée `# SKIP` dans la sortie, et non comptée comme réussie. À noter
que le compteur `# skipped` de Node reste à 0 dans ce cas, la suite entière
étant comptée dans `# suites` — regarder la ligne `# SKIP`, pas le compteur. Le test d'isolation SQL exécuté sous le rôle propriétaire ou un
superutilisateur passerait en ne prouvant rien : ces rôles contournent RLS, et
la vérification 9 échoue exprès dans ce cas.

Trois suites méritent une mention :

- `test/conformance.test.ts` exécute le vrai code Lua de l'agent et compare les
  chaînes canoniques et les signatures octet par octet. Sans Lua, il retombe sur
  les vecteurs figés. C'est la seule protection contre la panne où la plateforme
  renvoie un 401 à tous les agents déployés sans message exploitable.
- `test/integration.test.ts` passe par `app.inject()`, donc par le routage réel,
  les gardes réelles et PostgreSQL avec RLS active. Il vérifie notamment qu'un
  utilisateur d'une organisation ne peut ni lire ni modifier les données d'une
  autre, et qu'un agent authentifié ne peut pas écrire sur le serveur du voisin.
- `db/tests/isolation.sql` vérifie la couche base indépendamment du code.

## Points de conception à connaître avant de modifier le code

1. **Le corps des requêtes agent est haché sous sa forme brute.** Toute couche
   qui parse puis re-sérialise avant vérification casse la signature. C'est pour
   cela que l'API est en Fastify et non en route handler Next.js.

2. **Toutes les réponses agent sont signées, y compris les 401 et les 5xx.**
   L'agent rejette une réponse non signée : sans cela, un intermédiaire réseau
   pourrait le pousser dans l'état « credential révoquée », qui coupe tout
   trafic jusqu'à intervention humaine sur le serveur.

3. **`SET LOCAL` et non `SET` pour les variables de session Postgres.** Un `SET`
   simple survit au retour de la connexion au pool, et la requête suivante —
   celle d'un autre client — hérite du contexte précédent.

4. **Trois cadrages de transaction, à ne pas confondre** : `withTenant` pour les
   données d'organisation, `withUser` pour ses propres adhésions, et
   `withAgentLookup` pour la seule lecture qui précède la connaissance de
   l'organisation. Voir `docs/ARCHITECTURE.md` §7 bis.

5. **Le rôle n'est jamais mis en cache dans la session.** Il est résolu en base
   à chaque requête, ce qui rend une rétrogradation immédiate.

6. **Deux clés d'agent sont acceptées pendant une rotation.** Fermer la fenêtre
   avant que l'agent ait confirmé par un handshake signé avec la nouvelle clé
   l'enferme dehors, sans récupération à distance possible.

7. **Le cache anti-rejeu échoue fermé, la limitation de débit échoue ouverte.**
   Directions opposées, volontairement : voir l'en-tête de
   `src/agent-gateway/replay.ts`.

8. **Le frontend est servi sur la même origine que l'API**, via le proxy de
   `next.config.mjs`. En origine croisée, le cookie `SameSite=Lax` bloquerait
   les mutations et il faudrait passer en `SameSite=None`, c'est-à-dire
   renoncer à la protection CSRF native du navigateur.

9. **La page « Joueurs » ne liste aucun joueur, et c'est voulu.** Le protocole
   agent ne transporte aucun identifiant de joueur, seulement un effectif.
   Ajouter cet écran demanderait de changer le protocole des deux côtés et
   d'assumer une obligation RGPD que le produit n'a pas prise.

10. **Node tourne en mode « strip-only ».** Les propriétés de constructeur
   TypeScript (`constructor(private readonly x: T)`) ne sont pas supportées et
   font échouer le démarrage à l'import. Les champs sont déclarés explicitement.

## Limites assumées

- Un secret d'agent est une credential porteuse : qui peut lire la configuration
  du serveur FiveM peut usurper l'agent auprès de la plateforme.
- Le chiffrement des secrets protège d'un dump de base, pas d'une compromission
  de l'hôte API, qui détient la clé.
- La signature prouve la détention du secret partagé, pas la bonne santé de la
  plateforme. C'est pourquoi l'allowlist de commandes reste côté agent, et
  qu'aucun endpoint ne permet d'exécuter du code sur un serveur client.
- Aucun paiement réel n'est implémenté : le modèle et les quotas existent,
  l'intégration d'un prestataire demande sa spécification.
- La contrainte d'idempotence des alertes est garantie à l'intérieur d'une
  partition mensuelle, pas globalement. Documenté dans la migration 0001.
- scrypt est utilisé pour les mots de passe plutôt qu'Argon2id, pour éviter une
  dépendance binaire dans l'image. Les paramètres retenus sont au-dessus des
  recommandations OWASP pour scrypt, mais Argon2id resterait préférable.
