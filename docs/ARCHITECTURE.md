# ZShield Dashboard — Architecture

Document de conception. Il précède le code et le contraint. La référence du
protocole agent est `zshield-agent/docs/PROTOCOL.md` ; en cas de divergence,
c'est l'agent qui fait foi, parce qu'il est déjà déployé chez des opérateurs.

---

## 1. Architecture

```
Navigateur (Next.js)
   │  cookie de session, même origine
   ▼
API (Fastify, TypeScript)
   ├── /api/*        surface utilisateur, authentifiée par session
   ├── /v1/agents/*  Agent Gateway, authentifiée par HMAC
   ├── /healthz      liveness, aucune dépendance
   └── /readyz       readiness, teste Postgres + Redis
   │
   ├──► PostgreSQL  vérité, isolée par organisation (RLS)
   └──► Redis       cache de nonces, rate limiting, pub/sub temps réel
           │
           ▼
      WebSocket (/ws) ──► navigateurs abonnés à leur organisation
```

Deux surfaces d'authentification totalement séparées, dans deux arbres de
routes différents, avec deux middlewares différents :

| | `/api/*` | `/v1/agents/*` |
|---|---|---|
| Identité | utilisateur humain | agent d'un serveur |
| Preuve | cookie de session | HMAC-SHA256 par requête |
| Organisation déduite de | la session | la credential |
| CSRF | pertinent | sans objet (pas de cookie) |
| Rate limit | par utilisateur + IP | par agent |

Les mélanger est le défaut d'architecture qui produit une escalade de
privilèges : un agent ne doit jamais pouvoir atteindre une route utilisateur, un
utilisateur ne doit jamais pouvoir écrire dans les tables d'ingestion.

### Pourquoi Fastify plutôt qu'un route handler Next.js

L'agent signe le **corps brut**. Toute couche qui parse puis re-sérialise le
JSON avant que la signature soit vérifiée casse l'empreinte SHA-256 (ordre des
clés, espaces, échappement Unicode). Fastify permet de capturer le buffer brut
avant tout parsing. Next.js est donc réservé au frontend.

### Pourquoi pas d'ORM

Le schéma porte l'isolation multi-tenant dans des contraintes composites et des
politiques RLS. Écrire ces garanties en SQL explicite, versionné et relisible
vaut mieux qu'un fichier de modèle qui les génère. Accès via `pg` et des
requêtes paramétrées.

---

## 2. Modèle de données

```
Organization 1──n Membership n──1 User
     │                                 │
     │ 1──n Server 1──1 Agent          │ 1──n Session
     │         │  1──n ApiCredential   │ 1──n MfaFactor
     │         │  1──n AgentCommand
     │         │  1──n TelemetrySample
     │         │  1──n Alert n──1 Incident
     │ 1──n AuditLog
     │ 1──1 Subscription n──1 Plan
     │ 1──n Entitlement
     │ 1──n NotificationChannel
```

Règles structurelles, appliquées par la base et non par convention :

1. **Toute table de données porte `organization_id`**, y compris les tables
   feuilles comme `alerts`. Dénormalisé volontairement : une jointure oubliée
   dans une clause `WHERE` est un IDOR, une colonne manquante est une erreur SQL.
2. **Les clés étrangères sont composites** : `alerts.(organization_id, server_id)`
   référence `servers.(organization_id, id)`. Rattacher une alerte au serveur
   d'une autre organisation devient impossible, pas seulement improbable.
3. **RLS activée** sur chaque table tenant. La session Postgres porte
   `app.organization_id` ; les politiques filtrent dessus. C'est la deuxième
   couche : si le code oublie un filtre, la base renvoie zéro ligne au lieu des
   données du voisin.
4. Le rôle applicatif est `NOBYPASSRLS`. Les migrations tournent sous un rôle
   distinct.

### Identifiants

Préfixés et opaques : `org_`, `usr_`, `srv_`, `agt_`, `al_`, `inc_`, `cmd_`,
`key_`. 128 bits d'aléa en base32. Pas de séquence exposée : un identifiant
incrémental révèle le volume et invite à l'énumération.

### Stockage des secrets — décision à assumer

Un mot de passe utilisateur est vérifié, donc haché de façon irréversible
(scrypt, paramètres dans la migration). **Un secret HMAC d'agent doit être
recalculé à chaque requête : il ne peut pas être haché.** Il est donc chiffré au
repos en AES-256-GCM avec une clé issue de `ZSHIELD_CREDENTIAL_KEY`
(environnement, jamais en base). Conséquence à connaître : un dump de la base
seul ne suffit pas à usurper un agent, mais un dump + la variable
d'environnement suffit. C'est la limite réelle de ce design ; la lever
demanderait un KMS ou un HSM.

Les jetons de réinitialisation vivent dans `password_resets`, table portée par
l'utilisateur et non par l'organisation : un reset n'appartient à aucune
organisation, et le placer dans une table cloisonnée le rendrait visible aux
administrateurs de l'une d'elles. Un seul jeton vivant par usage et par
utilisateur, index unique partiel à l'appui : demander un nouveau lien invalide
le précédent.

`api_credentials` stocke aussi `secret_hint` (4 derniers caractères) pour que
l'interface puisse identifier une clé sans la révéler, et `last_seen_at` pour
détecter une clé fantôme.

### Rétention

`telemetry_samples` et `alerts` sont partitionnées par mois sur `created_at`.
La rétention est un *entitlement* : détacher une partition est instantané,
supprimer 40 millions de lignes ne l'est pas.

---

## 3. Protocole Agent ↔ SaaS

Implémenté à l'identique de `PROTOCOL.md`. Points que la plateforme doit
respecter et qui ne sont pas négociables :

1. Ordre de vérification : secret → horloge (±300 s) → nonce → signature →
   **puis** parsing du corps. Parser avant d'authentifier expose le parser JSON
   à du trafic non authentifié.
2. Hachage du **corps brut**, jamais d'une ré-sérialisation.
3. Comparaison en temps constant (`crypto.timingSafeEqual`).
4. **Toute réponse est signée, y compris les 401 et les 5xx.** L'agent rejette
   une réponse non signée : sans cela, un intermédiaire réseau pourrait le
   pousser dans l'état « credential révoquée ».
5. L'autorité est l'en-tête signé. Si `server_id` de l'enveloppe diffère de
   l'en-tête, la requête est rejetée en `400 E_VALIDATION`.
6. Deux clés acceptées simultanément pendant une rotation, de l'étape 1 à
   l'étape 4. Fermer la fenêtre trop tôt enferme l'agent dehors.
7. `min_agent_protocol` est obligatoire dans la réponse de handshake. L'agent
   échoue fermé s'il est trop ancien.
8. Une alerte dédupliquée arrive avec `occurrences: 50` : afficher le compteur,
   ne pas créer 50 lignes.

### Ce que la plateforme ne peut pas faire, par conception

Aucun endpoint et aucune commande ne permettent d'exécuter du Lua, d'ouvrir un
shell, de lire un fichier, de récupérer le secret, d'expulser un joueur ou
d'arrêter une ressource. L'allowlist de commandes est côté agent, et
l'opérateur du serveur peut la réduire encore. Un dashboard compromis ne devient
donc pas un accès root sur les serveurs de tous les clients. C'est le choix
d'architecture le plus important du produit.

---

## 4. Permissions

Quatre rôles, vérifiés **côté serveur uniquement**. Le frontend masque des
boutons ; il n'autorise rien.

| Action | OWNER | ADMIN | STAFF | VIEWER |
|---|---|---|---|---|
| Voir serveurs, alertes, incidents, analytics | ✅ | ✅ | ✅ | ✅ |
| Acquitter / résoudre une alerte | ✅ | ✅ | ✅ | ❌ |
| Créer / modifier un incident | ✅ | ✅ | ✅ | ❌ |
| Créer / supprimer un serveur | ✅ | ✅ | ❌ | ❌ |
| Générer / révoquer / rotationner une credential | ✅ | ✅ | ❌ | ❌ |
| Envoyer une commande à un agent | ✅ | ✅ | ❌ | ❌ |
| Modifier la configuration distante d'un agent | ✅ | ✅ | ❌ | ❌ |
| Inviter un membre, changer un rôle | ✅ | ✅ | ❌ | ❌ |
| Promouvoir/rétrograder un OWNER | ✅ | ❌ | ❌ | ❌ |
| Voir les audit logs | ✅ | ✅ | ❌ | ❌ |
| Facturation, plan, suppression de l'organisation | ✅ | ❌ | ❌ | ❌ |

Invariants :

- Une organisation garde **au moins un OWNER** : contrainte vérifiée en
  transaction, pas en JavaScript.
- Personne ne peut élever son propre rôle, même OWNER.
- Une permission est résolue par `(user_id, organization_id)` à chaque requête,
  jamais lue depuis le JWT ou le cookie : une rétrogradation prend effet
  immédiatement.
- Les credentials ne sont affichées qu'une fois, au moment de la création, et
  jamais relisibles ensuite.

---

## 5. Endpoints

### Utilisateur — `/api`

```
POST   /api/auth/register            POST   /api/auth/login
POST   /api/auth/logout              POST   /api/auth/mfa/enroll
POST   /api/auth/mfa/verify          POST   /api/auth/password/reset-request
POST   /api/auth/password/reset      POST   /api/auth/email/verify
GET    /api/auth/me                  GET    /api/auth/sessions
DELETE /api/auth/sessions/:id

GET    /api/organizations            PATCH  /api/organizations/:id
GET    /api/organizations/:id/members
POST   /api/organizations/:id/invitations
PATCH  /api/memberships/:id          DELETE /api/memberships/:id

GET    /api/servers                  POST   /api/servers
GET    /api/servers/:id              PATCH  /api/servers/:id
DELETE /api/servers/:id
GET    /api/servers/:id/health       GET    /api/servers/:id/telemetry
POST   /api/servers/:id/credentials          (génère, affiche une seule fois)
POST   /api/servers/:id/credentials/rotate
DELETE /api/servers/:id/credentials/:keyId   (révocation)
GET    /api/servers/:id/configuration
PUT    /api/servers/:id/configuration        (validée contre le schéma agent)

GET    /api/alerts                   PATCH  /api/alerts/:id
POST   /api/alerts/bulk-acknowledge
GET    /api/incidents                POST   /api/incidents
GET    /api/incidents/:id            PATCH  /api/incidents/:id
POST   /api/incidents/:id/alerts     POST   /api/incidents/:id/comments

GET    /api/agents/:id/commands      POST   /api/agents/:id/commands
GET    /api/audit-logs               GET    /api/analytics/:metric
GET    /api/billing/subscription     GET    /api/billing/entitlements
GET    /api/notifications/channels   POST   /api/notifications/channels
```

Pas de `organization_id` dans une query string. Il vient de la session. Un
paramètre de tenant fourni par le client est un IDOR en attente.

### Agent — `/v1/agents` (contrat figé)

```
POST /v1/agents/handshake
POST /v1/agents/heartbeat
POST /v1/agents/telemetry
POST /v1/agents/alerts
GET  /v1/agents/config?version=<n>
GET  /v1/agents/commands?limit=25
POST /v1/agents/commands/results
POST /v1/agents/credentials/rotate
```

---

## 6. Temps réel

Redis pub/sub en fan-out, WebSocket en diffusion.

```
ingestion (Agent Gateway)
   └─ écrit en Postgres, dans la transaction
   └─ PUBLISH org:<org_id> {type, payload}   après COMMIT
              │
     abonnés WebSocket de cette organisation
```

- Un canal Redis **par organisation**. Le serveur WebSocket n'abonne une socket
  qu'au canal de l'organisation présente dans sa session : le filtrage est fait
  à l'abonnement, pas à l'émission. Filtrer à l'émission, c'est un bug de
  condition qui envoie les alertes d'un client à un autre.
- Authentification à l'ouverture, par le cookie de session. Pas de token dans
  la query string : cela finit dans les logs d'accès.
- Publication **après** `COMMIT`, sinon l'interface affiche une alerte que la
  requête suivante ne trouve pas.
- Le WebSocket est un accélérateur, jamais la source : le client garde un
  polling de secours et rejoue un `GET` après reconnexion. Une socket
  silencieusement morte ne doit pas produire un dashboard faussement calme.
- Reconnexion : backoff exponentiel avec jitter, 1 s → 30 s, et
  `Last-Event-Seq` pour rattraper ce qui a été manqué.
- Événements : `agent.connected`, `agent.disconnected`, `agent.state_changed`,
  `alert.created`, `alert.updated`, `incident.created`, `incident.updated`,
  `command.acknowledged`, `server.health_changed`.

### Détection de déconnexion

Un agent qui disparaît n'envoie rien — il n'y a donc rien à recevoir. Un balayeur
périodique marque `OFFLINE` tout serveur dont
`last_heartbeat_at < now() - 3 × heartbeat_interval`, et émet l'événement. Sans
ce balayeur, un serveur tombé reste affiché `ONLINE` indéfiniment.

---

## 7. Sécurité

| Menace | Mesure |
|---|---|
| Fuite inter-tenant | `organization_id` obligatoire + FK composites + RLS + tests d'isolation |
| IDOR | résolution du tenant depuis la session, jamais depuis l'entrée |
| Injection SQL | requêtes paramétrées exclusivement ; aucune concaténation |
| Mass assignment | allowlist Zod par endpoint, `strict()` partout |
| Rejeu d'une requête agent | nonce en Redis, TTL 900 s, `SET NX` |
| Vol de session | cookie `HttpOnly`, `Secure`, `SameSite=Lax`, rotation à l'élévation |
| CSRF | double submit + `SameSite`, sur les mutations `/api/*` |
| Bruteforce mot de passe | rate limit par IP et par compte, délai progressif |
| Énumération de comptes | réponse identique que l'email existe ou non |
| XSS | React échappe par défaut ; CSP stricte ; aucun `dangerouslySetInnerHTML` |
| Secrets dans les logs | rédaction par nom de clé au niveau du logger |
| Dashboard compromis | allowlist de commandes côté agent ; aucun endpoint d'exécution |

Headers : `Strict-Transport-Security`, `Content-Security-Policy`,
`X-Content-Type-Options`, `Referrer-Policy: strict-origin-when-cross-origin`,
`X-Frame-Options: DENY`, `Permissions-Policy` minimale. CORS : allowlist
explicite d'origines, jamais `*` avec credentials.

Audit log : append-only. Pas de `UPDATE`, pas de `DELETE` accordés au rôle
applicatif. Un journal d'audit modifiable par l'application qu'il surveille ne
prouve rien.

### Limites connues, à dire au client plutôt qu'à découvrir

- Le secret d'agent est une credential porteuse. Qui lit la configuration du
  serveur FiveM peut usurper l'agent.
- Le chiffrement des secrets protège d'un dump de base, pas d'une compromission
  de l'hôte API.
- Le rate limiting en Redis dégrade en « autoriser » si Redis tombe. Le choix
  inverse transformerait une panne de cache en panne totale. C'est un arbitrage
  explicite, pas un oubli.
- La signature prouve la détention du secret, pas la bonne santé de la
  plateforme.

---

## 7 bis. Les deux lectures légitimement hors tenant

RLS cadre tout sur `app.organization_id`. Deux lectures du produit sont pourtant
antérieures à la connaissance de l'organisation, et l'ignorer produit un échec
**silencieux** plutôt qu'une erreur :

| Lecture | Quand | Politique |
|---|---|---|
| « de quelles organisations suis-je membre ? » | création de session, listing | `membership_self_read`, SELECT, cadrée sur `app.user_id` |
| « à quelle organisation appartient cette credential d'agent ? » | première étape de l'authentification agent | `agent_credential_lookup`, SELECT, exige `app.agent_lookup = 'on'` ET l'absence de contexte d'organisation |

Ces deux chemins ont d'abord été écrits sans politique dédiée. Résultat observé
en test d'intégration : les sessions naissaient sans organisation, et **aucun
agent n'aurait pu s'authentifier en production** — un 401 côté opérateur, rien
dans les logs côté plateforme. C'est le type de panne que seule une base réelle
révèle ; une base simulée aurait renvoyé les lignes.

L'alternative était de donner `BYPASSRLS` au rôle applicatif, ou de passer par
une fonction `SECURITY DEFINER`. Le choix retenu garde le contournement
**inscrit dans le schéma**, nommé, limité à `SELECT` et à une table : un futur
`SELECT * FROM alerts` sans contexte reste bloqué. Les migrations 0002 et 0003
portent ces corrections, et `db/tests/isolation.sql` vérifie que les deux
politiques restent étroites — notamment qu'elles n'ouvrent aucune écriture.

## 8. Arborescence

```
zshield-dashboard/
├── docker-compose.dev.yml
├── .env.example
├── package.json                  workspaces
├── db/
│   ├── migrations/               SQL numéroté, idempotent, réversible
│   └── seed.dev.sql
├── apps/
│   ├── api/
│   │   ├── src/
│   │   │   ├── config/env.ts     validation de l'environnement au boot
│   │   │   ├── lib/              db, redis, crypto, ids, errors, logger
│   │   │   ├── agent-gateway/    protocol, verify, replay, schemas, routes
│   │   │   ├── auth/             sessions, mot de passe, MFA
│   │   │   ├── rbac/             matrice de permissions
│   │   │   ├── api/              routes utilisateur
│   │   │   ├── realtime/         pub/sub + WebSocket
│   │   │   └── server.ts
│   │   └── test/
│   └── web/                      Next.js (étape ultérieure)
└── docs/
    ├── ARCHITECTURE.md           ce document
    └── API.md
```

---

## 9. État de livraison

| Étape | Contenu | État |
|---|---|---|
| 1 | Architecture, modèle de données, migrations, Agent Gateway complet, conformité protocole | **livrée** |
| 2 | Auth (sessions, MFA/TOTP, reset), RBAC, API utilisateur, realtime WebSocket, tests d'isolation | **livrée** |
| 3 | Frontend Next.js (11 routes, assistant d'ajout de serveur, temps réel) | **livrée** |
| 4 | Intégration d'un prestataire de paiement, envoi des emails et webhooks, observabilité | à faire |

Vérifications exécutées :

- 118 tests Node (conformité protocole, crypto, RBAC, TOTP, intégration HTTP) ;
- 16 vérifications SQL d'isolation, sous le rôle applicatif, RLS active ;
- typecheck TypeScript strict sans erreur sur les deux applications ;
- `next build` complet, 16 routes générées ;
- parcours de bout en bout au curl contre l'API réelle : inscription,
  connexion, quotas, révocation de session, refus CSRF.

### Note sur le frontend

Le frontend est servi sur la MÊME ORIGINE que l'API, par un proxy déclaré dans
`next.config.mjs`. Ce n'est pas du confort : le cookie de session est
`SameSite=Lax` et le jeton CSRF est un second cookie lisible par le script. En
origine croisée, `Lax` bloquerait les mutations et il faudrait passer en
`SameSite=None`, c'est-à-dire renoncer à la protection CSRF native du
navigateur. En production, le même effet s'obtient par le reverse proxy amont.

La page « Joueurs » ne contient aucune liste de joueurs, et c'est voulu : le
protocole agent ne transporte aucun identifiant de joueur — ni pseudo, ni
licence, ni adresse IP — seulement un effectif. La page dit explicitement ce
qu'elle ne saura pas, pour qu'aucun utilisateur ne cherche l'écran manquant.

Ce que l'étape 2 ne couvre pas encore : l'envoi réel des emails (les jetons sont
produits et stockés, la remise est un branchement à faire), la vérification
d'email n'est pas exigée à la connexion, et les invitations de membres ont leur
table mais pas encore leurs endpoints d'acceptation.
