# Z-Shield Dashboard — Notes admin

## Créer le compte admin initial (une seule fois)

L'inscription publique est **désactivée** (`/register` renvoie vers `/login`, l'API refuse
`register` avec 403). Pour créer TON compte :

1. Sur Render, service **API**, ajoute la variable `ALLOW_REGISTRATION = true` puis redéploie.
2. Va sur le web → `/register` (temporairement réactivé), crée ton compte + organisation.
3. Remets `ALLOW_REGISTRATION = false` (ou supprime la variable) et redéploie. Plus personne
   ne peut créer de compte.
4. Pour pouvoir **générer des licences**, rends ce compte admin plateforme : sur ta base
   Postgres (Render → base → Query), exécute une fois :
   ```sql
   UPDATE users SET is_platform_admin = true WHERE email = 'ton-email@exemple.com';
   ```

## Générer une licence pour un client (depuis le dashboard)

Onglet **Serveurs & licence** → carte « Générer une licence » :
- **Identifiant serveur** = l'« Identifiant de ce serveur » que le client lit dans sa console
  au démarrage (ou `any` pour une clé non liée).
- **Plan** + **durée** (jours) → **Générer la clé**.
- Copie le `token` et donne-le au client : il le colle dans `zshield-ac/config/config.lua`
  (`license = { key = '...' }`).

> La génération appelle `POST /api/licenses/generate` (permission `billing.manage`). Le secret
> de signature vit côté serveur, jamais dans le navigateur.

## Comptes multiples — inviter des utilisateurs (nouveau)

Chaque organisation (= un serveur/client) peut avoir plusieurs comptes.

1. Onglet **Comptes & accès** → bouton **Ajouter un compte**.
2. Entre l'**e-mail** de la personne + son **rôle** (Administrateur / Modérateur / Lecteur) →
   **Générer le code**. Un **lien** `…/invite.html?code=…` (et le code seul) s'affiche **une seule
   fois** — copie-le et envoie-le.
3. La personne ouvre le lien → « Crée ton compte pour accéder au serveur *Nom* » → elle choisit
   son nom + mot de passe → elle **rejoint ton organisation** avec le rôle prévu et arrive
   directement sur le panel.

Détails techniques : le code est un jeton opaque de 32 octets, **seul son hachage est stocké**
(migration `0014_invitation_acceptance.sql`, politiques RLS « par code »). Invitations à usage
unique, **valables 7 jours**, révocables depuis la liste « Invitations en attente ». Endpoints :
`POST/GET/DELETE /api/invitations`, `GET /api/invitations/lookup`, `POST /api/invitations/accept`.
L'inscription publique (`/register`) reste **désactivée** : on ne rejoint que sur invitation.

> ⚠️ Après avoir tiré cette version, Render relance la migration automatiquement
> (`preDeployCommand`). La table `invitations` existait déjà ; 0014 n'ajoute que les politiques
> d'acceptation, donc aucune perte de données.

## Console branchée sur l'API réelle

Toutes les vues lisent désormais les vraies données du dashboard (`/api/...`), avec la session
et la protection CSRF. En l'absence de serveur/agent connecté, chaque vue affiche un état vide
**honnête** (aucun chiffre inventé).

- **Vue d'ensemble** : KPI (`/api/overview`), menaces bloquées 24 h (`/api/protections`),
  activité en direct (`/api/detections`), détections par heure (`/api/analytics/detections-per-hour`).
- **Bans & sanctions** (`/api/bans`) : la file « Sanctions en attente » propose
  Confirmer / Réduire en kick / Faux positif ; les bans actifs, Débannir — chaque action appelle
  réellement l'API (`/confirm`, `/kick`, `/false-positive`, `/lift`) et consigne un retour
  d'apprentissage pour l'anticheat.
- **Joueurs** (`/api/players`) : joueurs à risque (score, détections, dernière activité) ;
  la fiche permet un bannissement réel (`POST /api/bans`).
- **Configuration** (`/api/servers/:id/protection-settings`) : le catalogue réel de protections
  (activer/désactiver + Surveiller/Bloquer). **Enregistrer** écrit les réglages **puis** envoie une
  commande `refresh_configuration` à l'agent : le cœur anticheat recharge sa configuration au
  prochain battement (`config_version` incrémenté). C'est le vrai « config changée → l'anticheat
  redémarre », pas un simple message.
- **Serveurs & licence** : liste réelle (`/api/servers`), ajout d'un serveur (`POST /api/servers`),
  et génération de licence (`POST /api/licenses/generate`).
- **Comptes & accès** : membres réels (`/api/members`) et matrice RBAC réelle (`/api/rbac/matrix`,
  la même qui autorise côté serveur).
- **Terminal** : commandes réelles mises en file pour l'agent (`status`, `health`, `refresh`,
  `lockdown`). Les bans/kicks passent par l'onglet dédié (tracés + preuve).

Choix de conception assumés (honnêteté) :

- **Carte live** : *désactivée par défaut*. Elle n'existe que si l'agent a `live.enabled = true`.
  L'agent envoie alors un instantané (position, santé, arme, ping) toutes les ~5 s ; la plateforme
  ne le stocke **pas en base** : seul le dernier instantané vit en mémoire (Redis, 20 s).
  Aucune IP, Steam, Discord ni HWID n'est envoyé.
- **Captures** : à la demande d'un membre du staff uniquement (jamais en continu). C'est une
  capture du **rendu du jeu** (via `screenshot-basic`), pas de l'écran ni des applications du
  joueur. Le délai est de ~30 à 60 s (l'agent relève ses commandes à intervalle régulier) et la
  commande `capture_request` doit être autorisée dans `commands.allowed`. Stockage 30 jours, image
  à usage unique via un jeton d'envoi de 5 min. Une capture côté client peut être bloquée ou
  falsifiée par un cheat interne : c'est un élément de preuve corroborant, jamais une preuve seule.
- **Multi-vue / spectate** : place une caméra d'administration **dans le jeu** via
  `spectate_request`, jamais une capture de la machine du joueur.
- **Installation** : le bouton Télécharger génère un vrai `zshield-server.cfg` prêt à coller. Le
  paquet complet des ressources est fourni séparément (`tools/package_client.sh`).
