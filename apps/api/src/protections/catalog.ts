/**
 * Catalogue des protections pilotables.
 *
 * Source unique de vérité, côté serveur : le dashboard et l'agent lisent cette
 * liste. Chaque protection a un identifiant stable (jamais renommé), un libellé
 * simple, une catégorie, et un réglage par défaut (activée + mode).
 *
 * Deux modes possibles :
 *   - 'watch'  (Surveiller) : Z-Shield observe et prévient, sans agir.
 *   - 'block'  (Bloquer)    : Z-Shield empêche l'action automatiquement.
 *
 * Les identifiants voyagent jusqu'au cœur anticheat : on ne les change pas.
 */

export type ProtectionMode = 'watch' | 'block';

export interface ProtectionDef {
  id: string;
  name: string;
  description: string;
  defaultEnabled: boolean;
  defaultMode: ProtectionMode;
}

export interface ProtectionCategory {
  id: string;
  label: string;
  items: ProtectionDef[];
}

const def = (
  id: string,
  name: string,
  description: string,
  defaultMode: ProtectionMode = 'block',
  defaultEnabled = true,
): ProtectionDef => ({ id, name, description, defaultEnabled, defaultMode });

export const PROTECTION_CATALOG: ProtectionCategory[] = [
  {
    id: 'deplacement',
    label: 'Déplacement',
    items: [
      def('mv_teleport', 'Anti téléportation', 'Bloque les sauts de position impossibles sur la carte.'),
      def('mv_noclip', 'Anti no-clip', 'Empêche de traverser murs et sol.'),
      def('mv_superjump', 'Anti super-saut', 'Détecte les sauts anormaux.'),
      def('mv_fly', 'Anti vol / déplacement aérien', 'Repère les déplacements en l’air sans véhicule.'),
      def('mv_speed', 'Vitesse impossible', 'Vitesse plus élevée que le jeu ne permet.', 'watch'),
      def('mv_accel', 'Accélération anormale', 'Changements de vitesse brutaux.', 'watch'),
      def('mv_pos_no_event', 'Position sans événement', 'La position change sans action légitime.'),
      def('mv_teleport_to_player', 'Téléport vers un joueur', 'Se téléporte successivement sur des joueurs.'),
    ],
  },
  {
    id: 'joueur',
    label: 'Joueur',
    items: [
      def('pl_invincible', 'Anti invincibilité', 'Bloque l’invincibilité persistante.'),
      def('pl_health_over_max', 'Vie au-dessus du maximum', 'Vie qui dépasse les valeurs normales.'),
      def('pl_armor', 'Armure anormale', 'Armure impossible.'),
      def('pl_regen', 'Régénération instantanée', 'Se soigne d’un coup ou en boucle.', 'watch'),
      def('pl_invisible', 'Anti invisibilité', 'Détecte les joueurs rendus invisibles.', 'watch'),
      def('pl_damage_resist', 'Résistance aux dégâts', 'Prend anormalement peu de dégâts.', 'watch'),
      def('pl_ragdoll_off', 'Suppression du ragdoll', 'Ne tombe jamais au sol.', 'watch', false),
    ],
  },
  {
    id: 'armes',
    label: 'Armes',
    items: [
      def('wp_no_source', 'Arme sans source valable', 'Arme obtenue sans autorisation serveur.'),
      def('wp_ammo_illegit', 'Munitions illégitimes', 'Munitions ajoutées sans raison.'),
      def('wp_ammo_impossible', 'Munitions impossibles', 'Quantité de munitions irréaliste.'),
      def('wp_fire_rate', 'Cadence de tir', 'Tirs trop rapides.'),
      def('wp_reload_instant', 'Rechargement instantané', 'Recharge d’un coup ou en boucle.'),
      def('wp_no_recoil', 'Absence de recul', 'Aucun recul anormal.', 'watch'),
      def('wp_damage_fake', 'Dégâts truqués', 'Dégâts incompatibles avec l’arme.'),
      def('wp_wallbang', 'Tir à travers les murs', 'Tirs qui traversent les obstacles.'),
      def('wp_shots_impossible', 'Nombre de tirs impossible', 'Trop de tirs sur un court instant.', 'watch'),
    ],
  },
  {
    id: 'vehicules',
    label: 'Véhicules',
    items: [
      def('vh_spawn_unauth', 'Spawn non autorisé', 'Véhicule créé sans autorisation.'),
      def('vh_spam', 'Anti-spam de véhicules', 'Création massive de véhicules.'),
      def('vh_forbidden_zone', 'Zones interdites', 'Création dans des zones bloquées.'),
      def('vh_invincible', 'Véhicule invincible', 'Véhicule rendu indestructible.', 'watch'),
      def('vh_speed', 'Vitesse / accélération impossible', 'Véhicule trop rapide.', 'watch'),
      def('vh_teleport', 'Téléport du véhicule', 'Le véhicule saute de position.'),
      def('vh_repair', 'Réparation instantanée', 'Réparé d’un coup en boucle.', 'watch'),
      def('vh_model', 'Changement de modèle', 'Modèle modifié anormalement.', 'watch', false),
    ],
  },
  {
    id: 'reseau',
    label: 'Réseau',
    items: [
      def('nt_event_server', 'Événements serveur protégés', 'Empêche d’appeler des events serveur depuis le client.'),
      def('nt_event_bad_params', 'Paramètres impossibles', 'Event appelé avec des valeurs aberrantes.'),
      def('nt_antiflood', 'Anti-flood', 'Limite les appels trop fréquents.'),
      def('nt_event_frequency', 'Fréquence anormale', 'Un même event appelé en boucle.'),
      def('nt_event_admin', 'Événements admin protégés', 'Bloque les tentatives d’events admin.'),
      def('nt_money_via_event', 'Argent/inventaire via event', 'Modif d’argent par un event non autorisé.'),
      def('nt_item_no_txn', 'Items sans transaction', 'Items donnés sans transaction.', 'watch'),
      def('nt_perms_via_event', 'Permissions via event', 'Changement de permissions par event.'),
    ],
  },
  {
    id: 'argent',
    label: 'Argent',
    items: [
      def('mn_create', 'Création d’argent', 'Argent apparu sans transaction.'),
      def('mn_balance_jump', 'Variation brutale de solde', 'Le solde change d’un coup.', 'watch'),
      def('mn_item_no_source', 'Items sans source', 'Objets apparus sans origine.'),
      def('mn_qty_impossible', 'Quantités impossibles', 'Quantités négatives ou irréalistes.'),
      def('mn_item_dupe', 'Duplication d’items', 'Objets dupliqués.'),
      def('mn_txn_frequency', 'Fréquence achat/vente', 'Transactions à une vitesse impossible.', 'watch'),
      def('mn_item_not_owned', 'Item non possédé', 'Utilise un item qu’il n’a pas.'),
      def('mn_inv_out_of_bounds', 'Modification hors des fonctions', 'Inventaire modifié hors des voies prévues.', 'watch'),
    ],
  },
  {
    id: 'aimbot',
    label: 'Aimbot / ESP',
    items: [
      def('ai_precision', 'Précision suspecte', 'Précision anormale sur la durée. Reste en Surveiller au début.', 'watch'),
      def('ai_reaction', 'Temps de réaction', 'Réactions trop rapides pour un humain.', 'watch'),
      def('ai_target_switch', 'Changements de cible', 'Cibles changées instantanément en boucle.', 'watch'),
      def('ai_walltrack', 'Tracking à travers les murs', 'Suit des joueurs derrière un obstacle.', 'watch'),
      def('ai_camera', 'Rotation caméra anormale', 'Rotations de vue impossibles.', 'watch', false),
      def('ai_headshot', 'Taux de headshots', 'Taux de tirs à la tête anormal.', 'watch', false),
    ],
  },
  {
    id: 'spam',
    label: 'Spam & abus',
    items: [
      def('sp_events', 'Spam d’événements', 'Envoie des events en masse.'),
      def('sp_commands', 'Spam de commandes', 'Répète des commandes en boucle.'),
      def('sp_entities', 'Création massive d’entités', 'Vague d’entités d’un coup.'),
      def('sp_peds', 'Peds en masse', 'Création massive de PNJ.'),
      def('sp_objects', 'Objets en masse', 'Création massive d’objets.'),
      def('sp_explosions', 'Explosions répétées', 'Explosions / effets en boucle.'),
      def('sp_mass_delete', 'Suppression massive', 'Supprime beaucoup d’entités d’un coup.', 'watch'),
      def('sp_request_flood', 'Flood de requêtes', 'Inonde le serveur de requêtes.'),
    ],
  },
  {
    id: 'listes',
    label: 'Listes & modèles',
    items: [
      def('bl_ped_models', 'Blacklist de peds', 'Refuse la création de modèles de PNJ interdits (peds « monstres », animaux de grief).'),
      def('bl_object_models', 'Blacklist d’objets', 'Refuse la création de props interdits (objets géants qui bloquent une zone).'),
      def('expl_type_block', 'Types d’explosion interdits', 'Bloque à la source certains types d’explosion (canon orbital, obus de char…).'),
    ],
  },
  {
    id: 'connexion',
    label: 'Connexion',
    items: [
      def('conn_name_blocklist', 'Pseudos interdits', 'Refuse les pseudos usurpant le staff ou une marque.'),
      def('conn_name_length', 'Longueur de pseudo', 'Signale les pseudos vides ou anormalement longs.', 'watch'),
      def('conn_relog', 'Anti-relog', 'Repère une reconnexion trop rapide après un départ (évasion de kick).', 'watch'),
    ],
  },
  // ---------------------------------------------------------------------------
  // Protections avancées (serveur-autoritatives). Les préfixes av_/nw_/rc_/rs_/bh_
  // sont mappés côté cœur (server/protections.lua → PREFIX_CATEGORY) vers les
  // catégories du moteur de détection : activer/désactiver pilote réellement le
  // gate de la catégorie correspondante.
  // ---------------------------------------------------------------------------
  {
    id: 'aim_stat',
    label: 'Visée — analyse statistique',
    items: [
      def('av_headshot_ratio', 'Ratio de headshots anormal', 'Compare le taux de tirs à la tête à une base humaine (test binomial).', 'watch'),
      def('av_snap', 'Recentrage instantané (snap)', 'Amplitude de recentrage de visée juste avant le tir, typique d’un aimbot.', 'watch'),
      def('av_reaction', 'Temps de réaction surhumain', 'Tirs répétés sous le plancher de réaction humaine.', 'watch'),
      def('av_silent_aim', 'Silent aim', 'Touche sans ligne de visée valable, même après compensation de latence.'),
      def('av_shot_rewind', 'Validation de tir serveur (rewind)', 'Rembobine la cible au moment du tir et rejette une touche géométriquement impossible.'),
      def('av_no_recoil', 'Absence de recul (statistique)', 'Dispersion de tir anormalement nulle sur la durée.', 'watch'),
      def('av_sprt', 'Preuve séquentielle (SPRT)', 'Accumule la preuve tir après tir avec des taux d’erreur bornés avant de trancher.', 'watch'),
      def('av_baseline', 'Ligne de base adaptative', 'Apprend la distribution normale par joueur (z-score) et signale un écart soutenu.', 'watch'),
    ],
  },
  {
    id: 'reseau_adv',
    label: 'Réseau & injection',
    items: [
      def('nw_executor', 'Anti-exécuteur & menus de triche', 'Ressource non déclarée = script injecté, et signatures de menus connus (Lapsus, Eulen, RedEngine, Susano…).'),
      def('nw_injection_traces', 'Traces d’injection & anti-dumper', 'Signatures/events réservés laissés par les menus, et énumération/dump d’events en rafale (vol de logique serveur).'),
      def('nw_lagswitch', 'Anti lag-switch', 'Gel volontaire de la connexion corrélé à un effet en jeu.'),
      def('nw_desync', 'Désync origine de tir', 'Action émise depuis une position très éloignée de la position serveur.'),
      def('nw_event_flood', 'Flood d’événements réseau', 'Débit d’events réseau au-delà d’un quota dur.'),
      def('nw_clocksync', 'Cohérence d’horloge (speedhack)', 'Temps client qui avance plus vite que le serveur = accélération d’horloge.'),
    ],
  },
  {
    id: 'integrite',
    label: 'Intégrité serveur-autoritaire',
    items: [
      def('rc_health', 'Réconciliation de la vie', 'Le serveur fait foi : une vie client au-dessus de la vérité serveur est corrigée.'),
      def('rc_money', 'Réconciliation de l’argent', 'Un solde injecté au-dessus de la vérité serveur est rejeté.'),
      def('rc_ammo', 'Réconciliation des munitions', 'Des munitions au-delà de la vérité serveur sont rejetées.'),
      def('rc_godmode', 'Anti god-mode (dégâts non appliqués)', 'Le joueur encaisse des dégâts mais sa vie ne baisse pas → invincibilité.'),
      def('rc_reach', 'Anti reach / distance', 'Action (mêlée, loot, interaction) au-delà de la portée légitime.'),
      def('rc_invariants', 'Invariants durs (bornes physiques)', 'Registre de règles toujours vraies : toute valeur hors bornes est rejetée.'),
      def('rc_envelope', 'Enveloppes de débit', 'Plafond de cadence par classe d’action (tir, spawn, message, achat).'),
      def('rc_spawnkill', 'Anti spawn-kill', 'Dégâts infligés à une victime encore protégée au spawn.', 'watch'),
    ],
  },
  {
    id: 'ressources',
    label: 'Ressources & auto-protection',
    items: [
      def('rs_stop_protected', 'Anti-arrêt de ressources protégées', 'Empêche l’arrêt des ressources déclarées protégées par une source non autorisée.'),
      def('rs_stop_anticheat', 'Anti-arrêt de l’anticheat', 'Toute tentative d’arrêt du cœur anticheat est bloquée et traitée en incident critique.'),
      def('rs_backdoor', 'Détection de backdoor', 'Repère les portes dérobées cachées dans des ressources.'),
      def('rs_crashguard', 'Anti-crash (entités malformées)', 'Valeurs infinies/aberrantes rejetées avant propagation.'),
    ],
  },
  {
    id: 'comportement',
    label: 'Comportement & réputation',
    items: [
      def('bh_macro', 'Anti bot / macro', 'Cadence métronomique d’actions trahissant un script.', 'watch'),
      def('bh_trainer', 'Signature de trainer / menu', 'Plusieurs détecteurs sérieux frappant le même joueur en peu de temps.', 'watch'),
      def('bh_reputation', 'Réputation persistante', 'Le risque survit à la reconnexion, accumulé par identifiant et décroissant.', 'watch'),
      def('bh_freecam', 'Anti freecam / spectate', 'Ped figé pendant que le joueur reste actif (aim/tir) = caméra libre probable.', 'watch'),
    ],
  },
  {
    id: 'sante_etat',
    label: 'Santé & état du joueur',
    items: [
      def('pl_regen_block', 'Anti régénération de vie', 'Bloque une régénération de vie anormale, sans source légitime.'),
      def('pl_stat_mod', 'Anti modification de stats', 'Empêche de modifier vie/armure côté client (god-mode partiel).'),
      def('pl_damage_immunity', 'Anti immunité aux dégâts', 'Bloque l’immunité aux dégâts (les balles ne font rien).'),
      def('pl_infinite_stamina', 'Anti endurance infinie', 'Courir sans jamais se fatiguer.', 'watch'),
      def('pl_combat_roll', 'Anti roulade infinie', 'Roulade de combat en boucle (exploit de déplacement).', 'watch'),
      def('pl_model_change', 'Anti changement de modèle', 'Empêche de changer de modèle de personnage à volonté.'),
      def('pl_night_vision', 'Anti vision nocturne', 'Détecte l’activation de la vision nocturne pour un avantage.', 'watch'),
      def('pl_afk_bypass', 'Anti contournement AFK', 'Empêche de tromper le système d’absence.', 'watch'),
      def('pl_lua_input', 'Anti entrée LUA injectée', 'Bloque l’exécution d’entrées Lua injectées côté client.'),
      def('pl_clear_tasks', 'Anti annulation d’actions', 'Empêche d’annuler de force les animations d’autres joueurs.', 'watch'),
    ],
  },
  {
    id: 'armes_detail',
    label: 'Armes — contrôle détaillé',
    items: [
      def('wp_give', 'Anti auto-attribution d’arme', 'Bloque le fait de se donner une arme hors du jeu.'),
      def('wp_remove', 'Anti retrait d’arme forcé', 'Empêche de retirer de force les armes d’autres joueurs.'),
      def('wp_spoofed_bullets', 'Anti balles falsifiées', 'Origine ou trajectoire de balle impossible.'),
      def('wp_kill_exploits', 'Anti kill impossible', 'Kills instantanés ou à distance impossibles.'),
      def('wp_component_mod', 'Anti composant d’arme illégitime', 'Viseur/chargeur trafiqué ajouté sans autorisation.'),
      def('wp_damage_mod', 'Anti modification de dégâts', 'Dégâts d’arme au-delà du plausible.'),
      def('wp_ammo_cheats', 'Anti triche de munitions', 'Ajout de munitions illégitime.'),
      def('wp_infinite_ammo', 'Anti munitions infinies', 'Munitions qui ne descendent jamais.'),
      def('wp_no_reload', 'Anti tir sans recharge', 'Tire sans jamais recharger.'),
      def('wp_explosive_bullets', 'Anti balles explosives', 'Balles explosives illégitimes.'),
      def('wp_super_punch', 'Anti super-coup', 'Coups de poing aux dégâts/portée impossibles.'),
      def('wp_hitbox', 'Anti modification de hitbox', 'Agrandissement des zones de touche.'),
      def('wp_blacklist', 'Liste d’armes interdites', 'Refuse à la source l’équipement d’armes bannies.'),
      def('wp_projectile', 'Comportement de projectile', 'Trajectoire ou cadence de projectile impossible.', 'watch'),
    ],
  },
  {
    id: 'vehicules_detail',
    label: 'Véhicules — contrôle détaillé',
    items: [
      def('vh_throwing', 'Anti projection de véhicule', 'Empêche de projeter des véhicules sur les joueurs (grief).'),
      def('vh_deletion', 'Anti suppression de véhicule', 'Bloque la suppression forcée des véhicules d’autrui.'),
      def('vh_hijack', 'Anti vol à distance', 'Vol/prise de contrôle de véhicule impossible.'),
      def('vh_speed_mod', 'Anti vitesse modifiée', 'Vitesses de véhicule impossibles.', 'watch'),
      def('vh_handling', 'Anti handling modifié', 'Modification du comportement (handling) du véhicule.', 'watch'),
      def('vh_plate', 'Anti changement de plaque', 'Changement de plaque à la volée pour brouiller les pistes.', 'watch'),
      def('vh_isolated', 'Anti spawn isolé', 'Véhicule apparu loin de tout joueur (spawn caché).'),
      def('vh_ai_spawn', 'Anti spawn par script', 'Véhicules apparus par des scripts non prévus.'),
      def('vh_blacklist', 'Liste de véhicules interdits', 'Refuse l’apparition de véhicules bannis.'),
      def('vh_whitelist', 'Liste blanche de véhicules', 'N’autorise que les véhicules d’une liste.', 'watch', false),
      def('vh_limiter', 'Limiteur de spawn véhicules', 'Plafonne le nombre de véhicules par joueur.'),
    ],
  },
  {
    id: 'pnj_objets',
    label: 'PNJ & objets',
    items: [
      def('sp_ped_ai', 'Anti spawn de PNJ par script', 'PNJ apparus par des scripts non prévus.'),
      def('sp_ped_blacklist', 'Blacklist de PNJ', 'Refuse la création de modèles de PNJ interdits.'),
      def('sp_ped_limiter', 'Limiteur de spawn PNJ', 'Plafonne le nombre de PNJ par joueur.'),
      def('sp_obj_ai', 'Anti spawn d’objets par script', 'Objets apparus par des scripts non prévus.'),
      def('sp_obj_blacklist', 'Blacklist d’objets', 'Refuse la création de props interdits.'),
      def('sp_obj_limiter', 'Limiteur de spawn objets', 'Plafonne le nombre d’objets par joueur.'),
      def('sp_pickup', 'Anti pickup illégitime', 'Objets ramassables (armes/argent au sol) illégitimes.'),
    ],
  },
  {
    id: 'explosions_particules',
    label: 'Explosions & particules',
    items: [
      def('sp_expl_ai', 'Anti explosion anormale', 'Détection intelligente d’explosions anormales.'),
      def('sp_expl_blacklist', 'Types d’explosion interdits', 'Bloque à la source certains types (obus de char, canon orbital…).'),
      def('sp_expl_invisible', 'Anti explosion invisible', 'Explosions invisibles (grief discret).'),
      def('sp_expl_inaudible', 'Anti explosion silencieuse', 'Explosions sans son (grief discret).'),
      def('sp_expl_limiter', 'Limiteur d’explosions', 'Plafonne le nombre d’explosions par joueur.'),
      def('sp_particle_ai', 'Anti particules abusives', 'Effets de particules anormaux.', 'watch'),
      def('sp_particle_attached', 'Anti particules attachées', 'Particules collées aux joueurs pour gêner (écran saturé).', 'watch'),
    ],
  },
  {
    id: 'evenements',
    label: 'Événements & triggers',
    items: [
      def('nt_server_event', 'Protection des events serveur', 'Rejette les events réseau serveur hors du contrat déclaré.'),
      def('nt_client_event', 'Protection des events client', 'Rejette les events client injectés qui n’existent pas normalement.'),
      def('nt_export', 'Protection des exports', 'Bloque les exports de ressources non accessibles au client.'),
      def('nt_trigger_blacklist', 'Liste d’events interdits', 'Toute tentative de déclencher un event banni est bloquée.'),
      def('nt_trigger_ratelimit', 'Limiteur de fréquence d’events', 'Limite la répétition d’un même event (anti-flood).'),
      def('nt_xss', 'Anti-injection XSS', 'Bloque l’injection de code via les champs de connexion/chat.'),
    ],
  },
  {
    id: 'connexion_detail',
    label: 'Connexion — contrôle détaillé',
    items: [
      def('conn_vpn', 'Anti VPN / proxy', 'Ajoute de la méfiance (ou refuse) les connexions via VPN/proxy.', 'watch', false),
      def('conn_duplication', 'Anti double-connexion', 'Refuse deux connexions simultanées du même identifiant.'),
      def('conn_discord_required', 'Discord lié obligatoire', 'Exige un compte Discord lié pour se connecter.', 'watch', false),
      def('conn_alphanumeric', 'Pseudo alphanumérique', 'Refuse les pseudos à caractères d’exploit ou invisibles.', 'watch'),
      def('conn_max_threat', 'Refus au score de menace', 'Refuse la connexion au-delà d’un score de menace à l’entrée.'),
    ],
  },
  {
    id: 'divers_anticheat',
    label: 'Anti-triche — divers',
    items: [
      def('rs_resource_injection', 'Anti injection de ressource', 'Détecte l’injection d’une ressource/script non déclaré.'),
      def('rs_dev_tools', 'Anti outils de développement', 'Détecte l’usage d’outils de debug en jeu.', 'watch'),
      def('rs_spoofer', 'Anti spoofer d’identifiants', 'Bloque l’usurpation d’identifiants (faux Steam/licence).'),
      def('rs_voice', 'Anti abus vocal', 'Voix à distance infinie, saturation.', 'watch'),
      def('rs_synaps', 'Anti exécuteur connu', 'Bloque des exécuteurs de triche connus et variantes.'),
      def('rs_cheat_traces', 'Traces de triche connues', 'Traque les traces laissées par les menus de triche connus.', 'watch'),
      def('rs_sound', 'Anti abus sonore', 'Sons forcés / saturation audio.', 'watch'),
      def('rs_forced_ragdoll', 'Anti ragdoll forcé', 'Empêche de faire tomber les joueurs de force.'),
      def('rs_vehicle_bomb', 'Anti bombardement véhicule', 'Bombardement depuis un véhicule (grief de masse).'),
      def('rs_magneto', 'Anti magneto', 'Exploit d’attraction/collage d’objets ou véhicules.', 'watch', false),
    ],
  },
  // ---------------------------------------------------------------------------
  // Contre-mesures ciblées de menus de triche connus (noclip menus, bypass AC,
  // manipulation d'autrui, construction, silent-kill…). Chaque entrée route vers
  // un détecteur serveur-autoritatif via son préfixe de catégorie.
  // ---------------------------------------------------------------------------
  {
    id: 'exploits_joueur',
    label: 'Exploits joueur (menus)',
    items: [
      def('pl_fake_handcuff', 'Anti fausses menottes', 'État « menotté » posé côté client sans action serveur légitime.'),
      def('pl_revive_exploit', 'Anti revive-exploit', 'Réanimation/god-mode via un event de revive détourné.'),
      def('rc_maxstats', 'Anti max skills / stats', 'Compétences ou stats poussées au-delà de la vérité serveur.'),
      def('mv_parkour', 'Anti parkour / déplacement exploit', 'Déplacements scriptés impossibles (parkour, murs).'),
      def('mv_sliderun', 'Anti slide-run', 'Glissade continue à vitesse anormale.', 'watch'),
    ],
  },
  {
    id: 'manip_autrui',
    label: 'Manipulation d’autres joueurs',
    items: [
      def('nt_player_grab', 'Anti bring / launch / bug player', 'Tente de déplacer, éjecter ou bloquer un autre joueur via events.'),
      def('nt_unjail', 'Anti unjail-exploit', 'Sortie de prison via un event serveur détourné.'),
      def('nt_radio_join', 'Anti join-radio non autorisé', 'Rejoint une fréquence radio privée sans y avoir droit.'),
      def('nt_dynamic_triggers', 'Anti triggers dynamiques / inject panel', 'Balayage/injection massifs d’events serveur (menus « dynamic triggers »).'),
    ],
  },
  {
    id: 'construction_entites',
    label: 'Construction & entités',
    items: [
      def('sp_construct', 'Anti construction (murs/rampes/boucliers)', 'Création massive d’objets pour murs, rampes, tours, ailes.'),
      def('sp_physgun', 'Anti physics-gun', 'Saisie/déplacement d’entités par prise d’ownership réseau.'),
      def('vh_attach', 'Anti attach / carry de véhicules', 'Attache/empile des véhicules pour grief ou transport.'),
      def('vh_spoof', 'Anti spoof de véhicule', 'Usurpation de modèle/plaque de véhicule.'),
    ],
  },
  {
    id: 'combat_deloyal',
    label: 'Combat déloyal',
    items: [
      def('wp_silentkill', 'Anti silent / stealth kill', 'Kill sans trace d’origine (hors logs) — provenance de dégâts invalide.'),
      def('av_triggerbot', 'Anti triggerbot', 'Tir déclenché automatiquement à la cible (réaction/pattern inhumains).', 'watch'),
      def('av_no_spread', 'Anti no-spread / no-recoil forcé', 'Dispersion/recul supprimés côté client.', 'watch'),
    ],
  },
  {
    id: 'reseau_desync',
    label: 'Réseau — désync forcée',
    items: [
      def('nw_fakelag', 'Anti fake-lag', 'Latence simulée pour esquiver la sanction (pas de rapport).'),
      def('nw_forcedesync', 'Anti force-desync', 'Désynchronisation volontaire de l’état joueur.'),
    ],
  },
  {
    id: 'anti_contournement',
    label: 'Anti-contournement de l’anticheat',
    items: [
      def('rs_ac_bypass', 'Anti bypass d’anticheat', 'Tentatives de neutraliser un anticheat (Felox/Quantum/…) : injection non déclarée détectée.'),
      def('rs_screenshot_tamper', 'Anti blocage de capture', 'Blocage du système de screenshot serveur (perte de preuve).'),
      def('rs_scan_evasion', 'Anti évasion de scan', 'Ressource qui masque sa présence au scan (allowlist stricte).'),
    ],
  },
];

/** Index plat id → définition, pour valider les écritures. */
export const PROTECTION_BY_ID: Map<string, ProtectionDef> = new Map(
  PROTECTION_CATALOG.flatMap((c) => c.items.map((i) => [i.id, i] as const)),
);

export const PROTECTION_COUNT = PROTECTION_BY_ID.size;
