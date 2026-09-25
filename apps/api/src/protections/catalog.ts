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
];

/** Index plat id → définition, pour valider les écritures. */
export const PROTECTION_BY_ID: Map<string, ProtectionDef> = new Map(
  PROTECTION_CATALOG.flatMap((c) => c.items.map((i) => [i.id, i] as const)),
);

export const PROTECTION_COUNT = PROTECTION_BY_ID.size;
