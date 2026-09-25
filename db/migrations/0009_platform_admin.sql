-- =============================================================================
-- 0009_platform_admin.sql — console vendeur (admin plateforme)
--
-- Le VENDEUR de Z-Shield a besoin de voir TOUS les clients et leurs serveurs
-- pour gérer les licences, alors que l'isolation par organisation (RLS) empêche
-- normalement de voir au-delà de son organisation.
--
-- On ajoute :
--   1. un drapeau `is_platform_admin` sur les utilisateurs ;
--   2. une politique PERMISSIVE SUPPLÉMENTAIRE sur `servers` et `licenses` qui
--      autorise l'accès quand le drapeau de connexion `app.platform_admin` vaut
--      'on'. Les politiques permissives se combinent en OR : l'isolation tenant
--      existante n'est PAS modifiée, on ajoute seulement un chemin admin.
--
-- Le drapeau `app.platform_admin` n'est posé que par withPlatformAdmin(), lui-même
-- appelé UNIQUEMENT après vérification que l'utilisateur est platform admin.
-- Il n'est jamais posé par une requête d'agent ni par le chemin tenant normal.
-- =============================================================================

BEGIN;

ALTER TABLE users
    ADD COLUMN is_platform_admin boolean NOT NULL DEFAULT false;

CREATE POLICY platform_admin_all ON servers
    USING (current_setting('app.platform_admin', true) = 'on')
    WITH CHECK (current_setting('app.platform_admin', true) = 'on');

CREATE POLICY platform_admin_all ON licenses
    USING (current_setting('app.platform_admin', true) = 'on')
    WITH CHECK (current_setting('app.platform_admin', true) = 'on');

COMMIT;
