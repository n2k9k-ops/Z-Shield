-- =============================================================================
-- 0003_non_tenant_read_paths.sql
--
-- Problème corrigé ici, révélé par les tests d'intégration.
--
-- RLS cadre l'accès sur `app.organization_id`. Or deux lectures du produit sont
-- légitimement ANTÉRIEURES à la connaissance de l'organisation :
--
--   1. « de quelles organisations cet utilisateur est-il membre ? », à la
--      création de session et au listing des organisations ;
--   2. « à quel serveur et quelle organisation appartient cette credential
--      d'agent ? », première étape de l'authentification d'un agent.
--
-- Sous FORCE ROW LEVEL SECURITY, ces deux requêtes renvoyaient ZÉRO LIGNE sans
-- lever d'erreur. Conséquences observées : les sessions naissaient sans
-- organisation, et surtout AUCUN agent n'aurait pu s'authentifier — un échec
-- silencieux, affichant un 401 côté opérateur sans rien dans les logs.
--
-- Deux réponses possibles étaient sur la table :
--
--   (a) donner BYPASSRLS au rôle applicatif, ou passer par une fonction
--       SECURITY DEFINER détenue par un rôle qui contourne RLS ;
--   (b) déclarer explicitement ces deux chemins comme des politiques nommées,
--       en lecture seule, activées par un drapeau de transaction.
--
-- (b) est retenu : le contournement reste inscrit dans le schéma, relisible et
-- limité à SELECT, au lieu d'être un privilège de rôle qui s'applique partout.
-- Un futur `SELECT * FROM alerts` sans contexte reste bloqué.
-- =============================================================================

BEGIN;

-- Utilisateur courant de la transaction, posé par withUser() côté application.
CREATE OR REPLACE FUNCTION app_current_user() RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT nullif(current_setting('app.user_id', true), '')
$$;

-- -----------------------------------------------------------------------------
-- 1. Un utilisateur lit SES propres adhésions.
--
-- En lecture seule : personne ne s'ajoute à une organisation par ce chemin.
-- La politique de tenant existante continue de régir tout le reste.
-- -----------------------------------------------------------------------------
CREATE POLICY membership_self_read ON memberships FOR SELECT
    USING (app_current_user() IS NOT NULL AND user_id = app_current_user());

-- -----------------------------------------------------------------------------
-- 2. Résolution d'une credential d'agent, avant tout contexte de tenant.
--
-- Conditions cumulatives, volontairement étroites :
--   - aucun contexte d'organisation n'est posé (donc ce n'est pas une requête
--     applicative ordinaire qui aurait oublié son cadrage) ;
--   - le drapeau app.agent_lookup vaut 'on', posé par withAgentLookup() ;
--   - SELECT uniquement.
--
-- L'écriture sur api_credentials (émission, rotation, révocation) passe par la
-- politique de tenant normale : à ce moment-là, l'organisation est connue.
-- -----------------------------------------------------------------------------
CREATE POLICY agent_credential_lookup ON api_credentials FOR SELECT
    USING (
        app_current_org() IS NULL
        AND current_setting('app.agent_lookup', true) = 'on'
    );

COMMIT;
