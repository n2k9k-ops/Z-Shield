-- =============================================================================
-- Test d'isolation multi-tenant.
--
-- À exécuter SOUS LE RÔLE APPLICATIF (zshield_app), jamais sous le propriétaire
-- du schéma ni un superutilisateur : ceux-là contournent RLS et le test
-- passerait en prouvant exactement rien.
--
--   psql "postgres://zshield_app:...@host/zshield" -v ON_ERROR_STOP=1 \
--        -f db/tests/isolation.sql
--
-- Prérequis : db/seed.dev.sql appliqué (deux organisations, Acme et Globex).
--
-- Chaque vérification lève une exception si elle échoue. Un test qui affiche
-- « faux » sans échouer finit par être ignoré dans un tableau de bord CI.
-- =============================================================================

\set ACME  'org_01hacme000000000000000000a'
\set GLOBEX 'org_01hglobex00000000000000000'

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Sans organisation posée, RLS doit tout masquer (échec fermé).
--
--    C'est le cas d'un bug applicatif qui oublie withTenant(). Le résultat
--    correct est « zéro ligne », pas « toutes les lignes ».
-- -----------------------------------------------------------------------------
DO $$
DECLARE visible integer;
BEGIN
    SELECT count(*) INTO visible FROM servers;
    IF visible <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 1 : % serveurs visibles sans app.organization_id posé', visible;
    END IF;
    RAISE NOTICE 'OK 1 : aucune ligne visible sans contexte de tenant';
END $$;

-- -----------------------------------------------------------------------------
-- 2. Avec Acme, on ne voit QUE Acme.
-- -----------------------------------------------------------------------------
SET LOCAL app.organization_id = :'ACME';

DO $$
DECLARE mine integer; foreign_rows integer;
BEGIN
    SELECT count(*) INTO mine FROM servers WHERE organization_id = current_setting('app.organization_id');
    SELECT count(*) INTO foreign_rows FROM servers WHERE organization_id <> current_setting('app.organization_id');

    IF mine <> 2 THEN
        RAISE EXCEPTION 'ÉCHEC 2a : % serveurs Acme visibles, 2 attendus', mine;
    END IF;
    IF foreign_rows <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 2b : % serveurs d''une autre organisation visibles', foreign_rows;
    END IF;
    RAISE NOTICE 'OK 2 : seuls les serveurs de l''organisation courante sont visibles';
END $$;

-- -----------------------------------------------------------------------------
-- 3. Un SELECT ciblant explicitement l'organisation voisine ne renvoie rien.
--
--    C'est la tentative d'IDOR la plus directe : connaître l'identifiant et le
--    demander. RLS doit la rendre stérile même si le code applicatif a laissé
--    passer le paramètre.
-- -----------------------------------------------------------------------------
DO $$
DECLARE leaked integer;
BEGIN
    SELECT count(*) INTO leaked FROM servers WHERE organization_id = 'org_01hglobex00000000000000000';
    IF leaked <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 3 : IDOR possible, % lignes de Globex lues depuis Acme', leaked;
    END IF;
    RAISE NOTICE 'OK 3 : un identifiant d''organisation fourni en entrée ne donne accès à rien';
END $$;

-- -----------------------------------------------------------------------------
-- 4. Écrire chez le voisin est refusé par WITH CHECK.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    BEGIN
        INSERT INTO servers (id, organization_id, name)
        VALUES ('srv_01hintrus00000000000000000', 'org_01hglobex00000000000000000', 'Intrusion');
        RAISE EXCEPTION 'ÉCHEC 4 : insertion acceptée dans une autre organisation';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'OK 4 : insertion dans une autre organisation refusée par RLS';
    END;
END $$;

-- -----------------------------------------------------------------------------
-- 5. Un UPDATE de masse ne touche pas les lignes du voisin.
--
--    Le cas dangereux n'est pas la requête malveillante, c'est le UPDATE sans
--    clause WHERE écrit à 2 h du matin pendant un incident.
-- -----------------------------------------------------------------------------
DO $$
DECLARE touched integer;
BEGIN
    UPDATE servers SET name = name;
    GET DIAGNOSTICS touched = ROW_COUNT;
    IF touched <> 2 THEN
        RAISE EXCEPTION 'ÉCHEC 5 : un UPDATE sans WHERE a touché % lignes, 2 attendues', touched;
    END IF;
    RAISE NOTICE 'OK 5 : un UPDATE sans clause WHERE reste borné à l''organisation courante';
END $$;

-- -----------------------------------------------------------------------------
-- 6. Les clés étrangères composites empêchent le rattachement croisé.
--
--    Deuxième couche, indépendante de RLS : même avec le bon contexte de
--    tenant, on ne peut pas créer une alerte sur le serveur d'un autre.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    BEGIN
        INSERT INTO alerts (id, organization_id, server_id, agent_alert_id, severity,
                            category, summary, occurred_at)
        VALUES ('al_01hcross000000000000000000', current_setting('app.organization_id'),
                'srv_01hglobexmain000000000000c', 'a1', 'HIGH', 'movement',
                'Alerte rattachée au serveur du voisin', now());
        RAISE EXCEPTION 'ÉCHEC 6 : alerte rattachée au serveur d''une autre organisation';
    EXCEPTION
        WHEN foreign_key_violation THEN
            RAISE NOTICE 'OK 6 : la FK composite interdit le rattachement inter-organisation';
    END;
END $$;

-- -----------------------------------------------------------------------------
-- 7. Régression : supprimer un serveur porteur d'un incident doit fonctionner.
--
--    ON DELETE SET NULL sur une FK composite dénulle par défaut TOUTES les
--    colonnes référençantes, dont organization_id qui est NOT NULL. Sans la
--    liste de colonnes explicite, cette suppression échoue — et l'interface
--    « supprimer le serveur » devient inutilisable dès le premier incident.
-- -----------------------------------------------------------------------------
DO $$
DECLARE orphan_org text;
BEGIN
    INSERT INTO incidents (id, organization_id, server_id, title)
    VALUES ('inc_01hregress0000000000000000', current_setting('app.organization_id'),
            'srv_01hacmetest0000000000000ab', 'Incident de régression');

    DELETE FROM servers WHERE id = 'srv_01hacmetest0000000000000ab';

    SELECT organization_id INTO orphan_org FROM incidents
     WHERE id = 'inc_01hregress0000000000000000';

    IF orphan_org IS NULL THEN
        RAISE EXCEPTION 'ÉCHEC 7 : organization_id a été dénullé, l''incident a quitté son tenant';
    END IF;
    RAISE NOTICE 'OK 7 : suppression du serveur possible, l''incident garde son organisation';
END $$;

-- -----------------------------------------------------------------------------
-- 8. Le journal d'audit est en ajout seul pour le rôle applicatif.
--
--    Un journal que l'application peut réécrire ne prouve rien sur ce que
--    l'application a fait.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    INSERT INTO audit_logs (organization_id, actor_kind, action)
    VALUES (current_setting('app.organization_id'), 'system', 'test.append');

    BEGIN
        UPDATE audit_logs SET action = 'test.tampered'
         WHERE organization_id = current_setting('app.organization_id');
        RAISE EXCEPTION 'ÉCHEC 8a : le rôle applicatif peut modifier le journal d''audit';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'OK 8a : modification du journal d''audit refusée';
    END;
END $$;

DO $$
BEGIN
    BEGIN
        DELETE FROM audit_logs WHERE organization_id = current_setting('app.organization_id');
        RAISE EXCEPTION 'ÉCHEC 8b : le rôle applicatif peut supprimer des entrées d''audit';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'OK 8b : suppression du journal d''audit refusée';
    END;
END $$;

-- -----------------------------------------------------------------------------
-- 9. Le rôle applicatif ne peut pas contourner RLS ni faire de DDL.
-- -----------------------------------------------------------------------------
DO $$
DECLARE can_bypass boolean;
BEGIN
    SELECT rolbypassrls INTO can_bypass FROM pg_roles WHERE rolname = current_user;
    IF can_bypass THEN
        RAISE EXCEPTION 'ÉCHEC 9a : le rôle % contourne RLS, tout ce test est sans valeur', current_user;
    END IF;

    BEGIN
        EXECUTE 'CREATE TABLE rls_escape (x int)';
        RAISE EXCEPTION 'ÉCHEC 9b : le rôle applicatif peut créer des tables';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'OK 9 : ni contournement de RLS ni DDL pour le rôle applicatif';
    END;
END $$;

-- -----------------------------------------------------------------------------
-- 10. Bascule d'organisation dans la même transaction : la vue change.
--
--     Vérifie que le filtre suit réellement la variable et n'a pas été mis en
--     cache par le planificateur au premier appel.
-- -----------------------------------------------------------------------------
SET LOCAL app.organization_id = :'GLOBEX';

DO $$
DECLARE visible integer; names text;
BEGIN
    SELECT count(*), string_agg(name, ',') INTO visible, names FROM servers;
    IF visible <> 1 OR names <> 'Globex Main' THEN
        RAISE EXCEPTION 'ÉCHEC 10 : après bascule, % ligne(s) visible(s) (%)', visible, names;
    END IF;
    RAISE NOTICE 'OK 10 : la bascule d''organisation change la vue dans la même transaction';
END $$;

-- -----------------------------------------------------------------------------
-- 11. Les deux contournements de la migration 0003 restent étroits.
--
--     `agent_credential_lookup` ouvre la lecture de api_credentials quand aucun
--     contexte de tenant n'est posé ET que app.agent_lookup vaut 'on'. Ces deux
--     conditions doivent être nécessaires, sinon le contournement devient une
--     porte ouverte sur les credentials de tous les clients.
-- -----------------------------------------------------------------------------
RESET app.organization_id;

DO $$
DECLARE visible integer;
BEGIN
    -- Sans le drapeau : rien, même sans contexte d'organisation.
    SELECT count(*) INTO visible FROM api_credentials;
    IF visible <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 11a : % credentials lisibles sans drapeau de recherche', visible;
    END IF;
    RAISE NOTICE 'OK 11a : les credentials restent masquées sans le drapeau de recherche';
END $$;

DO $$
BEGIN
    -- Avec le drapeau, la lecture est permise mais l'ÉCRITURE ne l'est pas :
    -- la politique est en SELECT uniquement.
    PERFORM set_config('app.agent_lookup', 'on', true);

    -- Subtilité : RLS ne LÈVE pas sur un UPDATE, elle retire simplement les
    -- lignes de la portée. La requête réussit en touchant zéro ligne. Attendre
    -- une exception ici serait un test qui passe pour la mauvaise raison.
    DECLARE touched integer;
    BEGIN
        UPDATE api_credentials SET revoke_reason = 'tentative';
        GET DIAGNOSTICS touched = ROW_COUNT;
        IF touched <> 0 THEN
            RAISE EXCEPTION 'ÉCHEC 11b : % credentials modifiées via le chemin de lecture', touched;
        END IF;
        RAISE NOTICE 'OK 11b : le chemin de recherche d''agent ne permet de modifier aucune ligne';
    END;
END $$;

DO $$
DECLARE visible integer;
BEGIN
    -- Et le drapeau n'ouvre QUE api_credentials, pas les données métier.
    SELECT count(*) INTO visible FROM alerts;
    IF visible <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 11c : le drapeau de recherche expose aussi les alertes (%)', visible;
    END IF;
    SELECT count(*) INTO visible FROM servers;
    IF visible <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 11c : le drapeau de recherche expose aussi les serveurs (%)', visible;
    END IF;
    RAISE NOTICE 'OK 11c : le drapeau de recherche n''ouvre que api_credentials';
END $$;

-- -----------------------------------------------------------------------------
-- 12. `membership_self_read` ne donne accès qu'à SES propres adhésions, en
--     lecture. Un utilisateur ne doit pas pouvoir s'inscrire lui-même dans une
--     organisation par ce chemin.
-- -----------------------------------------------------------------------------
DO $$
DECLARE mine integer; others integer;
BEGIN
    PERFORM set_config('app.agent_lookup', '', true);
    PERFORM set_config('app.user_id', 'usr_01howner000000000000000000', true);

    SELECT count(*) INTO mine FROM memberships
     WHERE user_id = 'usr_01howner000000000000000000';
    SELECT count(*) INTO others FROM memberships
     WHERE user_id <> 'usr_01howner000000000000000000';

    IF mine < 1 THEN
        RAISE EXCEPTION 'ÉCHEC 12a : un utilisateur ne voit pas ses propres adhésions';
    END IF;
    IF others <> 0 THEN
        RAISE EXCEPTION 'ÉCHEC 12b : % adhésions d''autres utilisateurs visibles', others;
    END IF;
    RAISE NOTICE 'OK 12a : un utilisateur voit ses adhésions et seulement les siennes';
END $$;

DO $$
BEGIN
    BEGIN
        INSERT INTO memberships (id, organization_id, user_id, role, accepted_at)
        VALUES ('mem_intrusion', 'org_01hglobex00000000000000000',
                'usr_01howner000000000000000000', 'OWNER', now());
        RAISE EXCEPTION 'ÉCHEC 12c : auto-inscription possible dans une organisation';
    EXCEPTION
        WHEN insufficient_privilege THEN
            RAISE NOTICE 'OK 12b : auto-inscription dans une organisation refusée';
    END;
END $$;

-- Aucune donnée de test ne doit survivre.
ROLLBACK;

\echo 'TOUS LES TESTS D''ISOLATION SONT PASSÉS'
