-- =============================================================================
-- Jeu de données de développement.
--
-- À NE JAMAIS exécuter en production : les mots de passe sont connus et les
-- secrets d'agent sont factices.
--
-- Deux organisations sont créées volontairement. Les tests d'isolation de
-- l'étape 2 en ont besoin : vérifier qu'un utilisateur d'Acme ne voit pas les
-- données de Globex demande que Globex existe et contienne des données.
-- =============================================================================

BEGIN;

INSERT INTO organizations (id, name, slug) VALUES
    ('org_01hacme000000000000000000a', 'Acme RP',   'acme-rp'),
    ('org_01hglobex00000000000000000', 'Globex RP', 'globex-rp')
ON CONFLICT (id) DO NOTHING;

-- Mot de passe des trois comptes : « development-password-1 »
-- (haché avec scrypt ; régénérer avec hashPassword() plutôt que copier ceci
-- dans un autre environnement).
INSERT INTO users (id, email, password_hash, display_name, email_verified_at) VALUES
    ('usr_01howner000000000000000000', 'owner@acme.test',
     'scrypt$32768$8$1$ZGV2LXNhbHQtYWNtZS0wMDA=$aW52YWxpZC1yZXBsYWNlLW1lLWluLWRldg==',
     'Alice Owner', now()),
    ('usr_01hstaff000000000000000000', 'staff@acme.test',
     'scrypt$32768$8$1$ZGV2LXNhbHQtYWNtZS0wMDE=$aW52YWxpZC1yZXBsYWNlLW1lLWluLWRldg==',
     'Bob Staff', now()),
    ('usr_01hother000000000000000000', 'owner@globex.test',
     'scrypt$32768$8$1$ZGV2LXNhbHQtZ2xvYmV4LTA=$aW52YWxpZC1yZXBsYWNlLW1lLWluLWRldg==',
     'Carol Rival', now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO memberships (id, organization_id, user_id, role, accepted_at) VALUES
    ('mem_acme_owner',   'org_01hacme000000000000000000a', 'usr_01howner000000000000000000', 'OWNER', now()),
    ('mem_acme_staff',   'org_01hacme000000000000000000a', 'usr_01hstaff000000000000000000', 'STAFF', now()),
    ('mem_globex_owner', 'org_01hglobex00000000000000000', 'usr_01hother000000000000000000', 'OWNER', now())
ON CONFLICT (id) DO NOTHING;

INSERT INTO subscriptions (id, organization_id, plan_code, state) VALUES
    ('sub_acme',   'org_01hacme000000000000000000a', 'pro',  'ACTIVE'),
    ('sub_globex', 'org_01hglobex00000000000000000', 'free', 'TRIALING')
ON CONFLICT (id) DO NOTHING;

INSERT INTO servers (id, organization_id, name, environment, created_by) VALUES
    ('srv_01hacmemain0000000000000aa', 'org_01hacme000000000000000000a',
     'Acme Main',    'production',  'usr_01howner000000000000000000'),
    ('srv_01hacmetest0000000000000ab', 'org_01hacme000000000000000000a',
     'Acme Staging', 'staging',     'usr_01howner000000000000000000'),
    ('srv_01hglobexmain000000000000c', 'org_01hglobex00000000000000000',
     'Globex Main',  'production',  'usr_01hother000000000000000000')
ON CONFLICT (id) DO NOTHING;

-- Les credentials d'agent ne sont PAS créées ici : leur secret doit être
-- chiffré avec ZSHIELD_CREDENTIAL_KEY, ce que le SQL ne peut pas faire.
-- Utiliser POST /api/servers/:id/credentials, ou le script de développement.

COMMIT;

-- Compte admin plateforme (vendeur) pour le dev local uniquement.
UPDATE users SET is_platform_admin = true WHERE email = 'owner@acme.test';
