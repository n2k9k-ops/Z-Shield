-- Rôles créés au premier démarrage du conteneur Postgres de développement.
-- En production, ces rôles sont créés par l'équipe infrastructure, avec des
-- mots de passe issus du gestionnaire de secrets.
CREATE ROLE zshield_app LOGIN PASSWORD 'devpassword' NOBYPASSRLS;
GRANT CONNECT ON DATABASE zshield TO zshield_app;
