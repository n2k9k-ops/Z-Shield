#!/bin/bash
# Crée le rôle applicatif au premier démarrage de PostgreSQL (production).
# Le rôle applicatif est NOBYPASSRLS : il ne peut jamais contourner l'isolation
# par organisation. Les migrations (DDL) tournent avec le superutilisateur.
# Le mot de passe vient de la variable d'environnement APP_DB_PASSWORD.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'zshield_app') THEN
            CREATE ROLE zshield_app LOGIN PASSWORD '${APP_DB_PASSWORD}' NOBYPASSRLS;
        END IF;
    END
    \$\$;
    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO zshield_app;
EOSQL
