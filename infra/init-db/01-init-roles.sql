-- Database Role Separation Initialization per 11-DATA-MODEL.md
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE USER flyway_user WITH PASSWORD 'flyway_secret_locally';
CREATE USER ospysin_app WITH PASSWORD 'app_secret_locally';

GRANT CONNECT, CREATE ON DATABASE ospysin TO flyway_user;
GRANT CONNECT ON DATABASE ospysin TO ospysin_app;
GRANT USAGE, CREATE ON SCHEMA public TO flyway_user;
ALTER SCHEMA public OWNER TO flyway_user;
GRANT USAGE ON SCHEMA public TO ospysin_app;
