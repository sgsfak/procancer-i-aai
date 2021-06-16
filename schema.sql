CREATE EXTENSION "uuid-ossp";
CREATE EXTENSION pgcrypto;

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pwd_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    description TEXT,
    active boolean DEFAULT TRUE
);

INSERT INTO clients(pwd_hash, name, redirect_uri) VALUES(crypt('password', gen_salt('bf', 10)), 'MOLGENIS', 'https://127.0.0.1/');




GRANT ALL ON ALL TABLES in schema "public" TO pcai_idp;