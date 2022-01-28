CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS clients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pwd_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    description TEXT,
    active boolean DEFAULT TRUE
);

-- INSERT INTO clients(pwd_hash, name, redirect_uri) VALUES(crypt('password', gen_salt('bf', 10)), 'MOLGENIS', 'https://127.0.0.1/');

CREATE TABLE IF NOT EXISTS organizations
    (id INT PRIMARY KEY
    , full_name TEXT NOT NULL
    , name TEXT NOT NULL
    , country TEXT NOT NULL
    , elixir_aai BOOLEAN DEFAULT FALSE
    , modeller BOOLEAN DEFAULT FALSE
    , provider BOOLEAN DEFAULT FALSE
    , technical BOOLEAN DEFAULT FALSE
);
COMMENT ON TABLE organizations IS 'The members of the ProCAncer-I consortium';
COMMENT ON COLUMN organizations.id IS 'partner number from the DoA';
COMMENT ON COLUMN organizations.full_name IS 'partner''s full name';
COMMENT ON COLUMN organizations.name IS 'partner''s short name';
COMMENT ON COLUMN organizations.country IS 'partner''s home country';
COMMENT ON COLUMN organizations.modeller IS 'True if partner participates on modelling tasks';
COMMENT ON COLUMN organizations.provider IS 'True if partner provides data';
COMMENT ON COLUMN organizations.technical IS 'True if partner provides technical expertise and works on platform implementation';



INSERT INTO organizations(id, full_name, name, country, elixir_aai, modeller)
VALUES
  ( 1, 'IDRYMA TECHNOLOGIAS KAI EREVNAS', 'FORTH', 'Greece', TRUE, TRUE)
, ( 2, 'FUNDACAO D. ANNA SOMMER CHAMPALIMAUD E DR. CARLOS MONTEZ CHAMPALIMAUD', 'FCHAMPALIMAUD', 'Portugal', FALSE, TRUE)
, ( 3, 'STICHTING KATHOLIEKE UNIVERSITEIT', 'RadboudUMC', 'Netherlands', TRUE, TRUE)
, ( 4, 'FUNDACION PARA LA INVESTIGACION DEL HOSPITAL UNIVERSITARIO LA FE DE LA COMUNIDAD VALENCIANA', 'HULAFE', 'Spain', FALSE, TRUE)
, ( 5, 'UNIVERSITA DI PISA', 'UNIPI', 'Italy', TRUE, FALSE)
, ( 6, 'INSTITUT JEAN PAOLI & IRENE CALMETTES', 'IPC', 'France', FALSE, FALSE)
, ( 7, 'HACETTEPE UNIVERSITESI', 'HACETTEPE', 'Turkey', TRUE, FALSE)
, ( 8, 'FUNDACIO INSTITUT D''INVESTIGACIO BIOMEDICA DE GIRONA DOCTOR JOSEP TRUETA', 'IDIBGI', 'Spain', FALSE, FALSE)
, ( 9, 'JOAO CARLOS COSTA - DIAGNOSTICO PORIMAGEN, S.A.', 'JCC', 'Portugal', FALSE, FALSE)
, (10, 'NACIONALINIS VEZIO INSTITUTAS', 'NCI', 'Lithuania', FALSE, FALSE)
, (11, 'GENIKO ANTIKARKINIKO OGKOLOGIKO NOSOKOMEIO ATHINON O AGIOS SAVVAS', 'GAONA St Savvas', 'Greece', FALSE, FALSE)
, (12, 'THE ROYAL MARSDEN NATIONAL HEALTH SERVICE TRUST', 'RMH', 'UK', FALSE, FALSE)
, (13, 'QS INSTITUTO DE INVESTIGACION E INNOVACION SL', 'QUIRONSALUD', 'Spain', FALSE, FALSE)
, (14, 'FONDAZIONE DEL PIEMONTE PER L''ONCOLOGIA', 'FPO', 'Italy', FALSE, TRUE)
, (15, 'CONSIGLIO NAZIONALE DELLE RICERCHE', 'CNR', 'Italy', TRUE, TRUE)
, (16, 'THE GENERAL HOSPITAL CORPORATION', 'QTIM', 'USA', FALSE, TRUE)
, (17, 'BIOTRONICS 3D LIMITED', 'B3D', 'UK', FALSE, FALSE)
, (18, 'ADVANTIS MEDICAL IMAGING MONOPROSOPI IDIOTIKI KEFALEOUCHIKI ETAIRIA', 'ADVANTIS', 'Greece', FALSE, FALSE)
, (19, 'QUIBIM SOCIEDAD LIMITADA', 'QUIBIM', 'Spain', FALSE, FALSE)
, (20, 'UNIVERSITAT WIEN', 'UNIVIE', 'Austria', TRUE, FALSE)

ON CONFLICT (id) DO NOTHING;


CREATE TABLE IF NOT EXISTS users
    ( user_id TEXT PRIMARY KEY
    , elixir_id TEXT NOT NULL UNIQUE
    , user_verified BOOLEAN NOT NULL DEFAULT FALSE
    , elixir_id_token JSONB NOT NULL
    , is_admin BOOLEAN NOT NULL DEFAULT FALSE
    , registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP

    -- the following are already reported by ELIXIR AAI
    -- See https://docs.google.com/document/d/1hD0lsxotLvPaML_CSydVX6rJ-zogAH2nRVl4ax4gW1o/edit
    , preferred_username TEXT GENERATED ALWAYS AS (elixir_id_token->>'preferred_username') STORED
    , name TEXT GENERATED ALWAYS AS (elixir_id_token->>'name') STORED
    , given_name TEXT GENERATED ALWAYS AS (elixir_id_token->>'given_name') STORED
    , family_name TEXT GENERATED ALWAYS AS (elixir_id_token->>'family_name') STORED
    , picture TEXT GENERATED ALWAYS AS (elixir_id_token->>'picture') STORED
    , website TEXT GENERATED ALWAYS AS (elixir_id_token->>'website') STORED
    , gender TEXT GENERATED ALWAYS AS (elixir_id_token->>'gender') STORED
    , zoneinfo TEXT GENERATED ALWAYS AS (elixir_id_token->>'zoneinfo') STORED
    , locale TEXT GENERATED ALWAYS AS (elixir_id_token->>'locale') STORED
    , updated_at TEXT GENERATED ALWAYS AS (elixir_id_token->>'updated_at') STORED
    , birthdate TEXT GENERATED ALWAYS AS (elixir_id_token->>'birthdate') STORED
    , email TEXT GENERATED ALWAYS AS (elixir_id_token->>'email') STORED
    , email_verified BOOLEAN GENERATED ALWAYS AS ((elixir_id_token->>'email_verified')::BOOLEAN) STORED
    , phone_number TEXT GENERATED ALWAYS AS (elixir_id_token->>'phone_number') STORED
    , phone_number_verified BOOLEAN GENERATED ALWAYS AS ((elixir_id_token->>'phone_number_verified')::BOOLEAN) STORED
    , address TEXT GENERATED ALWAYS AS (elixir_id_token->>'address') STORED

    , CONSTRAINT valid_elixir_id CHECK (elixir_id = elixir_id_token->>'sub')
);

CREATE INDEX IF NOT EXISTS users_elixir_id_token_gin ON users USING GIN (elixir_id_token jsonb_ops);

COMMENT ON COLUMN users.user_id IS 'The unique user''s ID in the ProstateNet platform';
COMMENT ON COLUMN users.elixir_id IS 'The unique user''s ID in ELIXIR, submitted in the `sub` claim';
COMMENT ON COLUMN users.elixir_id_token IS 'The JWT "id token" retrieved from ELIXIR federated AAI';
COMMENT ON COLUMN users.user_verified IS 'True if the user has been verified and authorized to be a user of the platform';

GRANT ALL ON ALL TABLES in schema "public" TO pcai_idp;
