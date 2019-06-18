

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

DROP DATABASE IF EXISTS config;

CREATE DATABASE config WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8';


\connect config

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;


CREATE OR REPLACE PROCEDURAL LANGUAGE plperl;



CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;



COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';



CREATE TYPE public.domaintypes AS ENUM (
    'routed',
    'virtual'
);



CREATE TYPE public.listtypes AS ENUM (
    'asn',
    'grey',
    'black',
    'white',
    'country',
    'norevdns'
);



CREATE TYPE public.mailtypes AS ENUM (
    'spam',
    'malware',
    'normal'
);



CREATE TYPE public.objecttypes AS ENUM (
    'asn',
    'domain',
    'address',
    'netblock'
);



CREATE FUNCTION public.log_to_db(character varying, character varying, character varying, character varying, character varying, character varying, integer) RETURNS integer
    LANGUAGE plperl
    AS $_$

my $eximid   = shift;
my $type     = shift;
my $sender   = shift;
my $mailfrom = shift;
my $mailto   = shift;
my $info     = shift;
my $size     = shift;

$mailfrom =~ s/\'/\'\'/g;
$mailto   =~ s/\'/\'\'/g;
$info     =~ s/\'/\'\'/g;

my @recipients = split /,/, $mailto;
my ( $froma, $fromd ) = split /\@/, $mailfrom;

foreach my $recip (@recipients) {
    $recip =~ s/\s//g;
    my ( $radd, $rdom ) = split /\@/, $recip;
    my $query = 'INSERT INTO maillog ';
    $query .= '(eximid, sender_address, type, from_domain, to_domain, mail_from, mail_to, info, size) ';
    $query .= 'VALUES ';
    $query .= "('$eximid', '$sender', '$type', '$fromd', '$rdom', '$mailfrom', '$recip', '$info', $size)";
    my $rv = spi_exec_query($query);
}

return 0;

$_$;


SET default_tablespace = '';

SET default_with_oids = false;


CREATE TABLE public.domains (
    id integer NOT NULL,
    owner bigint NOT NULL,
    domainname character varying,
    domaintype public.domaintypes DEFAULT 'routed'::public.domaintypes,
    greylist boolean DEFAULT true,
    antivirus boolean DEFAULT true,
    antispam boolean DEFAULT true,
    spamscore integer DEFAULT 50,
    mailroute character varying,
    strictaddress boolean DEFAULT false NOT NULL,
    quarantine boolean DEFAULT false,
    quarantine_address character varying DEFAULT ''::character varying,
    delivery_username character varying,
    delivery_password character varying,
    reject_message character varying,
    enabled boolean DEFAULT true,
    date_added timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT quarantine_address_present CHECK ((((quarantine IS TRUE) AND ((quarantine_address)::text <> ''::text)) OR (quarantine IS FALSE)))
);



CREATE TABLE public.synonyms (
    id integer NOT NULL,
    domain_id integer,
    name text,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE VIEW public.all_domains AS
 SELECT domains.id,
    domains.owner,
    domains.domainname,
    domains.domaintype,
    domains.greylist,
    domains.antivirus,
    domains.antispam,
    domains.spamscore,
    domains.mailroute,
    domains.strictaddress,
    domains.quarantine,
    domains.quarantine_address,
    domains.delivery_username,
    domains.delivery_password,
    domains.reject_message,
    domains.enabled
   FROM public.domains
UNION ALL
 SELECT d.id,
    d.owner,
    s.name AS domainname,
    d.domaintype,
    d.greylist,
    d.antivirus,
    d.antispam,
    d.spamscore,
    d.mailroute,
    d.strictaddress,
    d.quarantine,
    d.quarantine_address,
    d.delivery_username,
    d.delivery_password,
    d.reject_message,
    d.enabled
   FROM public.domains d,
    public.synonyms s
  WHERE (s.domain_id = d.id);



CREATE TABLE public.invalid_localparts (
    id integer NOT NULL,
    domain_id integer,
    localpart text,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE VIEW public.all_invalid_localparts AS
 SELECT domains.domainname,
    invalid_localparts.localpart
   FROM public.domains,
    public.invalid_localparts
  WHERE (domains.id = invalid_localparts.domain_id)
UNION ALL
 SELECT synonyms.name AS domainname,
    invalid_localparts.localpart
   FROM public.synonyms,
    public.invalid_localparts
  WHERE (synonyms.domain_id = invalid_localparts.domain_id);



CREATE TABLE public.valid_localparts (
    id integer NOT NULL,
    domain_id integer NOT NULL,
    localpart character varying NOT NULL,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE VIEW public.all_valid_localparts AS
 SELECT domains.domainname,
    valid_localparts.localpart
   FROM public.domains,
    public.valid_localparts
  WHERE (domains.id = valid_localparts.domain_id)
UNION ALL
 SELECT synonyms.name AS domainname,
    valid_localparts.localpart
   FROM public.synonyms,
    public.valid_localparts
  WHERE (synonyms.domain_id = valid_localparts.domain_id);



CREATE TABLE public.exceptions (
    id integer NOT NULL,
    listtype public.listtypes NOT NULL,
    domain_id integer,
    asn character varying,
    netblock cidr,
    sender_domain character varying,
    sender_address character varying,
    country_code character varying(2) DEFAULT NULL::character varying,
    comment character varying,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE VIEW public.asn_exception AS
 SELECT all_domains.domainname,
    exceptions.asn
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'asn'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.asn IS NOT NULL));



CREATE TABLE public.banned_wildcards (
    id integer NOT NULL,
    regex text,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.banned_wildcards_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.banned_wildcards_id_seq OWNED BY public.banned_wildcards.id;



CREATE VIEW public.bl_exception_address AS
 SELECT all_domains.domainname,
    exceptions.sender_address
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'black'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_address IS NOT NULL));



CREATE VIEW public.bl_exception_domain AS
 SELECT all_domains.domainname,
    exceptions.sender_domain
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'black'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_domain IS NOT NULL));



CREATE VIEW public.bl_exception_netblock AS
 SELECT all_domains.domainname,
    exceptions.netblock
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'black'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.netblock IS NOT NULL));



CREATE VIEW public.cc_exception AS
 SELECT all_domains.domainname,
    exceptions.country_code
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'country'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.country_code IS NOT NULL));



CREATE SEQUENCE public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.domains_id_seq OWNED BY public.domains.id;



CREATE SEQUENCE public.exceptions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.exceptions_id_seq OWNED BY public.exceptions.id;



CREATE VIEW public.gl_exception_address AS
 SELECT all_domains.domainname,
    exceptions.sender_address
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'grey'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_address IS NOT NULL));



CREATE VIEW public.gl_exception_domain AS
 SELECT all_domains.domainname,
    exceptions.sender_domain
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'grey'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_domain IS NOT NULL));



CREATE VIEW public.gl_exception_netblock AS
 SELECT all_domains.domainname,
    exceptions.netblock
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'grey'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.netblock IS NOT NULL));



CREATE TABLE public.global_accepts (
    id integer NOT NULL,
    object public.objecttypes NOT NULL,
    asn character varying,
    netblock cidr,
    sender_domain character varying,
    sender_address character varying,
    comment character varying,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.global_accepts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.global_accepts_id_seq OWNED BY public.global_accepts.id;



CREATE TABLE public.global_bans (
    id integer NOT NULL,
    object public.objecttypes NOT NULL,
    asn character varying,
    netblock cidr,
    sender_domain character varying,
    sender_address character varying,
    comment character varying,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.global_bans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.global_bans_id_seq OWNED BY public.global_bans.id;



CREATE TABLE public.greylist (
    id integer NOT NULL,
    relay_ip inet,
    from_domain character varying,
    block_expires timestamp without time zone DEFAULT (now() + '00:10:00'::interval) NOT NULL,
    record_expires timestamp without time zone DEFAULT (now() + '7 days'::interval) NOT NULL,
    create_time timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.greylist_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.greylist_id_seq OWNED BY public.greylist.id;



CREATE SEQUENCE public.invalid_localparts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.invalid_localparts_id_seq OWNED BY public.invalid_localparts.id;



CREATE TABLE public.maillog (
    id integer NOT NULL,
    eximid character varying(16),
    type public.mailtypes,
    sender_address character varying,
    from_domain character varying,
    to_domain character varying,
    mail_from character varying,
    mail_to character varying,
    info character varying,
    size integer,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.maillog_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.maillog_id_seq OWNED BY public.maillog.id;



CREATE VIEW public.norevdns_exception AS
 SELECT all_domains.domainname,
    exceptions.netblock
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'norevdns'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.netblock IS NOT NULL));



CREATE TABLE public.owners (
    id integer NOT NULL,
    name character varying,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.owners_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.owners_id_seq OWNED BY public.owners.id;



CREATE TABLE public.reject_messages (
    id integer NOT NULL,
    domain_id integer,
    from_domain character varying NOT NULL,
    reject_message character varying NOT NULL,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.reject_messages_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.reject_messages_id_seq OWNED BY public.reject_messages.id;



CREATE SEQUENCE public.synonyms_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.synonyms_id_seq OWNED BY public.synonyms.id;



CREATE TABLE public.transient_bans (
    id integer NOT NULL,
    host character varying,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE SEQUENCE public.transient_bans_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.transient_bans_id_seq OWNED BY public.transient_bans.id;



CREATE SEQUENCE public.valid_localparts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.valid_localparts_id_seq OWNED BY public.valid_localparts.id;



CREATE TABLE public.virtuals (
    id integer NOT NULL,
    domain_id integer,
    localpart character varying NOT NULL,
    redirect_to character varying NOT NULL,
    date_added timestamp without time zone DEFAULT now() NOT NULL
);



CREATE VIEW public.virtual_redirects AS
 SELECT domains.id,
    domains.domainname,
    virtuals.localpart,
    virtuals.redirect_to
   FROM public.virtuals,
    public.domains
  WHERE (domains.id = virtuals.domain_id)
UNION ALL
 SELECT synonyms.domain_id AS id,
    synonyms.name AS domainname,
    virtuals.localpart,
    virtuals.redirect_to
   FROM public.synonyms,
    public.virtuals
  WHERE (synonyms.domain_id = virtuals.domain_id);



CREATE SEQUENCE public.virtuals_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;



ALTER SEQUENCE public.virtuals_id_seq OWNED BY public.virtuals.id;



CREATE VIEW public.wl_exception_address AS
 SELECT all_domains.domainname,
    exceptions.sender_address
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'white'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_address IS NOT NULL));



CREATE VIEW public.wl_exception_domain AS
 SELECT all_domains.domainname,
    exceptions.sender_domain
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'white'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.sender_domain IS NOT NULL));



CREATE VIEW public.wl_exception_netblock AS
 SELECT all_domains.domainname,
    exceptions.netblock
   FROM public.all_domains,
    public.exceptions
  WHERE ((exceptions.listtype = 'white'::public.listtypes) AND (all_domains.id = exceptions.domain_id) AND (exceptions.netblock IS NOT NULL));



ALTER TABLE ONLY public.banned_wildcards ALTER COLUMN id SET DEFAULT nextval('public.banned_wildcards_id_seq'::regclass);



ALTER TABLE ONLY public.domains ALTER COLUMN id SET DEFAULT nextval('public.domains_id_seq'::regclass);



ALTER TABLE ONLY public.exceptions ALTER COLUMN id SET DEFAULT nextval('public.exceptions_id_seq'::regclass);



ALTER TABLE ONLY public.global_accepts ALTER COLUMN id SET DEFAULT nextval('public.global_accepts_id_seq'::regclass);



ALTER TABLE ONLY public.global_bans ALTER COLUMN id SET DEFAULT nextval('public.global_bans_id_seq'::regclass);



ALTER TABLE ONLY public.greylist ALTER COLUMN id SET DEFAULT nextval('public.greylist_id_seq'::regclass);



ALTER TABLE ONLY public.invalid_localparts ALTER COLUMN id SET DEFAULT nextval('public.invalid_localparts_id_seq'::regclass);



ALTER TABLE ONLY public.maillog ALTER COLUMN id SET DEFAULT nextval('public.maillog_id_seq'::regclass);



ALTER TABLE ONLY public.owners ALTER COLUMN id SET DEFAULT nextval('public.owners_id_seq'::regclass);



ALTER TABLE ONLY public.reject_messages ALTER COLUMN id SET DEFAULT nextval('public.reject_messages_id_seq'::regclass);



ALTER TABLE ONLY public.synonyms ALTER COLUMN id SET DEFAULT nextval('public.synonyms_id_seq'::regclass);



ALTER TABLE ONLY public.transient_bans ALTER COLUMN id SET DEFAULT nextval('public.transient_bans_id_seq'::regclass);



ALTER TABLE ONLY public.valid_localparts ALTER COLUMN id SET DEFAULT nextval('public.valid_localparts_id_seq'::regclass);



ALTER TABLE ONLY public.virtuals ALTER COLUMN id SET DEFAULT nextval('public.virtuals_id_seq'::regclass);



ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.owners
    ADD CONSTRAINT owners_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.reject_messages
    ADD CONSTRAINT reject_messages_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.virtuals
    ADD CONSTRAINT virtuals_pkey PRIMARY KEY (id);



CREATE INDEX domains_domainname_idx ON public.domains USING btree (domainname);



CREATE INDEX idx_exceptions_listtype ON public.exceptions USING btree (listtype);



CREATE INDEX idx_exceptions_sender_address ON public.exceptions USING btree (sender_address);



CREATE INDEX idx_exceptions_sender_domain ON public.exceptions USING btree (sender_domain);



CREATE INDEX idx_global_accepts_asn ON public.global_accepts USING btree (asn);



CREATE INDEX idx_global_accepts_netblock ON public.global_accepts USING btree (netblock);



CREATE INDEX idx_global_accepts_object ON public.global_accepts USING btree (object);



CREATE INDEX idx_global_accepts_sender_address ON public.global_accepts USING btree (sender_address);



CREATE INDEX idx_global_accepts_sender_domain ON public.global_accepts USING btree (sender_domain);



CREATE INDEX idx_global_bans_asn ON public.global_bans USING btree (asn);



CREATE INDEX idx_global_bans_netblock ON public.global_bans USING btree (netblock);



CREATE INDEX idx_global_bans_object_type ON public.global_bans USING btree (object);



CREATE INDEX idx_global_bans_sender_address ON public.global_bans USING btree (sender_address);



CREATE INDEX idx_global_bans_sender_domain ON public.global_bans USING btree (sender_domain);



CREATE INDEX idx_greylist_block_expires ON public.greylist USING btree (block_expires);



CREATE INDEX idx_greylist_from_domain ON public.greylist USING btree (from_domain);



CREATE INDEX idx_greylist_record_expires ON public.greylist USING btree (record_expires);



CREATE INDEX idx_greylist_relayip ON public.greylist USING btree (relay_ip);



CREATE INDEX idx_invalid_localparts_domain_id ON public.invalid_localparts USING btree (domain_id);



CREATE INDEX idx_invalid_localparts_localpart ON public.invalid_localparts USING btree (localpart);



CREATE INDEX idx_synonyms_domain_id ON public.synonyms USING btree (domain_id);



CREATE INDEX idx_synonyns_name ON public.synonyms USING btree (name);



CREATE INDEX idx_transient_bans_host ON public.transient_bans USING btree (host);



CREATE INDEX idx_valid_localpart_domain_id ON public.valid_localparts USING btree (domain_id);



CREATE INDEX invalid_localparts_localpart_idx ON public.invalid_localparts USING btree (localpart);



CREATE INDEX valid_localparts_localpart_idx ON public.valid_localparts USING btree (localpart);



ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domain_owner_fkey FOREIGN KEY (owner) REFERENCES public.owners(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.synonyms
    ADD CONSTRAINT exceptions_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.invalid_localparts
    ADD CONSTRAINT invalid_localparts_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.reject_messages
    ADD CONSTRAINT reject_messages_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);



ALTER TABLE ONLY public.synonyms
    ADD CONSTRAINT synonyms_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.valid_localparts
    ADD CONSTRAINT valid_localparts_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;



ALTER TABLE ONLY public.virtuals
    ADD CONSTRAINT virtuals_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);



