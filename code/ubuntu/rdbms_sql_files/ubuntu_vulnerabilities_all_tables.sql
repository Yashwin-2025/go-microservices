--
-- PostgreSQL database dump
--

-- Dumped from database version 14.15
-- Dumped by pg_dump version 17.2

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: asset_to_vul_mapping; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.asset_to_vul_mapping (
    asset_id text,
    problem_name text,
    os_build text
);


ALTER TABLE public.asset_to_vul_mapping OWNER TO postgres;

--
-- Name: os_table; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.os_table (
    os_name text,
    os_model text,
    os_full_name text,
    os_version text,
    os_build text,
    os_patches text,
    os_install_date text,
    os_autoupdate text,
    os_vendor text
);


ALTER TABLE public.os_table OWNER TO postgres;

--
-- Name: vulnerabilities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.vulnerabilities (
    problem_name text,
    problem_id text,
    is_suppressed text,
    suppressed_till text,
    evidence text,
    is_confirmed text,
    product text,
    fix text,
    url text
);


ALTER TABLE public.vulnerabilities OWNER TO postgres;

--
-- Data for Name: asset_to_vul_mapping; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.asset_to_vul_mapping (asset_id, problem_name, os_build) FROM stdin;
39377	CVE-2023-37207	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46719	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-43527	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44962	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-27363	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44978	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40983	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46786	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29154	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43860	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-37202	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-38472	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-40780	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2022-23478	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46819	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-40550	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21624	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-5380	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-1551	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43860	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43863	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-20569	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46806	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46857	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-0286	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43859	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43869	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2023-42822	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15673	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21496	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46817	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29901	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45421	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43904	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43857	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-20926	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-37434	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42320	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44984	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46828	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42310	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-3661	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46761	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2022-3964	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46754	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44943	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3712	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4583	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47542	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-29550	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46825	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43871	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28693	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46772	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3656	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43899	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22942	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-0466	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42290	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46680	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2023-52889	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2025-0239	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2024-42244	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-40548	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46788	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44961	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46705	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25728	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-26924	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46776	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44999	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-38090	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-43846	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-51792	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-40779	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44993	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2019-17450	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44935	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29988	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42270	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-49462	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-12084	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43907	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46822	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46746	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46759	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42267	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44931	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43887	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26384	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-44296	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46673	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46805	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38500	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-0755	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4206	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-36329	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42278	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46831	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3653	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46777	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46707	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26387	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45404	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-24489	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4581	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42321	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-36322	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46753	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43841	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43889	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29945	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44977	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3573	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47598	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43837	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46868	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46791	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29985	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-27017	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46698	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45022	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-25802	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-42260	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8698	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42276	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-10029	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46728	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46724	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38496	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46732	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42269	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2505	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-12087	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6867	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46676	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46683	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26383	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44958	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47603	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23960	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47659	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47665	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-10465	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46729	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45017	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-33602	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42314	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46791	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-40546	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-46872	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46836	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-10769	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-35556	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-27803	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15669	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-43542	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42263	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29989	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22824	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42262	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-24329	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-42288	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46685	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46694	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46343	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2024-31578	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46807	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46753	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46708	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46824	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46864	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46729	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46880	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46673	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43817	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46852	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43909	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32213	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46783	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-1999	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2024-32230	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-42302	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0742	Red Hat Enterprise Linux Server release 7_9 (Maipo)
37575	CVE-2022-36021	22_04_3 LTS (Jammy Jellyfish)
39281	CVE-2024-43827	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6860	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-23271	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-47537	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44988	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44977	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29909	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-29154	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43894	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46340	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-20266	20_04_6 LTS (Focal Fossa)
39374	CVE-2021-28429	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-47774	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46692	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42307	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21360	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44991	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46675	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-54479	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35567	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-1553	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42284	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43853	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-43543	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-1550	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46716	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44947	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-50602	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47674	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-43880	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-25704	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47669	22_04_5 LTS (Jammy Jellyfish)
39333	CVE-2024-56826	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43905	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43891	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46737	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42322	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42311	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46730	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23480	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46708	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15862	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-12723	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44998	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43913	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43828	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-10461	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-25685	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-31744	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43912	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47664	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46681	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44944	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-5700	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-45002	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47660	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-12088	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46773	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25643	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46807	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43856	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44982	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-54508	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42260	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46857	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26386	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-40866	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-31436	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-41042	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-26978	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47774	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45005	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25709	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46802	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22748	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46785	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44999	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43911	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2025-0237	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46694	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-13428	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46694	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-42079	Red Hat Enterprise Linux release 8_10 (Ootpa)
39375	CVE-2024-54502	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47537	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42279	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43876	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-37576	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44990	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44963	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42294	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43877	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44990	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-4010	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45411	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44991	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15969	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42283	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15676	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6377	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2025-0240	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43827	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2019-11719	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45410	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2020-14410	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-44974	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46751	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28286	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39471	CVE-2025-0240	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-48339	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0242	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47603	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45001	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45006	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-26934	20_04_6 LTS (Focal Fossa)
39377	CVE-2021-24002	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-42574	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46745	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2795	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42267	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-33033	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46713	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-41092	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-21476	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46718	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-41270	20_04_6 LTS (Focal Fossa)
39377	CVE-2020-10543	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-38409	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46859	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43850	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46758	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-3933	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5721	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45007	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45026	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45029	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46329	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15678	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-29944	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-12403	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42272	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47606	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46686	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26956	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43860	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42273	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0750	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46757	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25710	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46787	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44934	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46804	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46687	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46725	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43908	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-3776	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-44296	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44972	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46845	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43833	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43823	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-1271	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42315	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44939	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42299	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-31081	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-41133	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44967	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-25217	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46826	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46719	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-42928	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-32206	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2020-26935	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-43856	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43867	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-38478	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46772	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44953	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21967	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46821	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44937	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46871	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43827	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43909	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46703	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46775	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-29541	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43894	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43832	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45017	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43833	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22764	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47601	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2609	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46711	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46708	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43905	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46744	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-37750	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-38092	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-44959	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45010	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47683	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43832	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44972	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47661	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43842	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42285	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-52530	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43831	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46692	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42261	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47674	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46741	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46754	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-52532	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2024-44935	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46697	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43842	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12352	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46675	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44965	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46847	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46830	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43832	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42301	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5169	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-10460	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-21968	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-29911	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14363	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2022-23481	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46804	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43890	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-40866	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46859	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29912	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42286	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-3661	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44965	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47667	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47607	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2022-23613	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42292	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-23605	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-35898	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-5129	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46737	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46752	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26959	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46768	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-53122	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46805	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46776	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43824	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47775	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43842	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44970	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40674	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47602	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-36385	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2016-9849	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-42315	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-12747	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43820	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-46826	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46691	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46802	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5725	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43900	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-40782	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-42287	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46779	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44970	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0747	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45009	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46809	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-34479	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46830	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2022-23483	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46758	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12401	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2023-40184	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21282	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-46342	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44987	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42306	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-49984	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46761	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44975	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42265	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-50008	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-54505	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2616	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46705	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-2163	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-43534	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6208	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6857	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-43889	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-4129	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2022-23477	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12825	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-23603	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43912	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44962	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43828	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-3605	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-52006	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43839	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14796	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26951	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14362	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22760	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46733	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21619	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4057	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47541	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-14409	20_04_6 LTS (Focal Fossa)
39421	CVE-2024-56827	24_04_1 LTS (Noble Numbat)
39286	CVE-2024-46793	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46778	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6206	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43834	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42313	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-20277	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21299	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-35939	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-45026	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46793	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46723	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47613	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2024-54505	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-4051	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-3472	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44974	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23613	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38507	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-39472	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-27365	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43818	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47541	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-56827	20_04_6 LTS (Focal Fossa)
39471	CVE-2024-54508	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46854	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28282	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-35195	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46777	22_04_5 LTS (Jammy Jellyfish)
39333	CVE-2023-50229	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-16042	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-21424	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46722	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-4283	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-0753	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-54534	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-22822	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-31741	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46779	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15653	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45026	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45025	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43857	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42298	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46870	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47663	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45005	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-32399	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46695	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44967	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46871	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39333	CVE-2023-50230	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0749	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-54508	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46746	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-27219	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46858	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-9675	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47596	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46845	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-42703	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46703	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42320	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43890	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44960	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42278	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-3421	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46803	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46711	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-30547	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46747	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42311	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40959	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-35839	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46808	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44309	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46706	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43828	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46710	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6207	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46711	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-54502	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46759	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42296	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46743	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4055	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-27851	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-47658	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2024-53088	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46723	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-36328	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44942	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-12088	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45007	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46832	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43906	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-42301	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-21305	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47664	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43911	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42289	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43841	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46727	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-42284	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47683	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47666	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2023-52889	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-11053	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-10459	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46841	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4047	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-4083	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-38091	20_04_6 LTS (Focal Fossa)
39377	CVE-2021-43538	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46771	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26971	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-46874	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46705	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46771	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0746	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2017-18264	20_04_6 LTS (Focal Fossa)
39374	CVE-2019-9674	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46827	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46698	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2016-6609	20_04_6 LTS (Focal Fossa)
39343	CVE-2024-10466	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-34468	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46735	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43849	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28285	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42321	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46765	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46804	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46744	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2024-12085	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2024-41009	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-44966	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2025-0237	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-21426	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46843	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-45491	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46750	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2601	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-27838	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-29650	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42310	22_04_5 LTS (Jammy Jellyfish)
39421	CVE-2024-56826	24_04_1 LTS (Noble Numbat)
39377	CVE-2019-25013	Red Hat Enterprise Linux Server release 7_9 (Maipo)
37575	CVE-2023-28856	22_04_3 LTS (Jammy Jellyfish)
39377	CVE-2023-34058	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44973	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46829	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43891	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44975	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46724	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46718	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2964	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6862	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44969	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-54534	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-31535	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-0465	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42321	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-49460	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46842	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23964	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2021-3941	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46814	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46738	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46680	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-53057	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40789	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2024-12088	20_04_6 LTS (Focal Fossa)
39377	CVE-2022-46881	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-4558	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46824	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43820	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-1529	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-2526	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-45003	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12402	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-43750	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21341	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43895	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46675	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46850	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42316	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-40549	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-40964	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-53088	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-47599	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-25801	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-47665	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43834	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-1196	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46861	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-3550	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43887	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-44244	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-24394	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-44142	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4045	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2022-23477	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46809	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47599	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-32250	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-52532	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-43821	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32211	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42259	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46686	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-26851	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-45000	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3621	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46821	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2588	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46827	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42261	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25705	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44950	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46692	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42316	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42297	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-5688	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22761	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44998	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42292	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45019	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46866	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25732	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46774	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-0767	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-43536	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44957	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-21853	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44980	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-56378	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2025-22134	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43910	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46691	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-42929	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-10464	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2024-4767	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-2614	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46763	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12321	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4208	Red Hat Enterprise Linux Server release 7_9 (Maipo)
37575	CVE-2022-35977	22_04_3 LTS (Jammy Jellyfish)
39377	CVE-2020-14781	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2022-23482	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0409	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43893	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42262	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23481	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15677	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-27820	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44991	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42272	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15648	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44961	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-50264	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-27170	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-28176	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-29533	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-3752	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46784	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45012	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46766	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26137	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-51796	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-43906	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43895	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42283	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42304	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47669	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46693	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46713	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-25804	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-44942	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46739	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43880	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2021-20197	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2022-48936	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-22081	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-4453	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-23954	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42313	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46717	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46812	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43864	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43875	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8177	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23982	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6204	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43861	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2022-23479	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-27777	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46816	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0229	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42273	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-20305	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-23271	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46770	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2024-54479	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-42278	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-21011	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46709	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42296	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46826	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46727	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26961	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46819	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2018-25032	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46815	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-4008	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-11668	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46760	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6209	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42264	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43873	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-26401	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45008	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2024-54502	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-26381	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6856	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-1552	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46817	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43820	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-21886	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44967	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46846	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46744	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2025-0237	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-45006	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-11694	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2022-4285	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-4009	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-49967	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-22049	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6863	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42286	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44942	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47668	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-23598	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-50387	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4048	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-50264	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-2388	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22823	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-2828	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46782	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-27364	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46707	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5217	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45420	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-11053	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43821	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46821	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2019-20811	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46868	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-12086	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23995	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15652	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-4155	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46870	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44984	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-47360	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-42303	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42274	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46763	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14331	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43894	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2019-18282	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-25315	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46797	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2021-20284	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-42287	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21365	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15436	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44989	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14346	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-25803	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46809	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-16044	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43852	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46782	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-24407	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-25746	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4577	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43835	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40982	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46815	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46726	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-54505	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43884	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-4777	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42291	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42307	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46795	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43841	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43845	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40984	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43821	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-1086	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39471	CVE-2025-0241	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-23953	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21434	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47538	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-49528	20_04_6 LTS (Focal Fossa)
39377	CVE-2022-2200	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-25752	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43876	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2023-52918	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43864	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-31080	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-47175	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-42299	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21233	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2020-22040	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46818	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-0920	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43845	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-53057	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42312	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38508	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43830	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-33516	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-20265	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42286	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43854	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43875	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42265	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47615	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46770	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32207	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44979	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-35113	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42294	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42290	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21830	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44989	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44934	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-1983	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47615	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46735	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43837	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-20592	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45001	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46814	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42299	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25637	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43905	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43879	22_04_5 LTS (Jammy Jellyfish)
39333	CVE-2024-56827	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-4034	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2023-52918	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44957	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44975	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46838	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-4254	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46726	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12400	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2024-56826	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46679	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-5702	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47546	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-41974	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-43892	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-25215	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-43537	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-23825	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46860	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47664	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46855	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42309	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46706	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-27820	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46728	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44982	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45403	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-3854	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-30858	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2019-12922	20_04_6 LTS (Focal Fossa)
39343	CVE-2024-38586	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2024-5696	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43824	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47668	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46687	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42291	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43847	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42269	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-50602	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-3341	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-47666	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43839	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-1393	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25645	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42322	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46685	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14792	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46686	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2022-23480	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43895	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46793	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46772	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44988	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44986	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-49463	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-41066	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-45022	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22747	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46852	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45020	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43889	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-54505	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2024-2612	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-24511	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45011	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-4768	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-54502	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-45019	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43850	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42277	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21938	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-21885	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46753	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-23984	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46834	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-32487	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25686	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2022-23478	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42262	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46716	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46717	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47669	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46697	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-47668	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-12424	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43913	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46741	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-22809	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-4769	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2023-52492	Red Hat Enterprise Linux release 8_10 (Ootpa)
39348	CVE-2024-44187	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-6865	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44308	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43864	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-35195	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-42281	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25775	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44979	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-9632	Red Hat Enterprise Linux release 8_10 (Ootpa)
39471	CVE-2024-47175	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46781	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-10878	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46766	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22759	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43907	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42297	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43866	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46687	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12362	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-52530	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46813	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42298	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22756	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46777	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44986	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45027	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43825	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-27062	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43840	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46780	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43849	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-12086	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-42277	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-12085	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4921	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46733	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-24513	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46725	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42281	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45008	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46720	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46842	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-44187	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-42307	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2016-4658	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2025-0239	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47777	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46775	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-21068	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42264	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15664	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-32462	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42318	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46842	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26960	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-36319	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-38178	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-33599	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47600	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43902	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44985	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45012	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8624	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-25735	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-51798	20_04_6 LTS (Focal Fossa)
39377	CVE-2021-4140	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-46143	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-40779	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-0427	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2022-41325	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46749	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26485	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44948	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4623	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23984	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22763	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-3611	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42290	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46750	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46834	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44954	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46811	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42264	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42313	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44308	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46818	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-21853	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14351	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-40782	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-42312	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-12085	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42276	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-42753	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43884	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-4770	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46778	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-50009	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-49984	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29917	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46749	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44309	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-22045	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46828	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46805	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35559	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43892	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46810	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-38177	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-35588	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42268	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-1548	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14318	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42312	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46786	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46813	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45013	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46792	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5176	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42304	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-54505	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46848	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47683	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47544	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43890	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-28374	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45017	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25730	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0240	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-24512	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47778	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-2002	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46861	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2019-20934	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-4028	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-29986	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-23602	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46679	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25717	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47658	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26950	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45015	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46848	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-6514	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2022-23482	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43910	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46723	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2025-0238	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-45015	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46857	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15658	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44966	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46693	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2025-0238	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-46877	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-32360	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42294	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-36351	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-3899	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-9407	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-43835	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14797	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-52006	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43888	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44993	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43854	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46724	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43908	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40962	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44977	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42258	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46781	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46794	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43863	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25647	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43834	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5728	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-46341	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14323	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-40547	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26953	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44941	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47674	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44983	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46689	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-22043	20_04_6 LTS (Focal Fossa)
39377	CVE-2020-8623	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44954	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2025-22134	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43847	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-2319	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2023-0996	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46792	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-23271	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-4011	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-24329	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46779	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46841	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46836	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46710	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25742	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-45013	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-16092	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44988	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-1729	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-12086	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-11168	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-3564	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-51793	20_04_6 LTS (Focal Fossa)
39343	CVE-2019-1010204	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-0778	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46757	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29976	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46732	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46672	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44938	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46678	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46858	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25744	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-47359	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46784	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44993	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47659	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-27820	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-47661	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44963	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42277	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43845	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-42292	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46697	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-43854	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-6864	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-49967	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47597	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44935	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46739	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25751	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15999	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-53057	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8622	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-20921	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-25729	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-50349	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23981	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21293	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46832	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-54534	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43893	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25656	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46677	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43886	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43911	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21954	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-23599	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42306	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42287	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46781	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46710	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44937	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-0492	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-1802	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2022-39261	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-45010	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0408	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-51794	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46752	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42274	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45027	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2025-0242	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-34169	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-29443	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-4883	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-40866	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47835	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46677	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46767	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3564	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46745	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42279	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43882	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46715	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5724	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42258	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42288	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-39472	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47613	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2022-48560	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46768	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43843	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32212	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22737	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-52532	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-38498	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-0494	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46798	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46853	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46822	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43870	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45013	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45009	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23468	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46739	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-44185	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-47776	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45028	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42274	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42319	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42303	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22742	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2018-19968	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46750	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46749	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4585	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39471	CVE-2024-53122	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-42315	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42309	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46852	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29970	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-44244	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-43545	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43853	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46830	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44944	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23978	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-21937	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15654	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44971	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46756	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-44488	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42310	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2607	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42263	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2020-35448	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46784	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42295	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46831	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43833	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-44989	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-45012	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42284	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46882	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-31740	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46829	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2017-1000014	20_04_6 LTS (Focal Fossa)
39348	CVE-2024-54479	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-44956	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-20919	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-40780	Red Hat Enterprise Linux release 8_10 (Ootpa)
39348	CVE-2024-54502	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-26373	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-54508	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46855	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-22218	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43817	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43891	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44978	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47545	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42319	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44983	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-54479	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46797	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46752	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44940	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43881	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-50602	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46795	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44995	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44980	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42292	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-9632	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46756	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-0543	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2021-38093	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46717	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45030	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45011	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43825	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43871	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4863	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46858	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-1546	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46767	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47834	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-26260	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46850	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-43541	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-42932	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-21820	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-26976	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-29539	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-3715	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-54479	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42259	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43912	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-44187	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2022-23484	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-34414	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39471	CVE-2025-0243	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-25220	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2019-9942	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-43879	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2020-23109	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46853	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46741	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4580	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2019-11727	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43870	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12363	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-3864	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2025-0242	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44978	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-44296	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-21340	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46854	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45028	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46849	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21443	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-4378	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44947	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-47175	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-22555	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44962	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43875	22_04_5 LTS (Jammy Jellyfish)
37575	CVE-2022-24834	22_04_3 LTS (Jammy Jellyfish)
39374	CVE-2022-3109	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-45019	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42272	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42296	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-31737	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45018	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-20271	20_04_6 LTS (Focal Fossa)
39377	CVE-2024-33601	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26958	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46680	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43892	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42319	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42306	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46824	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-46679	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46751	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-6829	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42301	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42288	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46714	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46761	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25739	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46851	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42311	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6478	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44954	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46814	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-21261	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15683	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44938	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-53122	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-12747	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44970	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23493	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3177	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46702	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46828	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46672	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44931	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46701	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4207	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-21381	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46786	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-34481	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-40961	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2020-1971	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46788	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2018-7260	20_04_6 LTS (Focal Fossa)
39374	CVE-2018-12581	20_04_6 LTS (Focal Fossa)
39343	CVE-2024-27851	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2019-19721	20_04_6 LTS (Focal Fossa)
39374	CVE-2024-31585	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-43817	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2021-42574	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-43868	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-3596	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-28281	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45406	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44941	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2018-19970	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-47662	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42317	22_04_5 LTS (Jammy Jellyfish)
35415	CVE-2022-44940	22_04_3 LTS (Jammy Jellyfish)
39377	CVE-2021-35603	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46848	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47598	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46817	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46673	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-47662	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43857	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46840	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46774	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-43546	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46822	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43837	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2019-11768	20_04_6 LTS (Focal Fossa)
39377	CVE-2022-31738	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-42070	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46825	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2025-0239	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-5732	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43859	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46806	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35550	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43829	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-20900	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23840	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21283	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43853	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-12747	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46816	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42285	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42314	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44956	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43867	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44957	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43880	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46721	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-43539	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0238	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46851	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44972	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43889	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42269	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25737	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43906	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44948	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46702	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14782	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-29661	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46738	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46812	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43843	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40960	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46745	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14372	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43910	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47539	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-20296	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29946	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43873	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22827	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46732	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46751	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43900	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46853	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46762	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-37201	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14345	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43840	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45020	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46709	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12351	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26974	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0241	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-42276	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4049	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2019-20907	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-41160	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42302	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46867	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43843	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46785	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-49464	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46747	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47600	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46774	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-4453	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46831	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46775	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43914	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-1945	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46721	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46840	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-12425	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-38541	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-38506	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-3266	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43907	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22743	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46695	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42305	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46737	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44986	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-22038	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46740	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46740	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46854	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45418	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44996	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47597	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44950	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42314	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45022	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43873	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43869	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46720	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47660	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2023-40184	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43839	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38504	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44971	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40924	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-22739	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-41159	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44958	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47778	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44953	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-3852	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46691	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46678	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47539	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4574	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46765	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-29535	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2016-9866	20_04_6 LTS (Focal Fossa)
39377	CVE-2020-29573	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46797	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46847	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45010	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46676	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46773	22_04_5 LTS (Jammy Jellyfish)
39471	CVE-2025-0242	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46721	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-3661	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-44946	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47606	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46791	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-11168	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-1966	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45021	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-22051	20_04_6 LTS (Focal Fossa)
39377	CVE-2023-29536	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46755	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43909	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2025-0238	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-42317	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2016-5766	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44971	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46807	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-38476	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42265	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2021-3756	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-42258	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-31291	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-32810	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46738	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47665	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-31742	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44980	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-3600	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-0452	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-42739	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46743	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44983	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44931	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42268	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44974	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47601	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-20918	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46757	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40958	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-44185	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46794	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-23852	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2022-23493	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43840	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14314	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-2961	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46798	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-34416	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43861	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-40217	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2022-31160	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-23918	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44984	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46722	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-11168	20_04_6 LTS (Focal Fossa)
39374	CVE-2024-31582	20_04_6 LTS (Focal Fossa)
39377	CVE-2020-26965	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43904	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6858	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25648	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44953	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-10462	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46871	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-27779	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2024-0450	20_04_6 LTS (Focal Fossa)
39377	CVE-2023-28164	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46803	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46344	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25684	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43819	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46760	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46850	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46835	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46730	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-27749	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-38473	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46782	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0751	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46810	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44990	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-24903	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46707	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44943	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46871	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47777	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45412	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2022-3341	20_04_6 LTS (Focal Fossa)
39471	CVE-2024-3661	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46731	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21930	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43846	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-46878	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-50602	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-49502	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-43859	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46835	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46841	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43884	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2019-19617	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-47663	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-33600	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-34484	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45003	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42297	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8696	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-0548	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45006	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-44244	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-29984	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46762	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-36617	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46773	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2610	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14347	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45002	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44940	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46864	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44985	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2016-2124	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46689	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42295	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-43552	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25692	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2017-1000015	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46754	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46847	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43914	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-12087	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47662	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-3551	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-20254	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46808	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47540	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46838	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46733	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-4127	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-45009	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-27851	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2024-24857	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46780	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-44185	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-29980	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43888	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-42898	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-20867	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21125	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-20945	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2024-40779	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43818	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46713	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44966	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14385	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-22825	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46715	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40780	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-50868	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46835	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43902	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44987	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44958	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46727	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21541	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47659	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46715	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2016-6619	20_04_6 LTS (Focal Fossa)
39377	CVE-2019-19532	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-3861	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46768	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43883	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45000	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-3609	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2020-5504	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46731	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23968	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44947	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43881	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14355	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47538	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46787	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-45018	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-20233	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46846	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46716	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-31747	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44965	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43826	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46747	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46836	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46719	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43829	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23994	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-42896	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42270	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46679	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43868	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42273	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43850	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2022-23614	20_04_6 LTS (Focal Fossa)
39281	CVE-2023-42822	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3246	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2022-48565	20_04_6 LTS (Focal Fossa)
39374	CVE-2023-50229	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-42303	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-9341	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43879	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-50602	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2022-23468	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46823	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-40782	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-47668	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46701	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44996	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46827	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44956	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46864	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-26486	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26116	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44941	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-27838	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43888	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44987	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-0549	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44934	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43856	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-34472	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-35586	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21166	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43849	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46760	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46672	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32205	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-21085	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46731	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-41093	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43835	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23841	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45018	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-53088	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2019-17023	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42298	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6859	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46816	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46811	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46743	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46825	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44969	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46762	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-54479	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46703	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-5690	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46866	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-20271	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-44973	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2025-0243	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2024-12084	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-44939	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38501	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43899	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42309	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2019-12900	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-22754	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-29900	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45000	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43863	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43846	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42301	22_04_5 LTS (Jammy Jellyfish)
37575	CVE-2023-45145	22_04_3 LTS (Jammy Jellyfish)
39335	CVE-2024-43899	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-22039	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-45021	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43876	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46776	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42318	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-23984	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-13765	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42295	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46678	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45005	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46843	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2018-12699	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-44446	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2024-56378	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-46851	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2022-48773	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-45028	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-42927	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21628	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-12084	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2020-22024	20_04_6 LTS (Focal Fossa)
39377	CVE-2023-4128	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43847	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43868	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14360	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2025-22134	20_04_6 LTS (Focal Fossa)
39348	CVE-2024-54508	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46683	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-35111	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2025-0240	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2022-48566	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46812	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43852	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-7053	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-2341	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-3859	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46806	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42304	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-52530	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-44963	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2022-23484	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45405	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-45029	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46693	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44973	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-29967	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46729	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46788	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-50349	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-35513	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21626	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-38076	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-1547	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46867	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-3598	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2019-12616	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46815	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38493	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-25236	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-23601	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46689	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8695	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-10463	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46767	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46718	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-4558	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-46681	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47546	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44961	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4578	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-16012	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42285	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2611	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0239	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-4573	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44948	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43892	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22751	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46844	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-26602	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-33034	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46726	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-4367	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2025-0241	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2021-41184	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46818	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-54505	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-6212	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46676	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-50230	20_04_6 LTS (Focal Fossa)
39281	CVE-2019-11471	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-34470	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-37208	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46714	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46800	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5388	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44960	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-23479	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-5171	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43826	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44938	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43826	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44979	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21843	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43819	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46849	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-39472	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43830	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-35001	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-25712	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21540	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43886	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2025-0237	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46808	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-3347	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42318	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-44990	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-38503	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6205	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47658	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42284	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29916	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-54508	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2020-20898	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46840	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46855	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42279	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43823	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35578	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44995	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-27635	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-40957	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-42317	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23969	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43866	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-20593	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46849	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-47175	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46695	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-10467	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-44939	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2021-23215	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-8625	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43870	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44940	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43818	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45408	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43914	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47544	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46728	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-3857	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-4408	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2024-38608	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44946	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45003	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46681	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-9632	Red Hat Enterprise Linux release 8_10 (Ootpa)
39374	CVE-2021-38094	20_04_6 LTS (Focal Fossa)
39377	CVE-2022-22745	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-33909	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6816	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43902	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44943	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-23918	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43871	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42283	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-40956	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47602	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46770	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43880	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-29914	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-24968	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4575	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-5730	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46720	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42302	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42259	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-45960	Red Hat Enterprise Linux Server release 7_9 (Maipo)
37575	CVE-2023-25155	22_04_3 LTS (Jammy Jellyfish)
39377	CVE-2022-23816	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42281	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2019-17451	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-56378	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2016-6630	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-24968	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46846	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44959	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46755	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26976	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46798	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46709	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-45871	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46746	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47661	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46766	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46677	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45011	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46763	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2022-45061	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46843	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-37211	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-3156	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-6861	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-31083	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2025-0241	Red Hat Enterprise Linux release 8_10 (Ootpa)
39343	CVE-2024-10458	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43866	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2019-11756	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46740	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-7006	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-22738	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21123	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46832	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46714	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46783	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47663	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43824	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43852	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4622	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46759	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-15656	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46785	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46756	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-21820	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43893	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28733	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43861	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2022-32278	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46844	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44969	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47543	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23987	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-45416	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23961	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-22543	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23973	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-5693	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2019-17006	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42267	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45025	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43819	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-1472	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39375	CVE-2024-27838	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43830	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-2608	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39343	CVE-2025-0243	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43831	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-12085	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-45018	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-12085	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2023-34059	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43886	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46868	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44937	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46829	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-36318	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47660	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47545	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46819	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46722	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47540	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46811	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4053	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46685	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43831	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-4453	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-44995	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43854	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45030	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46780	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43877	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4056	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-45030	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42305	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-25743	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-32215	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45027	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21294	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-49501	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46826	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2024-12087	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-42263	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-42289	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46823	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-3302	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-40551	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-42270	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25211	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-21248	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-23998	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45002	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46859	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46844	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46810	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47667	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45001	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-38540	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2022-2320	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-5691	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-26973	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46803	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42320	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46834	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-2369	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-38509	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42289	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25212	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46730	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46860	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2018-25011	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45015	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-52918	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44998	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43883	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-49984	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2023-52889	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47834	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42268	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46802	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45029	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-51795	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-46838	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-4558	Red Hat Enterprise Linux release 8_10 (Ootpa)
39471	CVE-2024-35195	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-46792	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43869	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2022-48434	20_04_6 LTS (Focal Fossa)
39377	CVE-2020-12364	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14361	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-44935	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-17507	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47776	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42260	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2014-9218	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-47543	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46860	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22740	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2023-29659	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-20952	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-38477	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43829	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44999	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44944	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4046	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46698	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-35195	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43904	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-54502	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-43913	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-21094	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-14364	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-43900	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-45025	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44950	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-45020	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43825	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44946	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-21939	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-43867	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22741	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42291	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-43883	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46725	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-22826	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46701	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35561	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46735	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46706	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-42322	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43908	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-46702	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-24713	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-44985	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44982	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-45021	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-25632	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2019-6798	20_04_6 LTS (Focal Fossa)
39343	CVE-2024-53122	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46867	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-53088	Red Hat Enterprise Linux release 8_10 (Ootpa)
39377	CVE-2021-25214	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-47667	22_04_5 LTS (Jammy Jellyfish)
39348	CVE-2024-40789	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-46758	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14779	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47775	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-0741	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-31676	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-20225	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2023-50010	20_04_6 LTS (Focal Fossa)
39286	CVE-2024-42305	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-43881	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-44959	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-36558	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-12422	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46771	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-14803	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-1097	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-47607	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4584	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-35788	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-42261	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46823	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46870	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-32233	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39348	CVE-2025-0243	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-45007	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-40217	20_04_6 LTS (Focal Fossa)
39281	CVE-2024-46795	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-46755	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-28289	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-45008	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-47666	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-21296	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46765	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-4050	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-8648	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-43887	22_04_5 LTS (Jammy Jellyfish)
39286	CVE-2024-42316	22_04_5 LTS (Jammy Jellyfish)
39343	CVE-2024-39503	Red Hat Enterprise Linux release 8_10 (Ootpa)
39335	CVE-2024-43823	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-38497	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-29548	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-46861	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46813	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47596	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-35565	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-35564	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-5367	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2020-15659	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2021-43535	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39374	CVE-2022-3965	20_04_6 LTS (Focal Fossa)
39335	CVE-2024-50264	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-38023	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2024-0743	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46794	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2021-23999	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46787	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-26968	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-31736	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2022-23483	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2023-28162	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39335	CVE-2024-47835	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-45409	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46783	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46778	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-47542	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2020-6463	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39281	CVE-2024-46683	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2022-0330	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-46845	22_04_5 LTS (Jammy Jellyfish)
39374	CVE-2023-50007	20_04_6 LTS (Focal Fossa)
39343	CVE-2021-3487	Red Hat Enterprise Linux release 8_10 (Ootpa)
39286	CVE-2024-43877	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-46866	22_04_5 LTS (Jammy Jellyfish)
39375	CVE-2024-40789	Red Hat Enterprise Linux release 8_10 (Ootpa)
39281	CVE-2024-44989	22_04_5 LTS (Jammy Jellyfish)
39335	CVE-2024-44996	22_04_5 LTS (Jammy Jellyfish)
39377	CVE-2024-1549	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2022-25235	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39377	CVE-2023-22067	Red Hat Enterprise Linux Server release 7_9 (Maipo)
39286	CVE-2024-49967	22_04_5 LTS (Jammy Jellyfish)
39281	CVE-2024-44960	22_04_5 LTS (Jammy Jellyfish)
\.


--
-- Data for Name: os_table; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.os_table (os_name, os_model, os_full_name, os_version, os_build, os_patches, os_install_date, os_autoupdate, os_vendor) FROM stdin;
Ubuntu	placeholder	placeholder	22_04_5 LTS (Jammy Jellyfish)	22_04_5 LTS (Jammy Jellyfish)	[]	placeholder	placeholder	placeholder
Red Hat Enterprise Linux	placeholder	placeholder	Red Hat Enterprise Linux release 8_10 (Ootpa)	Red Hat Enterprise Linux release 8_10 (Ootpa)	[]	placeholder	placeholder	placeholder
Ubuntu	placeholder	placeholder	22_04_3 LTS (Jammy Jellyfish)	22_04_3 LTS (Jammy Jellyfish)	[]	placeholder	placeholder	placeholder
Red Hat Enterprise Linux Server	placeholder	placeholder	Red Hat Enterprise Linux Server release 7_9 (Maipo)	Red Hat Enterprise Linux Server release 7_9 (Maipo)	[]	placeholder	placeholder	placeholder
Ubuntu	placeholder	placeholder	24_04_1 LTS (Noble Numbat)	24_04_1 LTS (Noble Numbat)	[]	placeholder	placeholder	placeholder
Ubuntu	placeholder	placeholder	20_04_6 LTS (Focal Fossa)	20_04_6 LTS (Focal Fossa)	[]	placeholder	placeholder	placeholder
Ubuntu Linux 22_04	placeholder	placeholder	22_04_5 LTS (Jammy Jellyfish)	22_04_5 LTS (Jammy Jellyfish)	[]	placeholder	placeholder	placeholder
\.


--
-- Data for Name: vulnerabilities; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.vulnerabilities (problem_name, problem_id, is_suppressed, suppressed_till, evidence, is_confirmed, product, fix, url) FROM stdin;
CVE-2022-31741	1264180_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2024-4767	31546756_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2024-1549	31524687_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2023-28164	98292_0	False	placeholder	placeholder	True	RHSA-2023:1333: firefox security update (Important)	RHSA-2023:1333	https://access_redhat_com/errata/RHSA-2023:1333
CVE-2024-46709	31372414_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46709
CVE-2023-42822	159492_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2023-42822
CVE-2023-4863	1090230_0	False	placeholder	placeholder	True	RHSA-2023:5197: firefox security update (Important)	RHSA-2023:5197	https://access_redhat_com/errata/RHSA-2023:5197
CVE-2021-20225	113449_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2024-46746	31578924_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46746
CVE-2024-42258	31567971_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42258
CVE-2022-46340	1263243_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2024-35898	25364384_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-46803	24837522_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46803
CVE-2024-45027	15016309_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45027
CVE-2024-46797	20353636_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46797
CVE-2023-50229	1090752_0	False	placeholder	placeholder	True	USN-7222-1 -- BlueZ vulnerabilities	USN-7222-1 -- BlueZ vulnerabilities	https://ubuntu_com/security/CVE-2023-50229
CVE-2019-11756	1142666_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-42079	7008921_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-25717	1060440_0	False	placeholder	placeholder	True	RHSA-2021:5192: samba security and bug fix update (Important)	RHSA-2021:5192	https://access_redhat_com/errata/RHSA-2021:5192
CVE-2024-46765	31578940_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46765
CVE-2021-29650	126835_0	False	placeholder	placeholder	True	RHSA-2021:3327: kernel security and bug fix update (Important)	RHSA-2021:3327	https://access_redhat_com/errata/RHSA-2021:3327
CVE-2024-46826	31579441_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46826
CVE-2020-25212	1068586_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2022-25236	71046_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2022-23482	198592_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23482
CVE-2022-23483	31406713_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23483
CVE-2024-29944	6467121_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2024-2611	31377538_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2022-21443	73318_0	False	placeholder	placeholder	True	RHSA-2022:1487: java-1_8_0-openjdk security	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2020-14362	1123918_0	False	placeholder	placeholder	True	RHSA-2020:4910: xorg-x11-server security update (Important)	RHSA-2020:4910	https://access_redhat_com/errata/RHSA-2020:4910
CVE-2022-42928	1264297_0	False	placeholder	placeholder	True	RHSA-2022:7069: firefox security update (Important)	RHSA-2022:7069	https://access_redhat_com/errata/RHSA-2022:7069
CVE-2024-47777	28884293_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47777
CVE-2024-46726	20353373_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46726
CVE-2024-43914	7008498_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43914
CVE-2024-42272	31568551_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42272
CVE-2021-35578	141939_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2020-14781	72629_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2024-43827	31373175_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43827
CVE-2023-49462	1025114_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-49462
CVE-2024-45017	15016272_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45017
CVE-2024-46812	31579423_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46812
CVE-2024-46680	22143729_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46680
CVE-2020-15669	1099094_0	False	placeholder	placeholder	True	RHSA-2020:3556: firefox security update (Important)	RHSA-2020:3556	https://access_redhat_com/errata/RHSA-2020:3556
CVE-2020-10029	28320_0	False	placeholder	placeholder	True	RHSA-2021:0348: glibc security and bug fix update (Moderate)	RHSA-2021:0348	https://access_redhat_com/errata/RHSA-2021:0348
CVE-2024-4558	31677025_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2021-38509	187424_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2024-0409	1126447_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2024-43894	11688905_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43894
CVE-2024-31585	31539107_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2024-31585
CVE-2020-8698	129171_0	False	placeholder	placeholder	True	RHSA-2020:5083: microcode_ctl security	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2024-56827	placeholder	False	placeholder	placeholder	True	USN-7223-1 -- OpenJPEG vulnerabilities	USN-7223-1 -- OpenJPEG vulnerabilities	https://ubuntu_com/security/CVE-2024-56827
CVE-2020-26116	1098630_0	False	placeholder	placeholder	True	RHSA-2022:5235: python security update (Moderate)	RHSA-2022:5235	https://access_redhat_com/errata/RHSA-2022:5235
CVE-2024-46719	20353345_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46719
CVE-2024-3859	81696_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2023-40546	183578_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2020-25656	7152_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2021-42574	1167873_0	False	placeholder	placeholder	True	RHSA-2021:4033: binutils security update (Moderate)	RHSA-2021:4033	https://access_redhat_com/errata/RHSA-2021:4033
CVE-2024-46845	31579461_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46845
CVE-2023-34059	1169579_0	False	placeholder	placeholder	True	RHSA-2023:7279: open-vm-tools security update (Important)	RHSA-2023:7279	https://access_redhat_com/errata/RHSA-2023:7279
CVE-2024-42298	11688899_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42298
CVE-2023-21968	227146_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2024-43824	7011187_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43824
CVE-2023-29550	1124896_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2024-23918	31596073_0	False	placeholder	placeholder	True	USN-7149-1 -- Intel Microcode vulnerabilities	USN-7149-1 -- Intel Microcode vulnerabilities	https://ubuntu_com/security/CVE-2024-23918
CVE-2024-47597	28884277_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47597
CVE-2022-42927	1264296_0	False	placeholder	placeholder	True	RHSA-2022:7069: firefox security update (Important)	RHSA-2022:7069	https://access_redhat_com/errata/RHSA-2022:7069
CVE-2022-22748	240266_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2024-46717	18365445_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46717
CVE-2024-44943	11644049_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44943
CVE-2024-2609	6979025_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2024-46805	24837491_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46805
CVE-2024-46718	18365448_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46718
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-35195	2632143_0	False	placeholder	placeholder	True	RHSA-2025:0012: python-requests security update (Moderate)	RHSA-2025:0012	https://access_redhat_com/errata/RHSA-2025:0012
CVE-2022-37434	2767_0	False	placeholder	placeholder	True	RHSA-2023:1095: zlib security update (Moderate)	RHSA-2023:1095	https://access_redhat_com/errata/RHSA-2023:1095
CVE-2024-42274	4142091_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42274
CVE-2024-46727	31578911_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46727
CVE-2024-42306	4142791_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42306
CVE-2023-25735	1124852_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2016-9866	193758_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2016-9866
CVE-2022-22737	1264024_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2024-41009	7008910_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2021-30858	1094346_0	False	placeholder	placeholder	True	RHSA-2022:0059: webkitgtk4 security update (Moderate)	RHSA-2022:0059	https://access_redhat_com/errata/RHSA-2022:0059
CVE-2024-44948	7008712_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44948
CVE-2022-44940	91000_0	False	placeholder	placeholder	True	USN-6036-1 -- PatchELF vulnerability	USN-6036-1 -- PatchELF vulnerability	https://ubuntu_com/security/CVE-2022-44940
CVE-2019-11719	1123261_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-14314	97328_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2020-24511	168491_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2023-25742	98275_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-46851	31579467_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46851
CVE-2020-15999	70872_0	False	placeholder	placeholder	True	RHSA-2020:4907: freetype security update (Important)	RHSA-2020:4907	https://access_redhat_com/errata/RHSA-2020:4907
CVE-2023-25746	1124864_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-46784	31578950_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46784
CVE-2022-46342	1263245_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2024-42320	31373028_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42320
CVE-2019-17023	116633_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2021-23984	126846_0	False	placeholder	placeholder	True	RHSA-2021:0992: firefox security update (Important)	RHSA-2021:0992	https://access_redhat_com/errata/RHSA-2021:0992
CVE-2023-24329	1057274_0	False	placeholder	placeholder	True	USN-7180-1 -- Python vulnerabilities	USN-7180-1 -- Python vulnerabilities	https://ubuntu_com/security/CVE-2023-24329
CVE-2021-25804	1081611_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2021-25804
CVE-2023-25728	98261_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-45011	15016257_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45011
CVE-2024-42277	11688898_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42277
CVE-2022-46874	1264351_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2023-2828	1223593_0	False	placeholder	placeholder	True	RHSA-2023:4152: bind security update (Important)	RHSA-2023:4152	https://access_redhat_com/errata/RHSA-2023:4152
CVE-2023-6857	4222_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-44296	26161588_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2022-22759	240277_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2023-21830	196341_0	False	placeholder	placeholder	True	RHSA-2023:0203: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2023:0203	https://access_redhat_com/errata/RHSA-2023:0203
CVE-2021-4083	1083180_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2023-40217	63604_0	False	placeholder	placeholder	True	RHSA-2023:6885: python security update (Important)	RHSA-2023:6885	https://access_redhat_com/errata/RHSA-2023:6885
CVE-2020-29443	161581_0	False	placeholder	placeholder	True	RHSA-2021:2322: qemu-kvm security update (Moderate)	RHSA-2021:2322	https://access_redhat_com/errata/RHSA-2021:2322
CVE-2022-21626	81722_0	False	placeholder	placeholder	True	RHSA-2022:7002: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2022:7002	https://access_redhat_com/errata/RHSA-2022:7002
CVE-2023-47360	1137238_0	False	placeholder	placeholder	True	USN-6783-1 -- VLC vulnerabilities	USN-6783-1 -- VLC vulnerabilities	https://ubuntu_com/security/CVE-2023-47360
CVE-2022-46878	1264354_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2024-46821	31579434_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46821
CVE-2020-16012	29756_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2020-8177	1070421_0	False	placeholder	placeholder	True	RHSA-2020:5002: curl security update (Moderate)	RHSA-2020:5002	https://access_redhat_com/errata/RHSA-2020:5002
CVE-2023-5171	159455_0	False	placeholder	placeholder	True	RHSA-2023:5477: firefox security update (Important)	RHSA-2023:5477	https://access_redhat_com/errata/RHSA-2023:5477
CVE-2022-28289	1264159_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2022-46343	1263246_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2023-6816	99841_0	False	placeholder	placeholder	True	RHSA-2024:0629: tigervnc security update (Important)	RHSA-2024:0629	https://access_redhat_com/errata/RHSA-2024:0629
CVE-2024-21853	31596069_0	False	placeholder	placeholder	True	USN-7149-1 -- Intel Microcode vulnerabilities	USN-7149-1 -- Intel Microcode vulnerabilities	https://ubuntu_com/security/CVE-2024-21853
CVE-2024-46787	31373359_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46787
CVE-2017-18264	217205_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2017-18264
CVE-2024-44963	28814464_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44963
CVE-2024-33599	109860_0	False	placeholder	placeholder	True	RHSA-2024:3588: glibc security update (Important)	RHSA-2024:3588	https://access_redhat_com/errata/RHSA-2024:3588
CVE-2021-23978	1139626_0	False	placeholder	placeholder	True	RHSA-2021:0656: firefox security update (Critical)	RHSA-2021:0656	https://access_redhat_com/errata/RHSA-2021:0656
CVE-2024-47544	28884272_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47544
CVE-2023-32205	98313_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2024-27838	31551869_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2019-9942	115195_0	False	placeholder	placeholder	True	USN-5947-1 -- Twig vulnerabilities	USN-5947-1 -- Twig vulnerabilities	https://ubuntu_com/security/CVE-2019-9942
CVE-2024-42316	4919875_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42316
CVE-2022-45411	240501_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2023-50387	1096636_0	False	placeholder	placeholder	True	and dhcp security update (Important)	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2022-41325	1222835_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2022-41325
CVE-2021-27364	1074490_0	False	placeholder	placeholder	True	RHSA-2021:1071: kernel security and bug fix update (Important)	RHSA-2021:1071	https://access_redhat_com/errata/RHSA-2021:1071
CVE-2022-22747	240265_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2021-3933	134746_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-3933
CVE-2020-15648	209438_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-44938	14530197_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44938
CVE-2021-43541	187440_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-42270	4141973_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42270
CVE-2021-23987	1152515_0	False	placeholder	placeholder	True	RHSA-2021:0992: firefox security update (Important)	RHSA-2021:0992	https://access_redhat_com/errata/RHSA-2021:0992
CVE-2021-27219	1073188_0	False	placeholder	placeholder	True	RHSA-2021:2147: glib2 security update (Important)	RHSA-2021:2147	https://access_redhat_com/errata/RHSA-2021:2147
CVE-2024-44954	31571530_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44954
CVE-2022-48339	1057389_0	False	placeholder	placeholder	True	RHSA-2023:3481: emacs security update (Moderate)	RHSA-2023:3481	https://access_redhat_com/errata/RHSA-2023:3481
CVE-2020-26137	71618_0	False	placeholder	placeholder	True	RHSA-2022:5235: python security update (Moderate)	RHSA-2022:5235	https://access_redhat_com/errata/RHSA-2022:5235
CVE-2024-31080	1194977_0	False	placeholder	placeholder	True	RHSA-2024:2080: tigervnc security update (Important)	RHSA-2024:2080	https://access_redhat_com/errata/RHSA-2024:2080
CVE-2025-0237	34841455_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-49984	31590359_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-49984
CVE-2020-25648	1099858_0	False	placeholder	placeholder	True	RHSA-2021:1384: nss security and bug fix update (Moderate)	RHSA-2021:1384	https://access_redhat_com/errata/RHSA-2021:1384
CVE-2022-45403	240493_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-40924	31556913_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-21434	73107_0	False	placeholder	placeholder	True	RHSA-2022:1487: java-1_8_0-openjdk security	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-46737	20353406_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46737
CVE-2024-43847	31568603_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43847
CVE-2024-43854	4919887_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-12723	1144551_0	False	placeholder	placeholder	True	RHSA-2021:0343: perl security update (Moderate)	RHSA-2021:0343	https://access_redhat_com/errata/RHSA-2021:0343
CVE-2022-38478	1264249_0	False	placeholder	placeholder	True	RHSA-2022:6179: firefox security update (Important)	RHSA-2022:6179	https://access_redhat_com/errata/RHSA-2022:6179
CVE-2020-6463	1135885_0	False	placeholder	placeholder	True	RHSA-2020:3253: firefox security update (Important)	RHSA-2020:3253	https://access_redhat_com/errata/RHSA-2020:3253
CVE-2022-1729	1228872_0	False	placeholder	placeholder	True	RHSA-2022:5232: kernel security and bug fix update (Important)	RHSA-2022:5232	https://access_redhat_com/errata/RHSA-2022:5232
CVE-2020-5504	1142799_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2020-5504
CVE-2023-40550	100587_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2021-23840	1139209_0	False	placeholder	placeholder	True	RHSA-2021:3798: openssl security update (Moderate)	RHSA-2021:3798	https://access_redhat_com/errata/RHSA-2021:3798
CVE-2020-26973	1068735_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2022-21496	81096_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2023-5730	144119_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2024-46857	26164465_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46857
CVE-2020-26951	24189_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2024-44956	7028921_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44956
CVE-2022-45406	240496_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2020-22038	27286_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22038
CVE-2024-42311	7011178_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42311
CVE-2025-22134	34841685_0	False	placeholder	placeholder	True	USN-7220-1 -- Vim vulnerability	USN-7220-1 -- Vim vulnerability	https://ubuntu_com/security/CVE-2025-22134
CVE-2024-4768	31546759_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2022-46882	240550_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2024-43887	6976301_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43887
CVE-2021-3653	1246169_0	False	placeholder	placeholder	True	RHSA-2021:3801: kernel security and bug fix update (Important)	RHSA-2021:3801	https://access_redhat_com/errata/RHSA-2021:3801
CVE-2020-12425	208171_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-44940	14530199_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44940
CVE-2021-20284	126677_0	False	placeholder	placeholder	True	RHSA-2021:4364: binutils security update (Moderate)	RHSA-2021:4364	https://access_redhat_com/errata/RHSA-2021:4364
CVE-2024-46792	18366390_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46792
CVE-2024-47664	31582524_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47664
CVE-2023-6858	1027488_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2021-3715	1070786_0	False	placeholder	placeholder	True	RHSA-2021:3438: kernel security and bug fix update (Moderate)	RHSA-2021:3438	https://access_redhat_com/errata/RHSA-2021:3438
CVE-2024-32487	31538299_0	False	placeholder	placeholder	True	RHSA-2024:3669: less security update (Important)	RHSA-2024:3669	https://access_redhat_com/errata/RHSA-2024:3669
CVE-2023-4585	1171085_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2023-25737	1124853_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-46735	20353403_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46735
CVE-2021-29976	1083643_0	False	placeholder	placeholder	True	RHSA-2021:2741: firefox security update (Important)	RHSA-2021:2741	https://access_redhat_com/errata/RHSA-2021:2741
CVE-2023-29533	98295_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2022-40674	1100911_0	False	placeholder	placeholder	True	RHSA-2022:6997: firefox security update (Important)	RHSA-2022:6997	https://access_redhat_com/errata/RHSA-2022:6997
CVE-2022-23480	198590_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23480
CVE-2024-54534	28884468_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2023-29659	150989_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-29659
CVE-2024-46694	19855505_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46694
CVE-2020-14797	72645_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2021-38093	1245686_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-38093
CVE-2024-46703	31372351_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46703
CVE-2022-3550	31391192_0	False	placeholder	placeholder	True	RHSA-2022:8491: xorg-x11-server security update (Important)	RHSA-2022:8491	https://access_redhat_com/errata/RHSA-2022:8491
CVE-2024-46794	18366413_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46794
CVE-2024-45019	15016279_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45019
CVE-2024-1548	25360982_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2022-34472	240408_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2024-42260	4141774_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42260
CVE-2024-43891	6976306_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43891
CVE-2020-20898	1245652_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-20898
CVE-2024-42310	4919870_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42310
CVE-2024-43907	6467783_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43907
CVE-2024-9632	31593894_0	False	placeholder	placeholder	True	RHSA-2024:8798: xorg-x11-server and xorg-x11-server-Xwayland security update (Moderate)	RHSA-2024:8798	https://access_redhat_com/errata/RHSA-2024:8798
CVE-2023-4578	145835_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2024-42265	4141908_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42265
CVE-2022-46881	1264358_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2022-26373	232819_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2021-35603	141961_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2021-4028	1115987_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2022-36351	62474_0	False	placeholder	placeholder	True	RHSA-2024:3939: linux-firmware security update (Important)	RHSA-2024:3939	https://access_redhat_com/errata/RHSA-2024:3939
CVE-2019-11719	1123261_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2023-4053	51312_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2023-6816	99841_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2024-46800	20353644_0	False	placeholder	placeholder	True	USN-7120-1 -- Linux kernel vulnerabilities	USN-7120-1 -- Linux kernel vulnerabilities	https://ubuntu_com/security/CVE-2024-46800
CVE-2024-43892	7008485_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43892
CVE-2024-7006	7009894_0	False	placeholder	placeholder	True	RHSA-2024:8833: libtiff security update (Moderate)	RHSA-2024:8833	https://access_redhat_com/errata/RHSA-2024:8833
CVE-2023-4573	145828_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2021-23954	1139597_0	False	placeholder	placeholder	True	RHSA-2021:0290: firefox security update (Important)	RHSA-2021:0290	https://access_redhat_com/errata/RHSA-2021:0290
CVE-2024-47663	31582523_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47663
CVE-2021-38507	187422_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2023-34414	199010_0	False	placeholder	placeholder	True	RHSA-2023:3579: firefox security update (Important)	RHSA-2023:3579	https://access_redhat_com/errata/RHSA-2023:3579
CVE-2022-22942	1025984_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2021-20296	126915_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-20296
CVE-2023-25775	31487556_0	False	placeholder	placeholder	True	RHSA-2024:2004: kernel security and bug fix update (Important)	RHSA-2024:2004	https://access_redhat_com/errata/RHSA-2024:2004
CVE-2024-46829	24837488_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46829
CVE-2024-44959	31571536_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44959
CVE-2023-1945	98250_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2020-17507	94824_0	False	placeholder	placeholder	True	RHSA-2020:5021: qt and qt5-qtbase security update (Moderate)	RHSA-2020:5021	https://access_redhat_com/errata/RHSA-2020:5021
CVE-2025-0238	34841456_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-46698	15016442_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46698
CVE-2022-42929	240489_0	False	placeholder	placeholder	True	RHSA-2022:7069: firefox security update (Important)	RHSA-2022:7069	https://access_redhat_com/errata/RHSA-2022:7069
CVE-2024-46807	24837471_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46807
CVE-2024-45008	7008806_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45008
CVE-2021-3347	1072072_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2024-46867	31579480_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46867
CVE-2024-43870	31568833_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43870
CVE-2024-50602	26164373_0	False	placeholder	placeholder	True	RHSA-2024:9502: expat security update (Moderate)	RHSA-2024:9502	https://access_redhat_com/errata/RHSA-2024:9502
CVE-2024-46776	31373342_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46776
CVE-2024-0755	1126760_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2024-42287	11638401_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42287
CVE-2020-25684	161313_0	False	placeholder	placeholder	True	RHSA-2021:0153: dnsmasq security update (Moderate)	RHSA-2021:0153	https://access_redhat_com/errata/RHSA-2021:0153
CVE-2023-6867	4236_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-0743	1126748_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2024-46675	20352795_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46675
CVE-2023-29541	1124890_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2021-31535	167763_0	False	placeholder	placeholder	True	RHSA-2021:3296: libX11 security update (Important)	RHSA-2021:3296	https://access_redhat_com/errata/RHSA-2021:3296
CVE-2021-4034	1255148_0	False	placeholder	placeholder	True	RHSA-2022:0274: polkit security update (Important)	RHSA-2022:0274	https://access_redhat_com/errata/RHSA-2022:0274
CVE-2021-38503	201365_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2023-25751	98284_0	False	placeholder	placeholder	True	RHSA-2023:1333: firefox security update (Important)	RHSA-2023:1333	https://access_redhat_com/errata/RHSA-2023:1333
CVE-2023-44446	1230537_0	False	placeholder	placeholder	True	RHSA-2024:0279: gstreamer-plugins-bad-free security update (Important)	RHSA-2024:0279	https://access_redhat_com/errata/RHSA-2024:0279
CVE-2021-25214	166292_0	False	placeholder	placeholder	True	RHSA-2021:3325: bind security update (Moderate)	RHSA-2021:3325	https://access_redhat_com/errata/RHSA-2021:3325
CVE-2023-6205	111889_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2022-21476	1106364_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2022-34468	1264213_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2022-21233	232814_0	False	placeholder	placeholder	True	RHSA-2022:5937: kernel security and bug fix update (Moderate)	RHSA-2022:5937	https://access_redhat_com/errata/RHSA-2022:5937
CVE-2023-6212	1138332_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2024-44974	6932961_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44974
CVE-2024-47776	28884290_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47776
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2024-42283	4142444_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42283
CVE-2022-21360	70868_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2022-31747	240377_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2021-46143	1082439_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-46850	31579466_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46850
CVE-2024-43817	7011180_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43817
CVE-2022-22742	240259_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2022-46877	240544_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2022-2320	1228880_0	False	placeholder	placeholder	True	RHSA-2022:5905: xorg-x11-server security update (Important)	RHSA-2022:5905	https://access_redhat_com/errata/RHSA-2022:5905
CVE-2022-22740	1264062_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2021-33033	1076505_0	False	placeholder	placeholder	True	RHSA-2021:2725: kernel security and bug fix update (Important)	RHSA-2021:2725	https://access_redhat_com/errata/RHSA-2021:2725
CVE-2021-32399	1076497_0	False	placeholder	placeholder	True	RHSA-2021:3327: kernel security and bug fix update (Important)	RHSA-2021:3327	https://access_redhat_com/errata/RHSA-2021:3327
CVE-2024-46788	27423590_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46788
CVE-2024-47538	31621382_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47538
CVE-2022-1966	200795_0	False	placeholder	placeholder	True	RHSA-2022:5232: kernel security and bug fix update (Important)	RHSA-2022:5232	https://access_redhat_com/errata/RHSA-2022:5232
CVE-2024-43892	7008485_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2021-43542	187441_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2021-29985	1093954_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2024-44931	7008499_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44931
CVE-2024-43884	6467686_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43884
CVE-2024-43842	31373373_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43842
CVE-2024-54508	28884456_0	False	placeholder	placeholder	True	RHSA-2025:0145: webkit2gtk3 security update (Important)	RHSA-2025:0145	https://access_redhat_com/errata/RHSA-2025:0145
CVE-2024-1086	1127311_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2024-46773	22144329_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46773
CVE-2024-43829	31568596_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43829
CVE-2024-21820	31596067_0	False	placeholder	placeholder	True	USN-7149-1 -- Intel Microcode vulnerabilities	USN-7149-1 -- Intel Microcode vulnerabilities	https://ubuntu_com/security/CVE-2024-21820
CVE-2024-9632	31593894_0	False	placeholder	placeholder	True	RHSA-2024:9540: tigervnc security update (Important)	RHSA-2024:9540	https://access_redhat_com/errata/RHSA-2024:9540
CVE-2021-45960	1082362_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-43835	31373309_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43835
CVE-2019-19532	52277_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2022-24407	1086091_0	False	placeholder	placeholder	True	RHSA-2022:0666: cyrus-sasl security update (Important)	RHSA-2022:0666	https://access_redhat_com/errata/RHSA-2022:0666
CVE-2023-32360	199350_0	False	placeholder	placeholder	True	RHSA-2023:4766: cups security update (Important)	RHSA-2023:4766	https://access_redhat_com/errata/RHSA-2023:4766
CVE-2020-8695	129168_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2022-34169	1108717_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2020-12422	1232578_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-46843	24837479_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46843
CVE-2023-4051	1077615_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2024-46798	20353638_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46798
CVE-2024-45491	7008116_0	False	placeholder	placeholder	True	RHSA-2024:8859: xmlrpc-c security update (Moderate)	RHSA-2024:8859	https://access_redhat_com/errata/RHSA-2024:8859
CVE-2024-42319	4142991_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42319
CVE-2020-16092	209477_0	False	placeholder	placeholder	True	RHSA-2021:0347: qemu-kvm security and bug fix update (Moderate)	RHSA-2021:0347	https://access_redhat_com/errata/RHSA-2021:0347
CVE-2024-43856	4919890_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43856
CVE-2024-10458	31593712_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2024-46731	22702549_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46731
CVE-2023-5388	26114193_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2024-46813	31579424_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46813
CVE-2022-21296	70862_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2024-46810	24837499_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46810
CVE-2024-46816	31579428_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46816
CVE-2024-56378	32828543_0	False	placeholder	placeholder	True	USN-7213-1 -- poppler vulnerability	USN-7213-1 -- poppler vulnerability	https://ubuntu_com/security/CVE-2024-56378
CVE-2021-4028	1115987_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2023-32215	1124905_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2024-43908	6467788_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43908
CVE-2020-25710	1192749_0	False	placeholder	placeholder	True	RHSA-2022:0621: openldap security update (Moderate)	RHSA-2022:0621	https://access_redhat_com/errata/RHSA-2022:0621
CVE-2020-26953	24199_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2021-43537	1212106_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-12085	34829026_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12085
CVE-2020-14385	97329_0	False	placeholder	placeholder	True	RHSA-2020:5050: kpatch-patch security update (Important)	RHSA-2020:5050	https://access_redhat_com/errata/RHSA-2020:5050
CVE-2023-22067	143414_0	False	placeholder	placeholder	True	RHSA-2023:5761: java-1_8_0-openjdk security update (Moderate)	RHSA-2023:5761	https://access_redhat_com/errata/RHSA-2023:5761
CVE-2024-46716	18365419_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46716
CVE-2022-22760	240278_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2022-23825	71987_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2023-6206	217990_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2024-43909	6467793_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43909
CVE-2023-51793	31457150_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-51793
CVE-2024-44988	31397398_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44988
CVE-2024-46852	31439694_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46852
CVE-2022-23478	198588_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23478
CVE-2024-46840	24837506_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46840
CVE-2024-46846	24837529_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46846
CVE-2024-47662	31582522_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47662
CVE-2020-15862	1121925_0	False	placeholder	placeholder	True	RHSA-2020:5350: net-snmp security update (Important)	RHSA-2020:5350	https://access_redhat_com/errata/RHSA-2020:5350
CVE-2023-4045	51304_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2024-46762	22144304_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46762
CVE-2024-43866	31568827_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43866
CVE-2020-8623	1068482_0	False	placeholder	placeholder	True	RHSA-2020:5011: bind security and bug fix update (Moderate)	RHSA-2020:5011	https://access_redhat_com/errata/RHSA-2020:5011
CVE-2024-0746	100167_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2024-44967	31397361_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44967
CVE-2024-47602	28884282_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47602
CVE-2024-3852	1207654_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2023-51795	31539340_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-51795
CVE-2024-46849	31579465_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46849
CVE-2020-27749	113447_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2024-35939	31547618_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-4254	1055794_0	False	placeholder	placeholder	True	RHSA-2023:0403: sssd security and bug fix update (Important)	RHSA-2023:0403	https://access_redhat_com/errata/RHSA-2023:0403
CVE-2020-12363	112820_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2020-26935	72058_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2020-26935
CVE-2021-3712	1094297_0	False	placeholder	placeholder	True	RHSA-2022:0064: openssl security update (Moderate)	RHSA-2022:0064	https://access_redhat_com/errata/RHSA-2022:0064
CVE-2024-42321	4142993_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42321
CVE-2024-47596	28884276_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47596
CVE-2023-23605	1124844_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-46720	20353346_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46720
CVE-2024-46710	31578102_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46710
CVE-2024-46838	24837526_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46838
CVE-2021-4083	1083180_0	False	placeholder	placeholder	True	RHSA-2022:1198: kernel security	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2023-6862	1129775_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2021-2388	1081306_0	False	placeholder	placeholder	True	RHSA-2021:2845: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:2845	https://access_redhat_com/errata/RHSA-2021:2845
CVE-2022-45410	240500_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-43846	31373406_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43846
CVE-2024-0408	99862_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2024-47537	31621381_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47537
CVE-2022-3266	240463_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2020-22218	1097416_0	False	placeholder	placeholder	True	RHSA-2023:5615: libssh2 security update (Moderate)	RHSA-2023:5615	https://access_redhat_com/errata/RHSA-2023:5615
CVE-2020-0549	117885_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-40782	28877882_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2022-21443	73318_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-43863	7011212_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43863
CVE-2018-19968	59950_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2018-19968
CVE-2019-12616	235489_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2019-12616
CVE-2024-46781	22144335_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46781
CVE-2020-26978	29672_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2024-43841	4143693_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43841
CVE-2024-47601	28884281_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47601
CVE-2020-15436	129470_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2021-27363	113588_0	False	placeholder	placeholder	True	RHSA-2021:1071: kernel security and bug fix update (Important)	RHSA-2021:1071	https://access_redhat_com/errata/RHSA-2021:1071
CVE-2024-23984	17652880_0	False	placeholder	placeholder	True	USN-7149-1 -- Intel Microcode vulnerabilities	USN-7149-1 -- Intel Microcode vulnerabilities	https://ubuntu_com/security/CVE-2024-23984
CVE-2020-14361	1123917_0	False	placeholder	placeholder	True	RHSA-2020:4910: xorg-x11-server security update (Important)	RHSA-2020:4910	https://access_redhat_com/errata/RHSA-2020:4910
CVE-2024-54502	28884451_0	False	placeholder	placeholder	True	RHSA-2025:0145: webkit2gtk3 security update (Important)	RHSA-2025:0145	https://access_redhat_com/errata/RHSA-2025:0145
CVE-2022-34481	1264226_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2022-46871	1264348_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-46701	31577970_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46701
CVE-2023-49463	1025115_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-49463
CVE-2023-49460	1025113_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-49460
CVE-2021-33034	1076506_0	False	placeholder	placeholder	True	RHSA-2021:2727: kpatch-patch security update (Important)	RHSA-2021:2727	https://access_redhat_com/errata/RHSA-2021:2727
CVE-2022-21624	81760_0	False	placeholder	placeholder	True	RHSA-2022:7002: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2022:7002	https://access_redhat_com/errata/RHSA-2022:7002
CVE-2020-12403	167796_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2022-2526	204854_0	False	placeholder	placeholder	True	RHSA-2022:6160: systemd security update (Important)	RHSA-2022:6160	https://access_redhat_com/errata/RHSA-2022:6160
CVE-2021-38500	1168033_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2024-52532	31595561_0	False	placeholder	placeholder	True	RHSA-2024:9573: libsoup security update (Important)	RHSA-2024:9573	https://access_redhat_com/errata/RHSA-2024:9573
CVE-2024-46749	20353437_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46749
CVE-2023-5728	1169360_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2020-15664	71669_0	False	placeholder	placeholder	True	RHSA-2020:3556: firefox security update (Important)	RHSA-2020:3556	https://access_redhat_com/errata/RHSA-2020:3556
CVE-2024-46783	31578949_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46783
CVE-2021-20254	166502_0	False	placeholder	placeholder	True	RHSA-2021:2313: samba security and bug fix update (Moderate)	RHSA-2021:2313	https://access_redhat_com/errata/RHSA-2021:2313
CVE-2020-8622	95350_0	False	placeholder	placeholder	True	RHSA-2020:5011: bind security and bug fix update (Moderate)	RHSA-2020:5011	https://access_redhat_com/errata/RHSA-2020:5011
CVE-2022-26387	1264098_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2024-1552	28875059_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2024-45006	7028945_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45006
CVE-2022-46340	1263243_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2020-8695	129168_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2020-12424	208141_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2022-46329	31487538_0	False	placeholder	placeholder	True	RHSA-2024:3939: linux-firmware security update (Important)	RHSA-2024:3939	https://access_redhat_com/errata/RHSA-2024:3939
CVE-2024-43889	6467750_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43889
CVE-2022-31740	1264179_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2020-25712	1097895_0	False	placeholder	placeholder	True	RHSA-2020:5408: xorg-x11-server security update (Important)	RHSA-2020:5408	https://access_redhat_com/errata/RHSA-2020:5408
CVE-2023-32207	1124900_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2024-44985	7008788_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44985
CVE-2024-45018	15016273_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-40548	1127136_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2024-0749	100170_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2023-4622	1097442_0	False	placeholder	placeholder	True	RHSA-2024:2004: kernel security and bug fix update (Important)	RHSA-2024:2004	https://access_redhat_com/errata/RHSA-2024:2004
CVE-2024-46806	24837477_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46806
CVE-2020-29573	1155216_0	False	placeholder	placeholder	True	RHSA-2021:0348: glibc security and bug fix update (Moderate)	RHSA-2021:0348	https://access_redhat_com/errata/RHSA-2021:0348
CVE-2023-28162	1124875_0	False	placeholder	placeholder	True	RHSA-2023:1333: firefox security update (Important)	RHSA-2023:1333	https://access_redhat_com/errata/RHSA-2023:1333
CVE-2020-0543	128519_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-46728	22670003_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46728
CVE-2020-12401	71968_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-25645	1099490_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2016-5766	1109592_0	True	2123-12-30	placeholder	True	RHSA-2020:5443: gd security update (Moderate)	RHSA-2020:5443	https://access_redhat_com/errata/RHSA-2020:5443
CVE-2024-46683	15016414_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46683
CVE-2021-23964	1139624_0	False	placeholder	placeholder	True	RHSA-2021:0290: firefox security update (Important)	RHSA-2021:0290	https://access_redhat_com/errata/RHSA-2021:0290
CVE-2021-29984	1093953_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2023-51798	31539343_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-51798
CVE-2024-44937	6467881_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44937
CVE-2020-14385	97329_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2021-41133	1246635_0	False	placeholder	placeholder	True	RHSA-2021:4044: flatpak security update (Important)	RHSA-2021:4044	https://access_redhat_com/errata/RHSA-2021:4044
CVE-2020-25709	1192229_0	False	placeholder	placeholder	True	RHSA-2022:0621: openldap security update (Moderate)	RHSA-2022:0621	https://access_redhat_com/errata/RHSA-2022:0621
CVE-2020-36329	167455_0	False	placeholder	placeholder	True	RHSA-2021:2260: libwebp security update (Important)	RHSA-2021:2260	https://access_redhat_com/errata/RHSA-2021:2260
CVE-2024-1550	28875058_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2024-42278	31372654_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42278
CVE-2024-2608	46411_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2023-50868	180266_0	False	placeholder	placeholder	True	bind-dyndb-ldap	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2024-10463	31593717_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2024-43910	7008493_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43910
CVE-2022-32250	1086495_0	False	placeholder	placeholder	True	RHSA-2022:5232: kernel security and bug fix update (Important)	RHSA-2022:5232	https://access_redhat_com/errata/RHSA-2022:5232
CVE-2024-46853	31579468_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46853
CVE-2020-25692	1108744_0	False	placeholder	placeholder	True	RHSA-2021:1389: openldap security update (Moderate)	RHSA-2021:1389	https://access_redhat_com/errata/RHSA-2021:1389
CVE-2023-3611	1097344_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-45013	15016266_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45013
CVE-2024-47774	28884288_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47774
CVE-2024-9407	25365429_0	False	placeholder	placeholder	True	RHSA-2024:8846: container-tools:rhel8 security update (Important)	RHSA-2024:8846	https://access_redhat_com/errata/RHSA-2024:8846
CVE-2022-29911	240353_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2024-44942	6467903_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44942
CVE-2024-44941	14500295_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44941
CVE-2020-25632	1074308_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2024-46808	31579420_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46808
CVE-2024-42070	7030599_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-14796	72643_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2021-22555	1194746_0	False	placeholder	placeholder	True	RHSA-2021:3327: kernel security and bug fix update (Important)	RHSA-2021:3327	https://access_redhat_com/errata/RHSA-2021:3327
CVE-2020-29661	1070387_0	False	placeholder	placeholder	True	RHSA-2021:0862: kpatch-patch security update (Important)	RHSA-2021:0862	https://access_redhat_com/errata/RHSA-2021:0862
CVE-2024-53088	27538946_0	False	placeholder	placeholder	True	RHSA-2025:0065: kernel security update (Important)	RHSA-2025:0065	https://access_redhat_com/errata/RHSA-2025:0065
CVE-2024-46758	22144273_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46758
CVE-2023-49464	1025117_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-49464
CVE-2022-2200	1264171_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2023-25752	98285_0	False	placeholder	placeholder	True	RHSA-2023:1333: firefox security update (Important)	RHSA-2023:1333	https://access_redhat_com/errata/RHSA-2023:1333
CVE-2023-20900	1093268_0	False	placeholder	placeholder	True	RHSA-2023:5217: open-vm-tools security update (Important)	RHSA-2023:5217	https://access_redhat_com/errata/RHSA-2023:5217
CVE-2020-26959	1046862_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2024-43912	7008494_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43912
CVE-2022-29154	1086658_0	False	placeholder	placeholder	True	RHSA-2022:6170: rsync security update (Important)	RHSA-2022:6170	https://access_redhat_com/errata/RHSA-2022:6170
CVE-2020-14409	1186207_0	False	placeholder	placeholder	True	USN-5274-1 -- Simple DirectMedia Layer vulnerabilities	USN-5274-1 -- Simple DirectMedia Layer vulnerabilities	https://ubuntu_com/security/CVE-2020-14409
CVE-2023-6377	1025979_0	False	placeholder	placeholder	True	RHSA-2024:0009: xorg-x11-server security update (Important)	RHSA-2024:0009	https://access_redhat_com/errata/RHSA-2024:0009
CVE-2022-25235	37806_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2022-46872	1264349_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2022-3341	195931_0	False	placeholder	placeholder	True	USN-5958-1 -- FFmpeg vulnerabilities	USN-5958-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2022-3341
CVE-2024-47665	31582526_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47665
CVE-2024-46827	31579442_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46827
CVE-2023-29536	1124882_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2022-22827	1082531_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-23271	28877565_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-43843	31568601_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43843
CVE-2024-42322	4142998_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42322
CVE-2019-17006	72830_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-2607	31529838_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2020-12400	71967_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2021-23994	1194289_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2024-12087	34829128_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12087
CVE-2021-4140	240198_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2024-54505	28884454_0	False	placeholder	placeholder	True	USN-7201-1 -- WebKitGTK vulnerabilities	USN-7201-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-54505
CVE-2022-1097	240204_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2023-4049	51308_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2020-14792	255725_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2024-44973	31571545_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44973
CVE-2024-44970	31397366_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44970
CVE-2020-26971	1052099_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2024-5690	31551982_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2024-43861	7011210_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43861
CVE-2024-47603	28884283_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47603
CVE-2024-32462	1128434_0	False	placeholder	placeholder	True	RHSA-2024:3980: flatpak security update (Important)	RHSA-2024:3980	https://access_redhat_com/errata/RHSA-2024:3980
CVE-2022-32278	1225612_0	False	placeholder	placeholder	True	USN-6008-1 -- Exo vulnerability	USN-6008-1 -- Exo vulnerability	https://ubuntu_com/security/CVE-2022-32278
CVE-2019-11756	1142666_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-26976	29670_0	False	placeholder	placeholder	True	RHSA-2021:0290: firefox security update (Important)	RHSA-2021:0290	https://access_redhat_com/errata/RHSA-2021:0290
CVE-2020-24489	1193352_0	False	placeholder	placeholder	True	RHSA-2021:2305: microcode_ctl security	RHSA-2021:2305	https://access_redhat_com/errata/RHSA-2021:2305
CVE-2022-43750	77282_0	False	placeholder	placeholder	True	RHSA-2023:1987: kernel security and bug fix update (Moderate)	RHSA-2023:1987	https://access_redhat_com/errata/RHSA-2023:1987
CVE-2020-15436	129470_0	False	placeholder	placeholder	True	bug fix	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2021-21261	1186105_0	False	placeholder	placeholder	True	RHSA-2021:0411: flatpak security update (Important)	RHSA-2021:0411	https://access_redhat_com/errata/RHSA-2021:0411
CVE-2024-46743	20353419_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46743
CVE-2024-5702	31552044_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2021-25220	71204_0	False	placeholder	placeholder	True	RHSA-2023:0402: bind security update (Moderate)	RHSA-2023:0402	https://access_redhat_com/errata/RHSA-2023:0402
CVE-2022-22751	1264078_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2024-44972	31397115_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44972
CVE-2022-21541	253194_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2022-3965	31396174_0	False	placeholder	placeholder	True	USN-5958-1 -- FFmpeg vulnerabilities	USN-5958-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2022-3965
CVE-2024-43860	4919896_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43860
CVE-2021-35588	141950_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2024-54479	31652197_0	False	placeholder	placeholder	True	RHSA-2025:0145: webkit2gtk3 security update (Important)	RHSA-2025:0145	https://access_redhat_com/errata/RHSA-2025:0145
CVE-2021-20265	113722_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2020-14331	97322_0	False	placeholder	placeholder	True	RHSA-2020:5023: kernel security and bug fix update (Moderate)	RHSA-2020:5023	https://access_redhat_com/errata/RHSA-2020:5023
CVE-2024-46732	22670061_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46732
CVE-2023-37211	1224523_0	False	placeholder	placeholder	True	RHSA-2023:4079: firefox security update (Important)	RHSA-2023:4079	https://access_redhat_com/errata/RHSA-2023:4079
CVE-2019-25013	29486_0	False	placeholder	placeholder	True	RHSA-2021:0348: glibc security and bug fix update (Moderate)	RHSA-2021:0348	https://access_redhat_com/errata/RHSA-2021:0348
CVE-2020-8648	1111426_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2021-3177	161105_0	False	placeholder	placeholder	True	RHSA-2022:5235: python security update (Moderate)	RHSA-2022:5235	https://access_redhat_com/errata/RHSA-2022:5235
CVE-2024-43839	31373332_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43839
CVE-2020-0548	117884_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2022-21340	70865_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2022-48434	1107620_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2022-48434
CVE-2024-56826	placeholder	False	placeholder	placeholder	True	USN-7223-1 -- OpenJPEG vulnerabilities	USN-7223-1 -- OpenJPEG vulnerabilities	https://ubuntu_com/security/CVE-2024-56826
CVE-2024-46823	31579438_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46823
CVE-2023-50230	1230588_0	False	placeholder	placeholder	True	USN-7222-1 -- BlueZ vulnerabilities	USN-7222-1 -- BlueZ vulnerabilities	https://ubuntu_com/security/CVE-2023-50230
CVE-2023-23601	98255_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-46677	15016367_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46677
CVE-2022-48773	31346470_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-44989	7028924_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44989
CVE-2022-21540	253192_0	False	placeholder	placeholder	True	RHSA-2022:5698: java-1_8_0-openjdk security	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2024-20918	1126256_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2023-21938	227125_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2023-4584	1171084_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2020-22043	167989_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22043
CVE-2022-21293	70860_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2022-21248	70806_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2022-21299	70863_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2022-0330	1098869_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2020-15658	209449_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2023-22081	143427_0	False	placeholder	placeholder	True	RHSA-2023:5761: java-1_8_0-openjdk security update (Moderate)	RHSA-2023:5761	https://access_redhat_com/errata/RHSA-2023:5761
CVE-2022-39261	1213285_0	False	placeholder	placeholder	True	USN-5947-1 -- Twig vulnerabilities	USN-5947-1 -- Twig vulnerabilities	https://ubuntu_com/security/CVE-2022-39261
CVE-2024-44989	7028924_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	RHSA-2020:5083: microcode_ctl security	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2023-6860	4225_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2023-38409	47501_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2021-41184	142360_0	False	placeholder	placeholder	True	USN-5181-1 -- jQuery UI vulnerability	USN-5181-1 -- jQuery UI vulnerability	https://ubuntu_com/security/CVE-2021-41184
CVE-2020-0427	97482_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2024-3302	31698957_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2023-29548	98309_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2024-42244	7028625_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-8698	129171_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2024-24857	101091_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2021-23969	113204_0	False	placeholder	placeholder	True	RHSA-2021:0656: firefox security update (Critical)	RHSA-2021:0656	https://access_redhat_com/errata/RHSA-2021:0656
CVE-2024-43864	31568825_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43864
CVE-2021-41160	31371390_0	False	placeholder	placeholder	True	RHSA-2021:4619: freerdp security update (Important)	RHSA-2021:4619	https://access_redhat_com/errata/RHSA-2021:4619
CVE-2024-44979	31571548_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44979
CVE-2024-42313	4919872_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42313
CVE-2020-27777	28821_0	False	placeholder	placeholder	True	RHSA-2021:3327: kernel security and bug fix update (Important)	RHSA-2021:3327	https://access_redhat_com/errata/RHSA-2021:3327
CVE-2020-15652	209442_0	False	placeholder	placeholder	True	RHSA-2020:3253: firefox security update (Important)	RHSA-2020:3253	https://access_redhat_com/errata/RHSA-2020:3253
CVE-2021-35556	141905_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2024-4777	207504_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2022-29909	1264160_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2023-20569	68860_0	False	placeholder	placeholder	True	RHSA-2023:7513: linux-firmware security update (Moderate)	RHSA-2023:7513	https://access_redhat_com/errata/RHSA-2023:7513
CVE-2022-21540	253192_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2023-23603	98257_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-46723	20353353_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46723
CVE-2020-26958	76847_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2023-4580	145837_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2021-26260	168246_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-26260
CVE-2024-46753	18366182_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46753
CVE-2024-44995	7028932_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44995
CVE-2024-46672	15016318_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46672
CVE-2024-49967	31589752_0	False	placeholder	placeholder	True	USN-7167-2 -- Linux kernel vulnerabilities	USN-7167-2 -- Linux kernel vulnerabilities	https://ubuntu_com/security/CVE-2024-49967
CVE-2024-42292	4142596_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42292
CVE-2022-36319	1264237_0	False	placeholder	placeholder	True	RHSA-2022:5776: firefox security update (Important)	RHSA-2022:5776	https://access_redhat_com/errata/RHSA-2022:5776
CVE-2024-1546	25360974_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2022-29917	240359_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2024-43869	31568831_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43869
CVE-2024-46774	31373336_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46774
CVE-2020-24394	1068783_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2023-4048	1077611_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2020-14351	1070367_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2020-12403	167796_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-46760	22144275_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46760
CVE-2024-43823	7011186_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43823
CVE-2022-45420	240537_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-0229	1204571_0	False	placeholder	placeholder	True	RHSA-2024:0629: tigervnc security update (Important)	RHSA-2024:0629	https://access_redhat_com/errata/RHSA-2024:0629
CVE-2023-40217	63604_0	False	placeholder	placeholder	True	USN-7180-1 -- Python vulnerabilities	USN-7180-1 -- Python vulnerabilities	https://ubuntu_com/security/CVE-2023-40217
CVE-2021-41270	186851_0	False	placeholder	placeholder	True	USN-5290-1 -- Symfony vulnerabilities	USN-5290-1 -- Symfony vulnerabilities	https://ubuntu_com/security/CVE-2021-41270
CVE-2024-46730	31373215_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46730
CVE-2023-37208	1224515_0	False	placeholder	placeholder	True	RHSA-2023:4079: firefox security update (Important)	RHSA-2023:4079	https://access_redhat_com/errata/RHSA-2023:4079
CVE-2023-4208	1097440_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-1553	31524691_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2019-11727	96636_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2019-11727	96636_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-45020	15016280_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45020
CVE-2020-25704	129557_0	False	placeholder	placeholder	True	RHSA-2022:0063: kernel security and bug fix update (Moderate)	RHSA-2022:0063	https://access_redhat_com/errata/RHSA-2022:0063
CVE-2022-22739	240252_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2022-28693	placeholder	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2024-46780	31373350_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46780
CVE-2024-43832	4143500_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43832
CVE-2023-50868	180266_0	False	placeholder	placeholder	True	RHSA-2024:3741: bind	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2024-47545	28884273_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47545
CVE-2021-37750	65039_0	False	placeholder	placeholder	True	RHSA-2021:4788: krb5 security update (Moderate)	RHSA-2021:4788	https://access_redhat_com/errata/RHSA-2021:4788
CVE-2024-42302	4919867_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42302
CVE-2021-35586	141949_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2021-3573	64574_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2023-50007	31457148_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-50007
CVE-2019-17023	116633_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-47683	26164475_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47683
CVE-2024-41066	11688885_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-28286	240347_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2023-5380	144199_0	False	placeholder	placeholder	True	RHSA-2023:7428: tigervnc security update (Important)	RHSA-2023:7428	https://access_redhat_com/errata/RHSA-2023:7428
CVE-2024-43845	4143780_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43845
CVE-2024-21886	1206228_0	False	placeholder	placeholder	True	RHSA-2024:0629: tigervnc security update (Important)	RHSA-2024:0629	https://access_redhat_com/errata/RHSA-2024:0629
CVE-2024-2614	31529843_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2024-3854	1196375_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2024-46868	31579481_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46868
CVE-2023-6864	1027493_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-47542	28884270_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47542
CVE-2023-51792	101961_0	False	placeholder	placeholder	True	USN-6764-1 -- libde265 vulnerability	USN-6764-1 -- libde265 vulnerability	https://ubuntu_com/security/CVE-2023-51792
CVE-2022-36021	68264_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2022-36021
CVE-2021-38497	142745_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2023-4577	145834_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2024-46826	31579441_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-0452	129046_0	False	placeholder	placeholder	True	RHSA-2020:5402: libexif security update (Important)	RHSA-2020:5402	https://access_redhat_com/errata/RHSA-2020:5402
CVE-2024-46859	31579473_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46859
CVE-2024-43906	6467779_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43906
CVE-2024-21085	171717_0	False	placeholder	placeholder	True	RHSA-2024:1817: java-1_8_0-openjdk security update (Moderate)	RHSA-2024:1817	https://access_redhat_com/errata/RHSA-2024:1817
CVE-2020-15678	1099102_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-40789	31563330_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-3661	1230969_0	False	placeholder	placeholder	True	RHSA-2025:0288: Bug fix of NetworkManager (Moderate)	RHSA-2025:0288	https://access_redhat_com/errata/RHSA-2025:0288
CVE-2021-23968	113202_0	False	placeholder	placeholder	True	RHSA-2021:0656: firefox security update (Critical)	RHSA-2021:0656	https://access_redhat_com/errata/RHSA-2021:0656
CVE-2024-46814	31579425_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46814
CVE-2020-0543	128519_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2022-21434	73107_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-26851	171874_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-42294	4142621_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42294
CVE-2020-1971	8484_0	False	placeholder	placeholder	True	RHSA-2020:5566: openssl security update (Important)	RHSA-2020:5566	https://access_redhat_com/errata/RHSA-2020:5566
CVE-2024-46697	19830633_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46697
CVE-2024-47546	28884274_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47546
CVE-2022-45418	240535_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2020-14345	1123898_0	False	placeholder	placeholder	True	RHSA-2020:4910: xorg-x11-server security update (Important)	RHSA-2020:4910	https://access_redhat_com/errata/RHSA-2020:4910
CVE-2023-45145	143553_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2023-45145
CVE-2022-28282	240326_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2024-46824	31579439_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46824
CVE-2022-21341	230695_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2024-44980	31571549_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44980
CVE-2020-8625	1139294_0	False	placeholder	placeholder	True	RHSA-2021:0671: bind security update (Important)	RHSA-2021:0671	https://access_redhat_com/errata/RHSA-2021:0671
CVE-2023-4408	1208044_0	False	placeholder	placeholder	True	and dhcp security update (Important)	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2024-52530	31433942_0	False	placeholder	placeholder	True	RHSA-2024:9573: libsoup security update (Important)	RHSA-2024:9573	https://access_redhat_com/errata/RHSA-2024:9573
CVE-2023-23598	98252_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-31582	31555383_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2024-31582
CVE-2020-6829	128393_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-24489	1193352_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-43849	31373464_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43849
CVE-2020-24511	168491_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2021-4129	240197_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-40984	31556966_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-43868	26161555_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43868
CVE-2022-21282	70808_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2020-12401	71968_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2021-25802	1081609_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2021-25802
CVE-2019-11471	1197104_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2019-11471
CVE-2021-38508	187423_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2020-10878	1144452_0	False	placeholder	placeholder	True	RHSA-2021:0343: perl security update (Moderate)	RHSA-2021:0343	https://access_redhat_com/errata/RHSA-2021:0343
CVE-2024-44953	7028920_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44953
CVE-2024-53057	27538918_0	False	placeholder	placeholder	True	USN-7167-2 -- Linux kernel vulnerabilities	USN-7167-2 -- Linux kernel vulnerabilities	https://ubuntu_com/security/CVE-2024-53057
CVE-2022-23479	198589_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23479
CVE-2022-31737	240367_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2021-3347	1072072_0	False	placeholder	placeholder	True	RHSA-2021:2285: kpatch-patch security update (Important)	RHSA-2021:2285	https://access_redhat_com/errata/RHSA-2021:2285
CVE-2023-4057	51317_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2024-47615	28884287_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47615
CVE-2023-4206	1097438_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-43880	31568844_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43880
CVE-2020-14346	1123916_0	False	placeholder	placeholder	True	RHSA-2020:4910: xorg-x11-server security update (Important)	RHSA-2020:4910	https://access_redhat_com/errata/RHSA-2020:4910
CVE-2024-43837	4919885_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43837
CVE-2023-4050	1077614_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2022-40958	240482_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2019-17450	93544_0	False	placeholder	placeholder	True	RHSA-2020:4465: binutils security update (Low)	RHSA-2020:4465	https://access_redhat_com/errata/RHSA-2020:4465
CVE-2021-29986	1093955_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2024-47661	31582521_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47661
CVE-2024-47674	26164471_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47674
CVE-2024-46830	31579445_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46830
CVE-2023-50008	31539333_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-50008
CVE-2020-8698	129171_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2024-47659	31582509_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47659
CVE-2019-11727	96636_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-44993	7028930_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44993
CVE-2020-13765	255229_0	False	placeholder	placeholder	True	RHSA-2021:0347: qemu-kvm security and bug fix update (Moderate)	RHSA-2021:0347	https://access_redhat_com/errata/RHSA-2021:0347
CVE-2024-1547	29061562_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2024-54505	28884454_0	False	placeholder	placeholder	True	RHSA-2025:0145: webkit2gtk3 security update (Important)	RHSA-2025:0145	https://access_redhat_com/errata/RHSA-2025:0145
CVE-2024-43888	6467736_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43888
CVE-2022-38477	1264243_0	False	placeholder	placeholder	True	RHSA-2022:6179: firefox security update (Important)	RHSA-2022:6179	https://access_redhat_com/errata/RHSA-2022:6179
CVE-2021-3752	1060362_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2023-51796	101966_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-51796
CVE-2020-6514	208884_0	False	placeholder	placeholder	True	RHSA-2020:3253: firefox security update (Important)	RHSA-2020:3253	https://access_redhat_com/errata/RHSA-2020:3253
CVE-2024-43890	7008483_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43890
CVE-2022-21426	73031_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-46761	22182338_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46761
CVE-2021-38493	1168027_0	False	placeholder	placeholder	True	RHSA-2021:3498: firefox security update (Important)	RHSA-2021:3498	https://access_redhat_com/errata/RHSA-2021:3498
CVE-2020-24512	168492_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-33602	31545743_0	False	placeholder	placeholder	True	RHSA-2024:3588: glibc security update (Important)	RHSA-2024:3588	https://access_redhat_com/errata/RHSA-2024:3588
CVE-2022-34479	240415_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2024-5693	31551985_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2021-23961	1139604_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2022-21365	70869_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2023-22049	50382_0	False	placeholder	placeholder	True	RHSA-2023:4166: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2023:4166	https://access_redhat_com/errata/RHSA-2023:4166
CVE-2024-44987	7008791_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44987
CVE-2022-45404	240494_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-5696	31552037_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2024-42261	4141783_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42261
CVE-2023-22045	50360_0	False	placeholder	placeholder	True	RHSA-2023:4166: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2023:4166	https://access_redhat_com/errata/RHSA-2023:4166
CVE-2022-45421	1264347_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-47668	31582529_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47668
CVE-2021-32399	1076497_0	False	placeholder	placeholder	True	RHSA-2021:3381: kpatch-patch security update (Important)	RHSA-2021:3381	https://access_redhat_com/errata/RHSA-2021:3381
CVE-2024-46775	31373337_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46775
CVE-2024-42307	7008480_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42307
CVE-2023-49501	31539331_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-49501
CVE-2022-45412	1264311_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-46770	22182355_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46770
CVE-2020-8698	129171_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-27062	25469299_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-20867	99172_0	False	placeholder	placeholder	True	RHSA-2023:3944: open-vm-tools security and bug fix update (Low)	RHSA-2023:3944	https://access_redhat_com/errata/RHSA-2023:3944
CVE-2014-9218	238506_0	True	2123-12-30	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2014-9218
CVE-2024-42303	4142785_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42303
CVE-2022-21123	201436_0	False	placeholder	placeholder	True	RHSA-2022:5937: kernel security and bug fix update (Moderate)	RHSA-2022:5937	https://access_redhat_com/errata/RHSA-2022:5937
CVE-2022-24834	1071346_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2022-24834
CVE-2024-31080	1194977_0	False	placeholder	placeholder	True	RHSA-2024:1785: X_Org server security update (Important)	RHSA-2024:1785	https://access_redhat_com/errata/RHSA-2024:1785
CVE-2021-4008	1212722_0	False	placeholder	placeholder	True	RHSA-2022:0003: xorg-x11-server security update (Important)	RHSA-2022:0003	https://access_redhat_com/errata/RHSA-2022:0003
CVE-2024-10466	31593720_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2021-23953	113214_0	False	placeholder	placeholder	True	RHSA-2021:0290: firefox security update (Important)	RHSA-2021:0290	https://access_redhat_com/errata/RHSA-2021:0290
CVE-2021-33034	1076506_0	False	placeholder	placeholder	True	RHSA-2021:2725: kernel security and bug fix update (Important)	RHSA-2021:2725	https://access_redhat_com/errata/RHSA-2021:2725
CVE-2022-24903	1098934_0	False	placeholder	placeholder	True	RHSA-2022:4803: rsyslog security update (Important)	RHSA-2022:4803	https://access_redhat_com/errata/RHSA-2022:4803
CVE-2024-42291	4142585_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42291
CVE-2019-20907	1068320_0	False	placeholder	placeholder	True	RHSA-2020:5009: python security update (Moderate)	RHSA-2020:5009	https://access_redhat_com/errata/RHSA-2020:5009
CVE-2022-29901	252589_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2024-38540	26161549_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-48560	1092615_0	False	placeholder	placeholder	True	USN-7180-1 -- Python vulnerabilities	USN-7180-1 -- Python vulnerabilities	https://ubuntu_com/security/CVE-2022-48560
CVE-2025-0239	34841457_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-46739	20353408_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46739
CVE-2021-28429	62612_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-28429
CVE-2024-38586	1025199_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-6478	1025980_0	False	placeholder	placeholder	True	RHSA-2024:0006: tigervnc security update (Important)	RHSA-2024:0006	https://access_redhat_com/errata/RHSA-2024:0006
CVE-2022-21305	70864_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2020-12403	167796_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-43877	31568841_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43877
CVE-2024-46687	15536793_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46687
CVE-2022-46341	1263244_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2023-5725	144108_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2022-35977	196603_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2022-35977
CVE-2024-0450	164417_0	False	placeholder	placeholder	True	USN-7212-1 -- Python 2_7 vulnerabilities	USN-7212-1 -- Python 2_7 vulnerabilities	https://ubuntu_com/security/CVE-2024-0450
CVE-2020-15673	1099097_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-2961	31539092_0	False	placeholder	placeholder	True	RHSA-2024:3588: glibc security update (Important)	RHSA-2024:3588	https://access_redhat_com/errata/RHSA-2024:3588
CVE-2020-15656	1233734_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2021-42739	35761_0	False	placeholder	placeholder	True	RHSA-2022:0063: kernel security and bug fix update (Moderate)	RHSA-2022:0063	https://access_redhat_com/errata/RHSA-2022:0063
CVE-2024-43873	7011216_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43873
CVE-2020-12402	208149_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2023-4623	1170893_0	False	placeholder	placeholder	True	RHSA-2024:2004: kernel security and bug fix update (Important)	RHSA-2024:2004	https://access_redhat_com/errata/RHSA-2024:2004
CVE-2024-45003	25372555_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45003
CVE-2022-34169	1108717_0	False	placeholder	placeholder	True	RHSA-2022:5698: java-1_8_0-openjdk security	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2022-26381	1264092_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2024-42309	4919869_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42309
CVE-2024-0747	100168_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2025-0240	34841458_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-44977	31397376_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44977
CVE-2020-12400	71967_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-46768	31578942_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46768
CVE-2020-23109	1168053_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2020-23109
CVE-2022-3964	31396173_0	False	placeholder	placeholder	True	USN-5958-1 -- FFmpeg vulnerabilities	USN-5958-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2022-3964
CVE-2024-46844	31579460_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46844
CVE-2025-0241	34841459_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-46695	19855506_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46695
CVE-2023-6861	1027491_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-21094	171727_0	False	placeholder	placeholder	True	RHSA-2024:1817: java-1_8_0-openjdk security update (Moderate)	RHSA-2024:1817	https://access_redhat_com/errata/RHSA-2024:1817
CVE-2020-25647	1074404_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2023-4581	145838_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2023-28176	1124878_0	False	placeholder	placeholder	True	RHSA-2023:1333: firefox security update (Important)	RHSA-2023:1333	https://access_redhat_com/errata/RHSA-2023:1333
CVE-2024-42267	4141935_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42267
CVE-2022-2795	73772_0	False	placeholder	placeholder	True	RHSA-2023:0402: bind security update (Moderate)	RHSA-2023:0402	https://access_redhat_com/errata/RHSA-2023:0402
CVE-2024-44934	6467817_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44934
CVE-2020-12402	208149_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2021-41159	31544281_0	False	placeholder	placeholder	True	RHSA-2021:4619: freerdp security update (Important)	RHSA-2021:4619	https://access_redhat_com/errata/RHSA-2021:4619
CVE-2021-4028	1115987_0	False	placeholder	placeholder	True	RHSA-2022:1198: kernel security	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2024-46722	20353349_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46722
CVE-2024-43904	6467769_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43904
CVE-2024-47598	28884278_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47598
CVE-2021-23215	168245_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-23215
CVE-2024-21011	171633_0	False	placeholder	placeholder	True	RHSA-2024:1817: java-1_8_0-openjdk security update (Moderate)	RHSA-2024:1817	https://access_redhat_com/errata/RHSA-2024:1817
CVE-2020-25686	161320_0	False	placeholder	placeholder	True	RHSA-2021:0153: dnsmasq security update (Moderate)	RHSA-2021:0153	https://access_redhat_com/errata/RHSA-2021:0153
CVE-2022-46341	1263244_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2021-3756	142543_0	False	placeholder	placeholder	True	USN-5184-1 -- libmysofa vulnerability	USN-5184-1 -- libmysofa vulnerability	https://ubuntu_com/security/CVE-2021-3756
CVE-2020-8624	6516_0	False	placeholder	placeholder	True	RHSA-2020:5011: bind security and bug fix update (Moderate)	RHSA-2020:5011	https://access_redhat_com/errata/RHSA-2020:5011
CVE-2024-46706	19855507_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46706
CVE-2024-45021	15049681_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45021
CVE-2024-54508	28884456_0	False	placeholder	placeholder	True	USN-7201-1 -- WebKitGTK vulnerabilities	USN-7201-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-54508
CVE-2024-43889	6467750_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-11694	27543155_0	False	placeholder	placeholder	True	USN-7193-1 -- Thunderbird vulnerability	USN-7193-1 -- Thunderbird vulnerability	https://ubuntu_com/security/CVE-2024-11694
CVE-2021-23973	113209_0	False	placeholder	placeholder	True	RHSA-2021:0656: firefox security update (Critical)	RHSA-2021:0656	https://access_redhat_com/errata/RHSA-2021:0656
CVE-2024-42286	11638400_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42286
CVE-2023-49528	31538164_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-49528
CVE-2020-22051	20398_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22051
CVE-2024-53122	28879814_0	False	placeholder	placeholder	True	RHSA-2025:0065: kernel security update (Important)	RHSA-2025:0065	https://access_redhat_com/errata/RHSA-2025:0065
CVE-2024-45030	15016317_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45030
CVE-2020-8695	129168_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2021-35559	141909_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2023-29535	98296_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2024-45026	15016306_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45026
CVE-2022-0778	1098838_0	False	placeholder	placeholder	True	RHSA-2022:1066: openssl security update (Important)	RHSA-2022:1066	https://access_redhat_com/errata/RHSA-2022:1066
CVE-2021-3472	1153778_0	False	placeholder	placeholder	True	RHSA-2021:2033: xorg-x11-server security update (Important)	RHSA-2021:2033	https://access_redhat_com/errata/RHSA-2021:2033
CVE-2024-46714	31578903_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46714
CVE-2024-47606	28884284_0	False	placeholder	placeholder	True	USN-7174-1 -- GStreamer vulnerability	USN-7174-1 -- GStreamer vulnerability	https://ubuntu_com/security/CVE-2024-47606
CVE-2024-12084	34842679_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12084
CVE-2020-12352	202937_0	False	placeholder	placeholder	True	RHSA-2020:4276: kernel security update (Important)	RHSA-2020:4276	https://access_redhat_com/errata/RHSA-2020:4276
CVE-2020-24512	168492_0	False	placeholder	placeholder	True	RHSA-2021:2305: microcode_ctl security	RHSA-2021:2305	https://access_redhat_com/errata/RHSA-2021:2305
CVE-2022-21540	253192_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2024-47541	28884269_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47541
CVE-2020-22040	167987_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22040
CVE-2024-27017	31540579_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-46681	19855503_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46681
CVE-2024-11053	28884202_0	False	placeholder	placeholder	True	USN-7162-1 -- curl vulnerability	USN-7162-1 -- curl vulnerability	https://ubuntu_com/security/CVE-2024-11053
CVE-2024-27820	31551862_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-20921	180523_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2024-43900	6467754_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43900
CVE-2019-17023	116633_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-14782	72630_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2020-26934	72057_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2020-26934
CVE-2021-38092	1245685_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-38092
CVE-2024-46745	18366131_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46745
CVE-2024-26602	181129_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2021-25217	1030925_0	False	placeholder	placeholder	True	RHSA-2021:2357: dhcp security update (Important)	RHSA-2021:2357	https://access_redhat_com/errata/RHSA-2021:2357
CVE-2021-2341	54705_0	False	placeholder	placeholder	True	RHSA-2021:2845: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:2845	https://access_redhat_com/errata/RHSA-2021:2845
CVE-2023-5367	1240164_0	False	placeholder	placeholder	True	RHSA-2023:7428: tigervnc security update (Important)	RHSA-2023:7428	https://access_redhat_com/errata/RHSA-2023:7428
CVE-2024-0751	1126756_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2024-31081	1194978_0	False	placeholder	placeholder	True	RHSA-2024:2080: tigervnc security update (Important)	RHSA-2024:2080	https://access_redhat_com/errata/RHSA-2024:2080
CVE-2024-33600	206524_0	False	placeholder	placeholder	True	RHSA-2024:3588: glibc security update (Important)	RHSA-2024:3588	https://access_redhat_com/errata/RHSA-2024:3588
CVE-2024-45025	15016305_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45025
CVE-2024-46763	22144313_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46763
CVE-2024-43895	11641794_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43895
CVE-2024-43828	4919877_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43828
CVE-2021-20271	1152349_0	False	placeholder	placeholder	True	RHSA-2021:4785: rpm security update (Moderate)	RHSA-2021:4785	https://access_redhat_com/errata/RHSA-2021:4785
CVE-2022-21496	81096_0	False	placeholder	placeholder	True	RHSA-2022:1487: java-1_8_0-openjdk security	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-42288	7008478_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42288
CVE-2023-28856	227197_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2023-28856
CVE-2024-43871	7011214_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43871
CVE-2020-15436	129470_0	False	placeholder	placeholder	True	RHSA-2021:0336: kernel security	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2024-47660	31582510_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47660
CVE-2024-3861	81697_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2021-25801	1081608_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2021-25801
CVE-2024-42295	4142634_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42295
CVE-2020-26950	1046785_0	False	placeholder	placeholder	True	RHSA-2020:5099: firefox security update (Critical)	RHSA-2020:5099	https://access_redhat_com/errata/RHSA-2020:5099
CVE-2021-43545	187444_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2020-14323	128503_0	False	placeholder	placeholder	True	RHSA-2020:5439: samba security and bug fix update (Moderate)	RHSA-2020:5439	https://access_redhat_com/errata/RHSA-2020:5439
CVE-2024-31081	1194978_0	False	placeholder	placeholder	True	RHSA-2024:1785: X_Org server security update (Important)	RHSA-2024:1785	https://access_redhat_com/errata/RHSA-2024:1785
CVE-2016-2124	37947_0	True	2123-12-30	placeholder	True	RHSA-2021:5192: samba security and bug fix update (Important)	RHSA-2021:5192	https://access_redhat_com/errata/RHSA-2021:5192
CVE-2016-6619	1218225_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2016-6619
CVE-2024-47613	31621383_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47613
CVE-2019-17006	72830_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2021-23841	112778_0	False	placeholder	placeholder	True	RHSA-2021:3798: openssl security update (Moderate)	RHSA-2021:3798	https://access_redhat_com/errata/RHSA-2021:3798
CVE-2024-0742	100163_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2021-20271	1152349_0	False	placeholder	placeholder	True	USN-5273-1 -- RPM Package Manager vulnerabilities	USN-5273-1 -- RPM Package Manager vulnerabilities	https://ubuntu_com/security/CVE-2021-20271
CVE-2022-31744	240374_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2024-46825	31579440_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46825
CVE-2024-46756	22144269_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46756
CVE-2022-2601	1106973_0	False	placeholder	placeholder	True	RHSA-2024:2002: grub2 security update (Moderate)	RHSA-2024:2002	https://access_redhat_com/errata/RHSA-2024:2002
CVE-2023-47359	110800_0	False	placeholder	placeholder	True	USN-6783-1 -- VLC vulnerabilities	USN-6783-1 -- VLC vulnerabilities	https://ubuntu_com/security/CVE-2023-47359
CVE-2020-25685	161314_0	False	placeholder	placeholder	True	RHSA-2021:0153: dnsmasq security update (Moderate)	RHSA-2021:0153	https://access_redhat_com/errata/RHSA-2021:0153
CVE-2022-3109	1263393_0	False	placeholder	placeholder	True	USN-5958-1 -- FFmpeg vulnerabilities	USN-5958-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2022-3109
CVE-2024-4770	31546762_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2020-12401	71968_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2022-3551	31391217_0	False	placeholder	placeholder	True	RHSA-2022:8491: xorg-x11-server security update (Important)	RHSA-2022:8491	https://access_redhat_com/errata/RHSA-2022:8491
CVE-2020-27779	1074437_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2022-4283	1263255_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2024-43913	7008497_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43913
CVE-2024-42299	4142755_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42299
CVE-2022-21619	81769_0	False	placeholder	placeholder	True	RHSA-2022:7002: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2022:7002	https://access_redhat_com/errata/RHSA-2022:7002
CVE-2024-44946	7008146_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44946
CVE-2022-42932	1264301_0	False	placeholder	placeholder	True	RHSA-2022:7069: firefox security update (Important)	RHSA-2022:7069	https://access_redhat_com/errata/RHSA-2022:7069
CVE-2022-42898	1096935_0	False	placeholder	placeholder	True	RHSA-2022:8640: krb5 security update (Important)	RHSA-2022:8640	https://access_redhat_com/errata/RHSA-2022:8640
CVE-2020-24513	168493_0	False	placeholder	placeholder	True	RHSA-2021:2305: microcode_ctl security	RHSA-2021:2305	https://access_redhat_com/errata/RHSA-2021:2305
CVE-2022-26383	240285_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2022-23477	198587_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23477
CVE-2024-46848	24837548_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46848
CVE-2020-16044	1071823_0	False	placeholder	placeholder	True	RHSA-2021:0053: firefox security update (Critical)	RHSA-2021:0053	https://access_redhat_com/errata/RHSA-2021:0053
CVE-2021-43539	1212109_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-2610	31529841_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2022-42703	76490_0	False	placeholder	placeholder	True	RHSA-2023:1091: kernel security and bug fix update (Important)	RHSA-2023:1091	https://access_redhat_com/errata/RHSA-2023:1091
CVE-2024-46751	31373264_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46751
CVE-2022-25236	71046_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2021-3156	1186734_0	False	placeholder	placeholder	True	RHSA-2021:0221: sudo security update (Important)	RHSA-2021:0221	https://access_redhat_com/errata/RHSA-2021:0221
CVE-2024-43882	7011218_0	False	placeholder	placeholder	True	USN-7120-1 -- Linux kernel vulnerabilities	USN-7120-1 -- Linux kernel vulnerabilities	https://ubuntu_com/security/CVE-2024-43882
CVE-2022-22822	70771_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2023-20593	50752_0	False	placeholder	placeholder	True	RHSA-2023:4819: kernel security and bug fix update (Important)	RHSA-2023:4819	https://access_redhat_com/errata/RHSA-2023:4819
CVE-2025-0242	34841460_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2024-46832	24837513_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46832
CVE-2022-21294	70861_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2024-45007	7008805_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45007
CVE-2023-5129	159211_0	False	placeholder	placeholder	True	RHSA-2023:5197: firefox security update (Important)	RHSA-2023:5197	https://access_redhat_com/errata/RHSA-2023:5197
CVE-2022-46342	1263245_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2023-24329	1057274_0	False	placeholder	placeholder	True	RHSA-2023:3555: python security update (Important)	RHSA-2023:3555	https://access_redhat_com/errata/RHSA-2023:3555
CVE-2021-42574	1167873_0	False	placeholder	placeholder	True	RHSA-2021:4595: binutils security update (Moderate)	RHSA-2021:4595	https://access_redhat_com/errata/RHSA-2021:4595
CVE-2024-46811	31579422_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46811
CVE-2022-34484	1264229_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2020-15659	1233738_0	False	placeholder	placeholder	True	RHSA-2020:3253: firefox security update (Important)	RHSA-2020:3253	https://access_redhat_com/errata/RHSA-2020:3253
CVE-2024-44935	6467877_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44935
CVE-2024-46725	20353371_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46725
CVE-2022-31742	240372_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2021-31291	55029_0	False	placeholder	placeholder	True	RHSA-2021:3233: compat-exiv2-026 security update (Important)	RHSA-2021:3233	https://access_redhat_com/errata/RHSA-2021:3233
CVE-2021-21424	167045_0	False	placeholder	placeholder	True	USN-5290-1 -- Symfony vulnerabilities	USN-5290-1 -- Symfony vulnerabilities	https://ubuntu_com/security/CVE-2021-21424
CVE-2024-40983	31556965_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2016-4658	83497_0	True	2123-12-31	placeholder	True	RHSA-2021:3810: libxml2 security update (Moderate)	RHSA-2021:3810	https://access_redhat_com/errata/RHSA-2021:3810
CVE-2024-43911	6466882_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43911
CVE-2024-21068	171700_0	False	placeholder	placeholder	True	RHSA-2024:1817: java-1_8_0-openjdk security update (Moderate)	RHSA-2024:1817	https://access_redhat_com/errata/RHSA-2024:1817
CVE-2020-15654	209444_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-31578	31539035_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2024-31578
CVE-2024-42317	4142949_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42317
CVE-2024-44982	31397380_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44982
CVE-2024-44950	28877957_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44950
CVE-2020-0465	70093_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2023-3776	1097351_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-46691	15016429_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46691
CVE-2024-26924	25469084_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-20945	225351_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2024-44978	11668443_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44978
CVE-2020-7053	1142948_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2024-46782	22144338_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46782
CVE-2024-43830	4143439_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43830
CVE-2024-10464	31593718_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2020-28374	1049412_0	False	placeholder	placeholder	True	RHSA-2021:0862: kpatch-patch security update (Important)	RHSA-2021:0862	https://access_redhat_com/errata/RHSA-2021:0862
CVE-2024-12747	34829160_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12747
CVE-2024-0753	100174_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2018-19970	59953_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2018-19970
CVE-2022-21443	73318_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2022-22756	1264083_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2024-0229	1204571_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2021-29970	1083633_0	False	placeholder	placeholder	True	RHSA-2021:2741: firefox security update (Important)	RHSA-2021:2741	https://access_redhat_com/errata/RHSA-2021:2741
CVE-2024-46842	31579458_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46842
CVE-2023-42753	1184365_0	False	placeholder	placeholder	True	RHSA-2024:0346: kernel security and bug fix update (Important)	RHSA-2024:0346	https://access_redhat_com/errata/RHSA-2024:0346
CVE-2022-22754	240272_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2024-42285	4142461_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42285
CVE-2019-11756	1142666_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2023-5176	159460_0	False	placeholder	placeholder	True	RHSA-2023:5477: firefox security update (Important)	RHSA-2023:5477	https://access_redhat_com/errata/RHSA-2023:5477
CVE-2024-47658	31582508_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47658
CVE-2021-38501	1168034_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2022-26384	240286_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2024-46819	24837511_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46819
CVE-2024-47667	31582528_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47667
CVE-2024-0741	100162_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2024-46860	26164379_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46860
CVE-2024-24968	17652881_0	False	placeholder	placeholder	True	USN-7149-1 -- Intel Microcode vulnerabilities	USN-7149-1 -- Intel Microcode vulnerabilities	https://ubuntu_com/security/CVE-2024-24968
CVE-2024-9341	25365419_0	False	placeholder	placeholder	True	RHSA-2024:8846: container-tools:rhel8 security update (Important)	RHSA-2024:8846	https://access_redhat_com/errata/RHSA-2024:8846
CVE-2024-43886	6467725_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43886
CVE-2022-40959	240483_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2024-20919	180522_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2022-42896	1222024_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2022-31160	253264_0	False	placeholder	placeholder	True	USN-5181-1 -- jQuery UI vulnerability	USN-5181-1 -- jQuery UI vulnerability	https://ubuntu_com/security/CVE-2022-31160
CVE-2024-10462	31593716_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2020-12825	1158867_0	False	placeholder	placeholder	True	RHSA-2020:4072: libcroco security update (Moderate)	RHSA-2020:4072	https://access_redhat_com/errata/RHSA-2020:4072
CVE-2024-47778	28884294_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47778
CVE-2022-38476	1264242_0	False	placeholder	placeholder	True	RHSA-2022:6179: firefox security update (Important)	RHSA-2022:6179	https://access_redhat_com/errata/RHSA-2022:6179
CVE-2024-46854	31579469_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46854
CVE-2019-19617	52416_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2019-19617
CVE-2021-43538	187437_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2023-37201	1224512_0	False	placeholder	placeholder	True	RHSA-2023:4079: firefox security update (Important)	RHSA-2023:4079	https://access_redhat_com/errata/RHSA-2023:4079
CVE-2022-27635	31487514_0	False	placeholder	placeholder	True	RHSA-2024:3939: linux-firmware security update (Important)	RHSA-2024:3939	https://access_redhat_com/errata/RHSA-2024:3939
CVE-2023-22809	1220906_0	False	placeholder	placeholder	True	RHSA-2023:0291: sudo security update (Important)	RHSA-2023:0291	https://access_redhat_com/errata/RHSA-2023:0291
CVE-2022-2588	31513934_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2024-21885	1206227_0	False	placeholder	placeholder	True	RHSA-2024:0629: tigervnc security update (Important)	RHSA-2024:0629	https://access_redhat_com/errata/RHSA-2024:0629
CVE-2024-46707	31578101_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46707
CVE-2020-12364	128678_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2021-32810	55638_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2024-42315	4919874_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42315
CVE-2022-22823	70774_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-46685	15537753_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46685
CVE-2024-5700	31552042_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2024-44965	31571541_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44965
CVE-2024-50264	28879214_0	False	placeholder	placeholder	True	USN-7167-2 -- Linux kernel vulnerabilities	USN-7167-2 -- Linux kernel vulnerabilities	https://ubuntu_com/security/CVE-2024-50264
CVE-2024-47834	28884295_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47834
CVE-2024-43852	31374237_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43852
CVE-2023-35001	1224562_0	False	placeholder	placeholder	True	RHSA-2023:5622: kernel security and bug fix update (Important)	RHSA-2023:5622	https://access_redhat_com/errata/RHSA-2023:5622
CVE-2020-35513	161586_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2024-46715	18365416_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46715
CVE-2021-27365	1111562_0	False	placeholder	placeholder	True	RHSA-2021:1071: kernel security and bug fix update (Important)	RHSA-2021:1071	https://access_redhat_com/errata/RHSA-2021:1071
CVE-2021-20277	1039699_0	False	placeholder	placeholder	True	RHSA-2021:1072: libldb security update (Important)	RHSA-2021:1072	https://access_redhat_com/errata/RHSA-2021:1072
CVE-2022-23468	31406704_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23468
CVE-2024-46836	31429817_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46836
CVE-2022-34470	240406_0	False	placeholder	placeholder	True	RHSA-2022:5479: firefox security update (Important)	RHSA-2022:5479	https://access_redhat_com/errata/RHSA-2022:5479
CVE-2020-14410	161142_0	False	placeholder	placeholder	True	USN-5274-1 -- Simple DirectMedia Layer vulnerabilities	USN-5274-1 -- Simple DirectMedia Layer vulnerabilities	https://ubuntu_com/security/CVE-2020-14410
CVE-2020-10769	207672_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2024-46855	26164466_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46855
CVE-2024-45029	15016314_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45029
CVE-2024-39503	31556878_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-25744	1124862_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2020-14363	1123613_0	False	placeholder	placeholder	True	RHSA-2020:4908: libX11 security update (Important)	RHSA-2020:4908	https://access_redhat_com/errata/RHSA-2020:4908
CVE-2023-0494	1107283_0	False	placeholder	placeholder	True	RHSA-2023:0675: tigervnc and xorg-x11-server security update (Important)	RHSA-2023:0675	https://access_redhat_com/errata/RHSA-2023:0675
CVE-2024-42290	4142575_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42290
CVE-2023-52918	31592435_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2023-52918
CVE-2021-43536	187434_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-45009	15016249_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45009
CVE-2021-38506	187421_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2022-22825	1082475_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-42279	4142357_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42279
CVE-2024-42262	4141800_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42262
CVE-2020-11668	1068736_0	False	placeholder	placeholder	True	RHSA-2021:2725: kernel security and bug fix update (Important)	RHSA-2021:2725	https://access_redhat_com/errata/RHSA-2021:2725
CVE-2018-25032	1086329_0	False	placeholder	placeholder	True	RHSA-2022:2213: zlib security update (Important)	RHSA-2022:2213	https://access_redhat_com/errata/RHSA-2022:2213
CVE-2021-29989	1219883_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2024-43833	4919878_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43833
CVE-2022-4883	1056257_0	False	placeholder	placeholder	True	RHSA-2023:0377: libXpm security update (Important)	RHSA-2023:0377	https://access_redhat_com/errata/RHSA-2023:0377
CVE-2022-23816	91296_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2024-46767	18366290_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46767
CVE-2022-25315	71050_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2021-3421	7956_0	False	placeholder	placeholder	True	USN-5273-1 -- RPM Package Manager vulnerabilities	USN-5273-1 -- RPM Package Manager vulnerabilities	https://ubuntu_com/security/CVE-2021-3421
CVE-2024-1551	31524689_0	False	placeholder	placeholder	True	RHSA-2024:0976: firefox security update (Important)	RHSA-2024:0976	https://access_redhat_com/errata/RHSA-2024:0976
CVE-2020-36558	253269_0	False	placeholder	placeholder	True	RHSA-2024:2004: kernel security and bug fix update (Important)	RHSA-2024:2004	https://access_redhat_com/errata/RHSA-2024:2004
CVE-2024-46835	24837525_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46835
CVE-2022-46880	240548_0	False	placeholder	placeholder	True	RHSA-2022:9072: firefox security update (Important)	RHSA-2022:9072	https://access_redhat_com/errata/RHSA-2022:9072
CVE-2021-3621	1188252_0	False	placeholder	placeholder	True	RHSA-2021:3336: sssd security and bug fix update (Important)	RHSA-2021:3336	https://access_redhat_com/errata/RHSA-2021:3336
CVE-2025-0243	34841461_0	False	placeholder	placeholder	True	RHSA-2025:0144: firefox security update (Important)	RHSA-2025:0144	https://access_redhat_com/errata/RHSA-2025:0144
CVE-2020-35513	161586_0	False	placeholder	placeholder	True	RHSA-2021:0336: kernel security	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2023-6865	4234_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2023-50868	180266_0	False	placeholder	placeholder	True	and dhcp security update (Important)	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2024-44958	31571535_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44958
CVE-2021-20305	1074614_0	False	placeholder	placeholder	True	RHSA-2021:1145: nettle security update (Important)	RHSA-2021:1145	https://access_redhat_com/errata/RHSA-2021:1145
CVE-2024-43854	4919887_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43854
CVE-2024-4453	31548416_0	False	placeholder	placeholder	True	RHSA-2024:9056: gstreamer1-plugins-base security update (Moderate)	RHSA-2024:9056	https://access_redhat_com/errata/RHSA-2024:9056
CVE-2024-35839	31547465_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-9675	25365464_0	False	placeholder	placeholder	True	RHSA-2024:8846: container-tools:rhel8 security update (Important)	RHSA-2024:8846	https://access_redhat_com/errata/RHSA-2024:8846
CVE-2021-43534	1212103_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2019-9674	1068321_0	False	placeholder	placeholder	True	USN-7212-1 -- Python 2_7 vulnerabilities	USN-7212-1 -- Python 2_7 vulnerabilities	https://ubuntu_com/security/CVE-2019-9674
CVE-2024-47600	28884280_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47600
CVE-2024-42268	4141939_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42268
CVE-2022-2964	1229307_0	False	placeholder	placeholder	True	RHSA-2023:0399: kernel security and bug fix update (Important)	RHSA-2023:0399	https://access_redhat_com/errata/RHSA-2023:0399
CVE-2022-45061	1038105_0	False	placeholder	placeholder	True	USN-7212-1 -- Python 2_7 vulnerabilities	USN-7212-1 -- Python 2_7 vulnerabilities	https://ubuntu_com/security/CVE-2022-45061
CVE-2024-40866	22702129_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2021-25215	1075816_0	False	placeholder	placeholder	True	RHSA-2021:1469: bind security update (Important)	RHSA-2021:1469	https://access_redhat_com/errata/RHSA-2021:1469
CVE-2021-27803	1074239_0	False	placeholder	placeholder	True	RHSA-2021:0808: wpa_supplicant security update (Important)	RHSA-2021:0808	https://access_redhat_com/errata/RHSA-2021:0808
CVE-2021-0920	187865_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2023-4408	1208044_0	False	placeholder	placeholder	True	RHSA-2024:3741: bind	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2024-47175	22676313_0	False	placeholder	placeholder	True	RHSA-2025:0083: cups security update (Low)	RHSA-2025:0083	https://access_redhat_com/errata/RHSA-2025:0083
CVE-2021-4127	240194_0	False	placeholder	placeholder	True	RHSA-2021:0992: firefox security update (Important)	RHSA-2021:0992	https://access_redhat_com/errata/RHSA-2021:0992
CVE-2023-49502	31539332_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-49502
CVE-2021-30547	1193877_0	False	placeholder	placeholder	True	RHSA-2021:2741: firefox security update (Important)	RHSA-2021:2741	https://access_redhat_com/errata/RHSA-2021:2741
CVE-2024-47599	28884279_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47599
CVE-2023-50387	1096636_0	False	placeholder	placeholder	True	bind-dyndb-ldap	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2023-35788	1126098_0	False	placeholder	placeholder	True	RHSA-2023:4819: kernel security and bug fix update (Important)	RHSA-2023:4819	https://access_redhat_com/errata/RHSA-2023:4819
CVE-2023-5732	144121_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2021-33909	1111689_0	False	placeholder	placeholder	True	RHSA-2021:2727: kpatch-patch security update (Important)	RHSA-2021:2727	https://access_redhat_com/errata/RHSA-2021:2727
CVE-2023-51794	31540093_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-51794
CVE-2020-15677	71682_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2021-21381	1207437_0	False	placeholder	placeholder	True	RHSA-2021:1002: flatpak security update (Important)	RHSA-2021:1002	https://access_redhat_com/errata/RHSA-2021:1002
CVE-2024-42296	4142736_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42296
CVE-2021-23960	1139603_0	False	placeholder	placeholder	True	RHSA-2021:0290: firefox security update (Important)	RHSA-2021:0290	https://access_redhat_com/errata/RHSA-2021:0290
CVE-2024-46766	22144314_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46766
CVE-2022-22743	240260_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2021-3246	1081143_0	False	placeholder	placeholder	True	RHSA-2021:3295: libsndfile security update (Important)	RHSA-2021:3295	https://access_redhat_com/errata/RHSA-2021:3295
CVE-2024-46679	22180887_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46679
CVE-2024-44244	28878058_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-44960	31571537_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44960
CVE-2024-44969	31571542_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44969
CVE-2021-22555	1194746_0	False	placeholder	placeholder	True	RHSA-2021:3381: kpatch-patch security update (Important)	RHSA-2021:3381	https://access_redhat_com/errata/RHSA-2021:3381
CVE-2020-36322	127618_0	False	placeholder	placeholder	True	RHSA-2022:0063: kernel security and bug fix update (Moderate)	RHSA-2022:0063	https://access_redhat_com/errata/RHSA-2022:0063
CVE-2022-40964	31487530_0	False	placeholder	placeholder	True	RHSA-2024:3939: linux-firmware security update (Important)	RHSA-2024:3939	https://access_redhat_com/errata/RHSA-2024:3939
CVE-2024-45000	7028942_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45000
CVE-2024-46772	22182367_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46772
CVE-2024-44966	31397360_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44966
CVE-2024-5691	31551983_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2021-43535	1212104_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2022-21426	73031_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2022-22763	1264090_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2021-20266	166418_0	False	placeholder	placeholder	True	USN-5273-1 -- RPM Package Manager vulnerabilities	USN-5273-1 -- RPM Package Manager vulnerabilities	https://ubuntu_com/security/CVE-2021-20266
CVE-2023-5169	159453_0	False	placeholder	placeholder	True	RHSA-2023:5477: firefox security update (Important)	RHSA-2023:5477	https://access_redhat_com/errata/RHSA-2023:5477
CVE-2020-24512	168492_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2022-28285	240346_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2023-32206	98314_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2024-4367	207488_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2024-46871	31582507_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46871
CVE-2024-10461	31593715_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2022-24713	1061352_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2024-3857	31555341_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2024-43867	31568828_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43867
CVE-2024-46778	31578946_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46778
CVE-2024-44975	31397123_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44975
CVE-2024-42289	7008479_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42289
CVE-2023-40547	1126938_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2024-43818	7011181_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43818
CVE-2024-50602	26164373_0	False	placeholder	placeholder	True	USN-7145-1 -- Expat vulnerability	USN-7145-1 -- Expat vulnerability	https://ubuntu_com/security/CVE-2024-50602
CVE-2017-1000014	1237181_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2017-1000014
CVE-2024-32230	4919764_0	False	placeholder	placeholder	True	USN-6983-1 -- FFmpeg vulnerability	USN-6983-1 -- FFmpeg vulnerability	https://ubuntu_com/security/CVE-2024-32230
CVE-2024-31083	1195065_0	False	placeholder	placeholder	True	RHSA-2024:2080: tigervnc security update (Important)	RHSA-2024:2080	https://access_redhat_com/errata/RHSA-2024:2080
CVE-2023-5367	1240164_0	False	placeholder	placeholder	True	RHSA-2023:6802: xorg-x11-server security update (Important)	RHSA-2023:6802	https://access_redhat_com/errata/RHSA-2023:6802
CVE-2024-46738	20353407_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46738
CVE-2023-23602	98256_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2022-1529	1264017_0	False	placeholder	placeholder	True	RHSA-2022:4729: firefox security update (Critical)	RHSA-2022:4729	https://access_redhat_com/errata/RHSA-2022:4729
CVE-2022-31738	240368_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2020-26961	24290_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2024-46757	22144272_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46757
CVE-2020-12402	208149_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2023-2002	97634_0	False	placeholder	placeholder	True	RHSA-2024:2004: kernel security and bug fix update (Important)	RHSA-2024:2004	https://access_redhat_com/errata/RHSA-2024:2004
CVE-2024-44990	7028925_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44990
CVE-2023-32211	98316_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2021-20197	126675_0	False	placeholder	placeholder	True	RHSA-2021:4364: binutils security update (Moderate)	RHSA-2021:4364	https://access_redhat_com/errata/RHSA-2021:4364
CVE-2024-46676	22180883_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46676
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2021-29980	1093949_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2022-45405	240495_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2021-43543	187442_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2022-3564	31391897_0	False	placeholder	placeholder	True	RHSA-2023:4151: kernel security and bug fix update (Important)	RHSA-2023:4151	https://access_redhat_com/errata/RHSA-2023:4151
CVE-2024-45015	15016270_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45015
CVE-2016-9849	193741_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2016-9849
CVE-2024-46702	31372348_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46702
CVE-2022-29912	240354_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2024-44309	28879234_0	False	placeholder	placeholder	True	USN-7142-1 -- WebKitGTK vulnerabilities	USN-7142-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-44309
CVE-2023-44488	1184871_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2023-25155	68269_0	False	placeholder	placeholder	True	USN-6531-1 -- Redis vulnerabilities	USN-6531-1 -- Redis vulnerabilities	https://ubuntu_com/security/CVE-2023-25155
CVE-2024-45018	15016273_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45018
CVE-2021-29945	169464_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2019-6798	219614_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2019-6798
CVE-2024-41042	31563116_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-23852	70870_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-44187	31578846_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2021-24002	1194296_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2022-21434	73107_0	False	placeholder	placeholder	True	bug fix	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-46755	22702628_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46755
CVE-2021-3598	169891_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-3598
CVE-2024-46815	31579426_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46815
CVE-2022-40674	1100911_0	False	placeholder	placeholder	True	RHSA-2022:6834: expat security update (Important)	RHSA-2022:6834	https://access_redhat_com/errata/RHSA-2022:6834
CVE-2019-17006	72830_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-35113	1052109_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2022-29914	240356_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2024-43825	31373158_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43825
CVE-2024-44984	31427740_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44984
CVE-2020-12351	1227360_0	False	placeholder	placeholder	True	RHSA-2020:4276: kernel security update (Important)	RHSA-2020:4276	https://access_redhat_com/errata/RHSA-2020:4276
CVE-2020-24511	168491_0	False	placeholder	placeholder	True	RHSA-2021:2305: microcode_ctl security	RHSA-2021:2305	https://access_redhat_com/errata/RHSA-2021:2305
CVE-2018-25011	167450_0	False	placeholder	placeholder	True	RHSA-2021:2260: libwebp security update (Important)	RHSA-2021:2260	https://access_redhat_com/errata/RHSA-2021:2260
CVE-2021-35561	141914_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2024-11168	28878166_0	False	placeholder	placeholder	True	USN-7218-1 -- Python vulnerability	USN-7218-1 -- Python vulnerability	https://ubuntu_com/security/CVE-2024-11168
CVE-2024-43859	4919895_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43859
CVE-2020-26956	24227_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2024-46847	24837530_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46847
CVE-2023-25739	1124855_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2022-4285	31214_0	False	placeholder	placeholder	True	RHSA-2023:6236: binutils security update (Moderate)	RHSA-2023:6236	https://access_redhat_com/errata/RHSA-2023:6236
CVE-2020-14364	95667_0	False	placeholder	placeholder	True	RHSA-2020:4079: qemu-kvm security update (Important)	RHSA-2020:4079	https://access_redhat_com/errata/RHSA-2020:4079
CVE-2024-45002	7028944_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45002
CVE-2023-34416	199012_0	False	placeholder	placeholder	True	RHSA-2023:3579: firefox security update (Important)	RHSA-2023:3579	https://access_redhat_com/errata/RHSA-2023:3579
CVE-2022-21283	230687_0	False	placeholder	placeholder	True	RHSA-2022:0306: java-1_8_0-openjdk security update (Moderate)	RHSA-2022:0306	https://access_redhat_com/errata/RHSA-2022:0306
CVE-2024-44308	27543033_0	False	placeholder	placeholder	True	USN-7142-1 -- WebKitGTK vulnerabilities	USN-7142-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-44308
CVE-2024-46750	31373263_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46750
CVE-2021-38091	1245684_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-38091
CVE-2024-12086	34829058_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12086
CVE-2024-46693	15016432_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46693
CVE-2023-4047	1077610_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2024-52006	34839163_0	False	placeholder	placeholder	True	USN-7207-1 -- Git vulnerabilities	USN-7207-1 -- Git vulnerabilities	https://ubuntu_com/security/CVE-2024-52006
CVE-2020-12400	71967_0	False	placeholder	placeholder	True	RHSA-2020:4076: nss and nspr security	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-42276	4142298_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42276
CVE-2024-27851	31551877_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-46864	26164381_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46864
CVE-2024-46744	31578923_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46744
CVE-2020-25705	1154848_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2021-4155	70378_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2024-44957	7028922_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44957
CVE-2023-21967	227145_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2021-22543	1192544_0	False	placeholder	placeholder	True	RHSA-2021:3801: kernel security and bug fix update (Important)	RHSA-2021:3801	https://access_redhat_com/errata/RHSA-2021:3801
CVE-2020-35111	29674_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2020-35513	161586_0	False	placeholder	placeholder	True	bug fix	RHSA-2021:0336	https://access_redhat_com/errata/RHSA-2021:0336
CVE-2023-6859	1027489_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-46673	15016354_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46673
CVE-2021-20233	1074411_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2024-41093	7008920_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-22761	1264088_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2024-42259	14530148_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42259
CVE-2024-3596	32871723_0	False	placeholder	placeholder	True	RHSA-2024:8860: krb5 security update (Important)	RHSA-2024:8860	https://access_redhat_com/errata/RHSA-2024:8860
CVE-2023-29539	1124886_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2023-1999	31480887_0	False	placeholder	placeholder	True	RHSA-2023:2077: libwebp security update (Important)	RHSA-2023:2077	https://access_redhat_com/errata/RHSA-2023:2077
CVE-2022-38076	31487525_0	False	placeholder	placeholder	True	RHSA-2024:3939: linux-firmware security update (Important)	RHSA-2024:3939	https://access_redhat_com/errata/RHSA-2024:3939
CVE-2021-3564	168247_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2024-46834	31579449_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46834
CVE-2024-46708	31372355_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46708
CVE-2023-4575	145832_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2024-44986	7008789_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44986
CVE-2024-10465	31593719_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2020-36385	1193091_0	False	placeholder	placeholder	True	RHSA-2021:4777: kernel security and bug fix update (Important)	RHSA-2021:4777	https://access_redhat_com/errata/RHSA-2021:4777
CVE-2020-27170	114103_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2020-10543	1144323_0	False	placeholder	placeholder	True	RHSA-2021:0343: perl security update (Moderate)	RHSA-2021:0343	https://access_redhat_com/errata/RHSA-2021:0343
CVE-2022-46343	1263246_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2023-6478	1025980_0	False	placeholder	placeholder	True	RHSA-2024:0009: xorg-x11-server security update (Important)	RHSA-2024:0009	https://access_redhat_com/errata/RHSA-2024:0009
CVE-2024-44971	7008749_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44971
CVE-2022-28281	1264134_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2023-4046	51305_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2023-3600	1071122_0	False	placeholder	placeholder	True	RHSA-2023:5477: firefox security update (Important)	RHSA-2023:5477	https://access_redhat_com/errata/RHSA-2023:5477
CVE-2016-6630	193735_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2016-6630
CVE-2023-20593	50752_0	False	placeholder	placeholder	True	RHSA-2023:7513: linux-firmware security update (Moderate)	RHSA-2023:7513	https://access_redhat_com/errata/RHSA-2023:7513
CVE-2024-43821	7011184_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43821
CVE-2021-2163	127993_0	False	placeholder	placeholder	True	RHSA-2021:1298: java-1_8_0-openjdk security update (Moderate)	RHSA-2021:1298	https://access_redhat_com/errata/RHSA-2021:1298
CVE-2024-40779	31563321_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-4769	31546761_0	False	placeholder	placeholder	True	RHSA-2024:2881: firefox security update (Important)	RHSA-2024:2881	https://access_redhat_com/errata/RHSA-2024:2881
CVE-2024-42314	4919873_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42314
CVE-2021-3487	188588_0	False	placeholder	placeholder	True	RHSA-2021:4364: binutils security update (Moderate)	RHSA-2021:4364	https://access_redhat_com/errata/RHSA-2021:4364
CVE-2020-0466	1098245_0	False	placeholder	placeholder	True	RHSA-2022:0620: kernel security and bug fix update (Important)	RHSA-2022:0620	https://access_redhat_com/errata/RHSA-2022:0620
CVE-2024-5688	31551980_0	False	placeholder	placeholder	True	RHSA-2024:3951: firefox security update (Important)	RHSA-2024:3951	https://access_redhat_com/errata/RHSA-2024:3951
CVE-2023-37207	200056_0	False	placeholder	placeholder	True	RHSA-2023:4079: firefox security update (Important)	RHSA-2023:4079	https://access_redhat_com/errata/RHSA-2023:4079
CVE-2024-47539	28884267_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47539
CVE-2020-26965	24438_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2020-13428	1146552_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2020-13428
CVE-2023-0996	1169485_0	False	placeholder	placeholder	True	USN-6847-1 -- libheif vulnerabilities	USN-6847-1 -- libheif vulnerabilities	https://ubuntu_com/security/CVE-2023-0996
CVE-2021-29946	1194301_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2023-25730	98263_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2021-27364	1074490_0	False	placeholder	placeholder	True	RHSA-2021:1069: kpatch-patch security update (Important)	RHSA-2021:1069	https://access_redhat_com/errata/RHSA-2021:1069
CVE-2023-3899	1092685_0	False	placeholder	placeholder	True	RHSA-2023:4701: subscription-manager security update (Moderate)	RHSA-2023:4701	https://access_redhat_com/errata/RHSA-2023:4701
CVE-2021-26401	133860_0	False	placeholder	placeholder	True	RHSA-2023:0399: kernel security and bug fix update (Important)	RHSA-2023:0399	https://access_redhat_com/errata/RHSA-2023:0399
CVE-2024-20926	99676_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2021-44142	1069900_0	False	placeholder	placeholder	True	RHSA-2022:0328: samba security and bug fix update (Critical)	RHSA-2022:0328	https://access_redhat_com/errata/RHSA-2022:0328
CVE-2020-25211	95997_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2022-1271	1100416_0	False	placeholder	placeholder	True	RHSA-2022:2191: gzip security update (Important)	RHSA-2022:2191	https://access_redhat_com/errata/RHSA-2022:2191
CVE-2024-46692	15016431_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46692
CVE-2020-15653	209443_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-44185	31593037_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2020-15676	71681_0	False	placeholder	placeholder	True	RHSA-2020:4080: firefox security and bug fix update (Important)	RHSA-2020:4080	https://access_redhat_com/errata/RHSA-2020:4080
CVE-2024-42281	4142403_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42281
CVE-2021-35565	141920_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2021-33909	1111689_0	False	placeholder	placeholder	True	RHSA-2021:2725: kernel security and bug fix update (Important)	RHSA-2021:2725	https://access_redhat_com/errata/RHSA-2021:2725
CVE-2024-20952	1126276_0	False	placeholder	placeholder	True	RHSA-2024:0223: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2024:0223	https://access_redhat_com/errata/RHSA-2024:0223
CVE-2023-25743	1124861_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-44990	7028925_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2018-7260	131515_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2018-7260
CVE-2022-48565	63408_0	False	placeholder	placeholder	True	USN-7180-1 -- Python vulnerabilities	USN-7180-1 -- Python vulnerabilities	https://ubuntu_com/security/CVE-2022-48565
CVE-2021-23981	1152509_0	False	placeholder	placeholder	True	RHSA-2021:0992: firefox security update (Important)	RHSA-2021:0992	https://access_redhat_com/errata/RHSA-2021:0992
CVE-2023-25732	1124850_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-44998	7028940_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44998
CVE-2024-43880	31568844_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-46721	20353348_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46721
CVE-2023-5217	1090228_0	False	placeholder	placeholder	True	RHSA-2023:5477: firefox security update (Important)	RHSA-2023:5477	https://access_redhat_com/errata/RHSA-2023:5477
CVE-2024-46802	24837517_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46802
CVE-2022-43552	68109_0	False	placeholder	placeholder	True	RHSA-2023:7743: curl security update (Low)	RHSA-2023:7743	https://access_redhat_com/errata/RHSA-2023:7743
CVE-2022-40962	1264295_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2024-46793	22729536_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46793
CVE-2024-43831	4143499_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43831
CVE-2024-10459	31593713_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2024-46752	18366174_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46752
CVE-2020-22024	18044_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22024
CVE-2024-39472	31556144_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-39472
CVE-2019-20811	255216_0	False	placeholder	placeholder	True	RHSA-2020:5023: kernel security and bug fix update (Moderate)	RHSA-2020:5023	https://access_redhat_com/errata/RHSA-2020:5023
CVE-2020-22039	167986_0	False	placeholder	placeholder	True	USN-6430-1 -- FFmpeg vulnerabilities	USN-6430-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2020-22039
CVE-2024-44961	31571538_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44961
CVE-2021-35550	45737_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2024-54502	28884451_0	False	placeholder	placeholder	True	USN-7201-1 -- WebKitGTK vulnerabilities	USN-7201-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-54502
CVE-2022-46344	1263248_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2021-38504	1212090_0	False	placeholder	placeholder	True	RHSA-2021:4116: firefox security update (Important)	RHSA-2021:4116	https://access_redhat_com/errata/RHSA-2021:4116
CVE-2024-43905	6467771_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43905
CVE-2022-21541	253194_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2022-4378	1096938_0	False	placeholder	placeholder	True	RHSA-2023:1091: kernel security and bug fix update (Important)	RHSA-2023:1091	https://access_redhat_com/errata/RHSA-2023:1091
CVE-2023-20592	111356_0	False	placeholder	placeholder	True	RHSA-2024:0753: linux-firmware security update (Moderate)	RHSA-2024:0753	https://access_redhat_com/errata/RHSA-2024:0753
CVE-2024-38608	6467174_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2019-11719	1123261_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2023-25729	1124847_0	False	placeholder	placeholder	True	RHSA-2023:0812: firefox security update (Important)	RHSA-2023:0812	https://access_redhat_com/errata/RHSA-2023:0812
CVE-2024-43883	31569109_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43883
CVE-2022-26486	240313_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2024-43876	31568840_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43876
CVE-2023-6208	1138328_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2024-46817	31579430_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46817
CVE-2024-21885	1206227_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2023-40551	100588_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2024-12085	34829026_0	False	placeholder	placeholder	True	RHSA-2025:0325: rsync security update (Important)	RHSA-2025:0325	https://access_redhat_com/errata/RHSA-2025:0325
CVE-2023-5724	1169350_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2023-21937	227124_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2024-46828	31579443_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46828
CVE-2024-45022	15016285_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45022
CVE-2021-29154	1075752_0	False	placeholder	placeholder	True	RHSA-2021:3327: kernel security and bug fix update (Important)	RHSA-2021:3327	https://access_redhat_com/errata/RHSA-2021:3327
CVE-2022-36318	240427_0	False	placeholder	placeholder	True	RHSA-2022:5776: firefox security update (Important)	RHSA-2022:5776	https://access_redhat_com/errata/RHSA-2022:5776
CVE-2024-47668	31582529_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-38473	1264240_0	False	placeholder	placeholder	True	RHSA-2022:6179: firefox security update (Important)	RHSA-2022:6179	https://access_redhat_com/errata/RHSA-2022:6179
CVE-2024-46759	22182326_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46759
CVE-2023-50010	31539335_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-50010
CVE-2021-33516	1192448_0	False	placeholder	placeholder	True	RHSA-2021:2417: gupnp security update (Important)	RHSA-2021:2417	https://access_redhat_com/errata/RHSA-2021:2417
CVE-2022-0492	1086184_0	False	placeholder	placeholder	True	RHSA-2022:4642: kernel security and bug fix update (Important)	RHSA-2022:4642	https://access_redhat_com/errata/RHSA-2022:4642
CVE-2024-26976	25391557_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2019-12900	6466_0	False	placeholder	placeholder	True	RHSA-2024:8922: bzip2 security update (Low)	RHSA-2024:8922	https://access_redhat_com/errata/RHSA-2024:8922
CVE-2024-42284	4142455_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42284
CVE-2024-46779	22144332_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46779
CVE-2021-43527	187426_0	False	placeholder	placeholder	True	RHSA-2021:4904: nss security update (Critical)	RHSA-2021:4904	https://access_redhat_com/errata/RHSA-2021:4904
CVE-2022-25315	71050_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2022-31736	240366_0	False	placeholder	placeholder	True	RHSA-2022:4870: firefox security update (Important)	RHSA-2022:4870	https://access_redhat_com/errata/RHSA-2022:4870
CVE-2022-38023	1086996_0	False	placeholder	placeholder	True	RHSA-2023:1090: samba security update (Important)	RHSA-2023:1090	https://access_redhat_com/errata/RHSA-2023:1090
CVE-2023-6863	1027492_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2024-46754	18366190_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46754
CVE-2024-43893	11641792_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43893
CVE-2020-12321	1278085_0	False	placeholder	placeholder	True	RHSA-2021:0339: linux-firmware security update (Important)	RHSA-2021:0339	https://access_redhat_com/errata/RHSA-2021:0339
CVE-2022-22824	70775_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2023-45871	1125330_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2024-46777	31578945_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46777
CVE-2023-32213	1124904_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2023-6207	1138327_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2024-46678	22143722_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46678
CVE-2022-40982	62485_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-44935	6467877_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-52492	31528685_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-26968	1258395_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
CVE-2022-23484	31406714_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23484
CVE-2024-36617	28879616_0	False	placeholder	placeholder	True	USN-7188-1 -- FFmpeg vulnerability	USN-7188-1 -- FFmpeg vulnerability	https://ubuntu_com/security/CVE-2024-36617
CVE-2021-4011	1212725_0	False	placeholder	placeholder	True	RHSA-2022:0003: xorg-x11-server security update (Important)	RHSA-2022:0003	https://access_redhat_com/errata/RHSA-2022:0003
CVE-2024-40780	31563322_0	False	placeholder	placeholder	True	RHSA-2024:9636: webkit2gtk3 security update (Important)	RHSA-2024:9636	https://access_redhat_com/errata/RHSA-2024:9636
CVE-2024-12088	34829156_0	False	placeholder	placeholder	True	USN-7206-1 -- rsync vulnerabilities	USN-7206-1 -- rsync vulnerabilities	https://ubuntu_com/security/CVE-2024-12088
CVE-2024-45028	15016313_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45028
CVE-2022-28733	1076673_0	False	placeholder	placeholder	True	RHSA-2022:8900: grub2 security update (Important)	RHSA-2022:8900	https://access_redhat_com/errata/RHSA-2022:8900
CVE-2023-37202	1224513_0	False	placeholder	placeholder	True	RHSA-2023:4079: firefox security update (Important)	RHSA-2023:4079	https://access_redhat_com/errata/RHSA-2023:4079
CVE-2024-10460	31593714_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2022-38177	1101081_0	False	placeholder	placeholder	True	RHSA-2022:6765: bind security update (Important)	RHSA-2022:6765	https://access_redhat_com/errata/RHSA-2022:6765
CVE-2022-40960	240484_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2024-43840	31373345_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43840
CVE-2020-12362	1139247_0	False	placeholder	placeholder	True	RHSA-2021:2314: kernel security and bug fix update (Important)	RHSA-2021:2314	https://access_redhat_com/errata/RHSA-2021:2314
CVE-2016-6609	1218215_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2016-6609
CVE-2023-4408	1208044_0	False	placeholder	placeholder	True	bind-dyndb-ldap	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2021-29967	1194321_0	False	placeholder	placeholder	True	RHSA-2021:2206: firefox security update (Important)	RHSA-2021:2206	https://access_redhat_com/errata/RHSA-2021:2206
CVE-2024-46713	15016579_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46713
CVE-2024-44944	7011248_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44944
CVE-2022-21476	1106364_0	False	placeholder	placeholder	True	RHSA-2022:1487: java-1_8_0-openjdk security	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-31083	1195065_0	False	placeholder	placeholder	True	RHSA-2024:1785: X_Org server security update (Important)	RHSA-2024:1785	https://access_redhat_com/errata/RHSA-2024:1785
CVE-2024-46786	31578951_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46786
CVE-2020-14318	129618_0	False	placeholder	placeholder	True	RHSA-2020:5439: samba security and bug fix update (Moderate)	RHSA-2020:5439	https://access_redhat_com/errata/RHSA-2020:5439
CVE-2024-46741	20353412_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46741
CVE-2022-2505	1264173_0	False	placeholder	placeholder	True	RHSA-2022:5776: firefox security update (Important)	RHSA-2022:5776	https://access_redhat_com/errata/RHSA-2022:5776
CVE-2022-22826	1082510_0	False	placeholder	placeholder	True	RHSA-2022:1069: expat security update (Important)	RHSA-2022:1069	https://access_redhat_com/errata/RHSA-2022:1069
CVE-2024-10467	31593723_0	False	placeholder	placeholder	True	RHSA-2024:8729: firefox security update (Moderate)	RHSA-2024:8729	https://access_redhat_com/errata/RHSA-2024:8729
CVE-2020-14372	1111557_0	False	placeholder	placeholder	True	RHSA-2021:0699: grub2 security update (Moderate)	RHSA-2021:0699	https://access_redhat_com/errata/RHSA-2021:0699
CVE-2024-46724	20353354_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46724
CVE-2021-23999	1194294_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2021-3605	65499_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-3605
CVE-2020-8695	129168_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2023-4921	1171253_0	False	placeholder	placeholder	True	RHSA-2024:1249: kernel security and bug fix update (Important)	RHSA-2024:1249	https://access_redhat_com/errata/RHSA-2024:1249
CVE-2022-48566	63409_0	False	placeholder	placeholder	True	USN-7180-1 -- Python vulnerabilities	USN-7180-1 -- Python vulnerabilities	https://ubuntu_com/security/CVE-2022-48566
CVE-2022-40956	240464_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2022-21426	73031_0	False	placeholder	placeholder	True	RHSA-2022:1487: java-1_8_0-openjdk security	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2019-19721	1159036_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2019-19721
CVE-2024-50349	34838999_0	False	placeholder	placeholder	True	USN-7207-1 -- Git vulnerabilities	USN-7207-1 -- Git vulnerabilities	https://ubuntu_com/security/CVE-2024-50349
CVE-2022-45408	240498_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2024-46804	31427724_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46804
CVE-2019-17451	93545_0	False	placeholder	placeholder	True	RHSA-2020:1797: binutils security and bug fix update (Low)	RHSA-2020:1797	https://access_redhat_com/errata/RHSA-2020:1797
CVE-2020-35448	29245_0	False	placeholder	placeholder	True	RHSA-2021:4364: binutils security update (Moderate)	RHSA-2021:4364	https://access_redhat_com/errata/RHSA-2021:4364
CVE-2022-45409	1264308_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2020-36328	167453_0	False	placeholder	placeholder	True	RHSA-2021:2260: libwebp security update (Important)	RHSA-2021:2260	https://access_redhat_com/errata/RHSA-2021:2260
CVE-2021-43546	187445_0	False	placeholder	placeholder	True	RHSA-2021:5014: firefox security update (Important)	RHSA-2021:5014	https://access_redhat_com/errata/RHSA-2021:5014
CVE-2024-46861	26164378_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46861
CVE-2024-21886	1206228_0	False	placeholder	placeholder	True	RHSA-2024:0320: xorg-x11-server security update (Important)	RHSA-2024:0320	https://access_redhat_com/errata/RHSA-2024:0320
CVE-2024-46858	31579472_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46858
CVE-2024-45005	31397409_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45005
CVE-2022-22738	1264030_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2023-5721	99743_0	False	placeholder	placeholder	True	RHSA-2023:6162: firefox security update (Important)	RHSA-2023:6162	https://access_redhat_com/errata/RHSA-2023:6162
CVE-2024-43819	7011182_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43819
CVE-2024-43902	6467758_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43902
CVE-2022-45416	240533_0	False	placeholder	placeholder	True	RHSA-2022:8552: firefox security update (Important)	RHSA-2022:8552	https://access_redhat_com/errata/RHSA-2022:8552
CVE-2022-22764	1264091_0	False	placeholder	placeholder	True	RHSA-2022:0514: firefox security update (Important)	RHSA-2022:0514	https://access_redhat_com/errata/RHSA-2022:0514
CVE-2024-46809	24837478_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46809
CVE-2023-34058	1240276_0	False	placeholder	placeholder	True	RHSA-2023:7279: open-vm-tools security update (Important)	RHSA-2023:7279	https://access_redhat_com/errata/RHSA-2023:7279
CVE-2024-45001	31571560_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45001
CVE-2024-44939	14530198_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44939
CVE-2023-40549	100586_0	False	placeholder	placeholder	True	RHSA-2024:1959: shim security update (Important)	RHSA-2024:1959	https://access_redhat_com/errata/RHSA-2024:1959
CVE-2024-46740	20353411_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46740
CVE-2021-35564	141917_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2019-1010204	96137_0	False	placeholder	placeholder	True	RHSA-2020:1797: binutils security and bug fix update (Low)	RHSA-2020:1797	https://access_redhat_com/errata/RHSA-2020:1797
CVE-2023-52889	4141764_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2023-52889
CVE-2018-12699	182475_0	False	placeholder	placeholder	True	RHSA-2024:9689: binutils security update (Low)	RHSA-2024:9689	https://access_redhat_com/errata/RHSA-2024:9689
CVE-2023-21843	196355_0	False	placeholder	placeholder	True	RHSA-2023:0203: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2023:0203	https://access_redhat_com/errata/RHSA-2023:0203
CVE-2023-6856	1027486_0	False	placeholder	placeholder	True	RHSA-2024:0026: firefox security update (Important)	RHSA-2024:0026	https://access_redhat_com/errata/RHSA-2024:0026
CVE-2022-1271	1100416_0	False	placeholder	placeholder	True	RHSA-2022:5052: xz security update (Important)	RHSA-2022:5052	https://access_redhat_com/errata/RHSA-2022:5052
CVE-2024-46785	31373357_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46785
CVE-2024-2612	31529842_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2023-23599	98253_0	False	placeholder	placeholder	True	RHSA-2023:0296: firefox security update (Important)	RHSA-2023:0296	https://access_redhat_com/errata/RHSA-2023:0296
CVE-2024-43834	31373302_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43834
CVE-2024-43881	31568845_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43881
CVE-2024-42297	31568567_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42297
CVE-2018-12581	182434_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2018-12581
CVE-2021-25803	1081610_0	False	placeholder	placeholder	True	USN-6180-1 -- VLC media player vulnerabilities	USN-6180-1 -- VLC media player vulnerabilities	https://ubuntu_com/security/CVE-2021-25803
CVE-2024-43875	31568839_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43875
CVE-2020-0549	117885_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2020-6829	128393_0	False	placeholder	placeholder	True	bug fix	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2022-4283	1263255_0	False	placeholder	placeholder	True	RHSA-2023:0046: xorg-x11-server security update (Important)	RHSA-2023:0046	https://access_redhat_com/errata/RHSA-2023:0046
CVE-2019-11768	235488_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2019-11768
CVE-2021-38094	1245687_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-38094
CVE-2024-43820	4143060_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43820
CVE-2024-54479	31652197_0	False	placeholder	placeholder	True	USN-7201-1 -- WebKitGTK vulnerabilities	USN-7201-1 -- WebKitGTK vulnerabilities	https://ubuntu_com/security/CVE-2024-54479
CVE-2024-46870	31582506_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46870
CVE-2022-31676	1256835_0	False	placeholder	placeholder	True	RHSA-2022:6381: open-vm-tools security update (Important)	RHSA-2022:6381	https://access_redhat_com/errata/RHSA-2022:6381
CVE-2022-40957	240465_0	False	placeholder	placeholder	True	RHSA-2022:6711: firefox security update (Important)	RHSA-2022:6711	https://access_redhat_com/errata/RHSA-2022:6711
CVE-2024-42269	4141967_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42269
CVE-2024-46711	31578119_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46711
CVE-2024-42301	4919865_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42301
CVE-2023-6209	111892_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2024-42263	4141821_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42263
CVE-2020-25643	1069458_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2017-1000015	213038_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2017-1000015
CVE-2024-47540	28884268_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47540
CVE-2021-2369	54735_0	False	placeholder	placeholder	True	RHSA-2021:2845: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:2845	https://access_redhat_com/errata/RHSA-2021:2845
CVE-2024-47835	28884296_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47835
CVE-2023-4574	145831_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2023-3609	1097346_0	False	placeholder	placeholder	True	RHSA-2023:5622: kernel security and bug fix update (Important)	RHSA-2023:5622	https://access_redhat_com/errata/RHSA-2023:5622
CVE-2024-47606	28884284_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47606
CVE-2023-44446	1230537_0	False	placeholder	placeholder	True	RHSA-2024:0013: gstreamer1-plugins-bad-free security update (Important)	RHSA-2024:0013	https://access_redhat_com/errata/RHSA-2024:0013
CVE-2023-3341	1131465_0	False	placeholder	placeholder	True	RHSA-2023:5691: bind security update (Important)	RHSA-2023:5691	https://access_redhat_com/errata/RHSA-2023:5691
CVE-2024-46747	20353435_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46747
CVE-2024-46689	20352797_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46689
CVE-2022-21628	209488_0	False	placeholder	placeholder	True	RHSA-2022:7002: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2022:7002	https://access_redhat_com/errata/RHSA-2022:7002
CVE-2021-3656	1111830_0	False	placeholder	placeholder	True	RHSA-2021:3801: kernel security and bug fix update (Important)	RHSA-2021:3801	https://access_redhat_com/errata/RHSA-2021:3801
CVE-2021-4009	1212723_0	False	placeholder	placeholder	True	RHSA-2022:0003: xorg-x11-server security update (Important)	RHSA-2022:0003	https://access_redhat_com/errata/RHSA-2022:0003
CVE-2022-2319	1228879_0	False	placeholder	placeholder	True	RHSA-2022:5905: xorg-x11-server security update (Important)	RHSA-2022:5905	https://access_redhat_com/errata/RHSA-2022:5905
CVE-2020-8695	129168_0	False	placeholder	placeholder	True	RHSA-2020:5083: microcode_ctl security	RHSA-2020:5083	https://access_redhat_com/errata/RHSA-2020:5083
CVE-2024-44983	11668841_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44983
CVE-2023-4056	51316_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2024-47607	28884285_0	False	placeholder	placeholder	True	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	USN-7175-1 -- GStreamer Base Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47607
CVE-2024-46686	15537756_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46686
CVE-2024-46818	31579431_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46818
CVE-2024-46795	20353634_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46795
CVE-2024-46733	18365775_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46733
CVE-2022-21496	81096_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2021-3715	1070786_0	False	placeholder	placeholder	True	RHSA-2021:3441: kpatch-patch security update (Moderate)	RHSA-2021:3441	https://access_redhat_com/errata/RHSA-2021:3441
CVE-2021-38090	1245683_0	False	placeholder	placeholder	True	USN-6449-1 -- FFmpeg vulnerabilities	USN-6449-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2021-38090
CVE-2023-4207	1097441_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2024-47775	28884289_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47775
CVE-2023-32233	1176379_0	False	placeholder	placeholder	True	RHSA-2023:5622: kernel security and bug fix update (Important)	RHSA-2023:5622	https://access_redhat_com/errata/RHSA-2023:5622
CVE-2023-50009	31539334_0	False	placeholder	placeholder	True	USN-6803-1 -- FFmpeg vulnerabilities	USN-6803-1 -- FFmpeg vulnerabilities	https://ubuntu_com/security/CVE-2023-50009
CVE-2024-42305	4142790_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42305
CVE-2022-23614	31348180_0	False	placeholder	placeholder	True	USN-5947-1 -- Twig vulnerabilities	USN-5947-1 -- Twig vulnerabilities	https://ubuntu_com/security/CVE-2022-23614
CVE-2024-43850	31568604_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43850
CVE-2022-29900	14677_0	False	placeholder	placeholder	True	RHSA-2022:7337: kernel security and bug fix update (Important)	RHSA-2022:7337	https://access_redhat_com/errata/RHSA-2022:7337
CVE-2023-21954	227135_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2024-42284	4142455_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2024-42264	4141855_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42264
CVE-2020-15683	72836_0	False	placeholder	placeholder	True	RHSA-2020:4310: firefox security update (Important)	RHSA-2020:4310	https://access_redhat_com/errata/RHSA-2020:4310
CVE-2022-26386	240288_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2024-44962	31571539_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44962
CVE-2020-14803	72651_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2024-2616	46419_0	False	placeholder	placeholder	True	RHSA-2024:1486: firefox security update (Critical)	RHSA-2024:1486	https://access_redhat_com/errata/RHSA-2024:1486
CVE-2021-27365	1111562_0	False	placeholder	placeholder	True	RHSA-2021:1069: kpatch-patch security update (Important)	RHSA-2021:1069	https://access_redhat_com/errata/RHSA-2021:1069
CVE-2024-43853	4919886_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43853
CVE-2024-42292	4142596_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-21125	201438_0	False	placeholder	placeholder	True	RHSA-2022:5937: kernel security and bug fix update (Moderate)	RHSA-2022:5937	https://access_redhat_com/errata/RHSA-2022:5937
CVE-2020-0548	117884_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2022-25235	37806_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2020-24513	168493_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:2305	https://access_redhat_com/errata/RHSA-2021:2305
CVE-2022-22745	240263_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2022-21476	1106364_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1487	https://access_redhat_com/errata/RHSA-2022:1487
CVE-2024-46822	24837489_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46822
CVE-2024-46791	20353626_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46791
CVE-2023-32212	98317_0	False	placeholder	placeholder	True	RHSA-2023:3137: firefox security update (Important)	RHSA-2023:3137	https://access_redhat_com/errata/RHSA-2023:3137
CVE-2020-24489	1193352_0	False	placeholder	placeholder	True	bug fix and enhancement update (Important)	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-0750	1126755_0	False	placeholder	placeholder	True	RHSA-2024:0600: firefox security update (Important)	RHSA-2024:0600	https://access_redhat_com/errata/RHSA-2024:0600
CVE-2023-31436	1251721_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2020-14355	71888_0	False	placeholder	placeholder	True	RHSA-2020:4187: spice and spice-gtk security update (Important)	RHSA-2020:4187	https://access_redhat_com/errata/RHSA-2020:4187
CVE-2023-6204	111888_0	False	placeholder	placeholder	True	RHSA-2023:7509: firefox security update (Important)	RHSA-2023:7509	https://access_redhat_com/errata/RHSA-2023:7509
CVE-2021-23995	1194290_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2023-50387	1096636_0	False	placeholder	placeholder	True	RHSA-2024:3741: bind	RHSA-2024:3741	https://access_redhat_com/errata/RHSA-2024:3741
CVE-2023-21939	227126_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2023-21930	1251007_0	False	placeholder	placeholder	True	RHSA-2023:1904: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2023:1904	https://access_redhat_com/errata/RHSA-2023:1904
CVE-2020-28374	1049412_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2021-4010	1212724_0	False	placeholder	placeholder	True	RHSA-2022:0003: xorg-x11-server security update (Important)	RHSA-2022:0003	https://access_redhat_com/errata/RHSA-2022:0003
CVE-2021-23982	126844_0	False	placeholder	placeholder	True	RHSA-2021:0992: firefox security update (Important)	RHSA-2021:0992	https://access_redhat_com/errata/RHSA-2021:0992
CVE-2024-33601	31430483_0	False	placeholder	placeholder	True	RHSA-2024:3588: glibc security update (Important)	RHSA-2024:3588	https://access_redhat_com/errata/RHSA-2024:3588
CVE-2024-46705	31578041_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46705
CVE-2024-40961	12939694_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-6829	128393_0	False	placeholder	placeholder	True	and enhancement update (Moderate)	RHSA-2020:4076	https://access_redhat_com/errata/RHSA-2020:4076
CVE-2024-46841	28877974_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46841
CVE-2024-46771	31373328_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46771
CVE-2024-42318	4142955_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42318
CVE-2020-29661	1070387_0	False	placeholder	placeholder	True	RHSA-2021:0856: kernel security and bug fix update (Important)	RHSA-2021:0856	https://access_redhat_com/errata/RHSA-2021:0856
CVE-2022-29916	240358_0	False	placeholder	placeholder	True	RHSA-2022:1703: firefox security update (Important)	RHSA-2022:1703	https://access_redhat_com/errata/RHSA-2022:1703
CVE-2021-38496	1168029_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2023-6377	1025979_0	False	placeholder	placeholder	True	RHSA-2024:0006: tigervnc security update (Important)	RHSA-2024:0006	https://access_redhat_com/errata/RHSA-2024:0006
CVE-2024-44947	17652758_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44947
CVE-2022-23481	198591_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23481
CVE-2024-44996	17652764_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44996
CVE-2024-42301	4919865_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-26974	1052101_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2022-38472	240430_0	False	placeholder	placeholder	True	RHSA-2022:6179: firefox security update (Important)	RHSA-2022:6179	https://access_redhat_com/errata/RHSA-2022:6179
CVE-2024-46831	31417475_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46831
CVE-2024-47543	28884271_0	False	placeholder	placeholder	True	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	USN-7176-1 -- GStreamer Good Plugins vulnerabilities	https://ubuntu_com/security/CVE-2024-47543
CVE-2024-3864	31683602_0	False	placeholder	placeholder	True	RHSA-2024:1910: firefox security update (Important)	RHSA-2024:1910	https://access_redhat_com/errata/RHSA-2024:1910
CVE-2022-48936	31375126_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-23613	1255677_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23613
CVE-2021-29988	1093957_0	False	placeholder	placeholder	True	RHSA-2021:3154: firefox security update (Important)	RHSA-2021:3154	https://access_redhat_com/errata/RHSA-2021:3154
CVE-2019-12922	126335_0	False	placeholder	placeholder	True	USN-4843-1 -- phpMyAdmin vulnerabilities	USN-4843-1 -- phpMyAdmin vulnerabilities	https://ubuntu_com/security/CVE-2019-12922
CVE-2024-44999	7028941_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44999
CVE-2021-35567	141922_0	False	placeholder	placeholder	True	RHSA-2021:3889: java-1_8_0-openjdk security and bug fix update (Important)	RHSA-2021:3889	https://access_redhat_com/errata/RHSA-2021:3889
CVE-2020-15969	1154148_0	False	placeholder	placeholder	True	RHSA-2020:4310: firefox security update (Important)	RHSA-2020:4310	https://access_redhat_com/errata/RHSA-2020:4310
CVE-2023-40184	31488992_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2023-40184
CVE-2024-45010	15016254_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45010
CVE-2024-41092	31563168_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2020-14779	254820_0	False	placeholder	placeholder	True	RHSA-2020:4350: java-1_8_0-openjdk security and bug fix update (Moderate)	RHSA-2020:4350	https://access_redhat_com/errata/RHSA-2020:4350
CVE-2020-25637	255688_0	False	placeholder	placeholder	True	RHSA-2020:5040: libvirt security and bug fix update (Moderate)	RHSA-2020:5040	https://access_redhat_com/errata/RHSA-2020:5040
CVE-2021-23998	169457_0	False	placeholder	placeholder	True	RHSA-2021:1363: firefox security update (Important)	RHSA-2021:1363	https://access_redhat_com/errata/RHSA-2021:1363
CVE-2023-4583	1171083_0	False	placeholder	placeholder	True	RHSA-2023:5019: firefox security update (Important)	RHSA-2023:5019	https://access_redhat_com/errata/RHSA-2023:5019
CVE-2024-42273	4142009_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42273
CVE-2024-43879	31568843_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43879
CVE-2020-14347	209325_0	False	placeholder	placeholder	True	RHSA-2020:5408: xorg-x11-server security update (Important)	RHSA-2020:5408	https://access_redhat_com/errata/RHSA-2020:5408
CVE-2022-23493	198596_0	False	placeholder	placeholder	True	USN-6474-1 -- xrdp vulnerabilities	USN-6474-1 -- xrdp vulnerabilities	https://ubuntu_com/security/CVE-2022-23493
CVE-2024-46729	18365638_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46729
CVE-2022-1802	1264018_0	False	placeholder	placeholder	True	RHSA-2022:4729: firefox security update (Critical)	RHSA-2022:4729	https://access_redhat_com/errata/RHSA-2022:4729
CVE-2022-34169	1108717_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2023-0286	1056413_0	False	placeholder	placeholder	True	RHSA-2023:1335: openssl security update (Important)	RHSA-2023:1335	https://access_redhat_com/errata/RHSA-2023:1335
CVE-2021-4083	1083180_0	False	placeholder	placeholder	True	and enhancement update (Important)	RHSA-2022:1198	https://access_redhat_com/errata/RHSA-2022:1198
CVE-2021-3941	134748_0	False	placeholder	placeholder	True	USN-5620-1 -- OpenEXR vulnerabilities	USN-5620-1 -- OpenEXR vulnerabilities	https://ubuntu_com/security/CVE-2021-3941
CVE-2024-44991	31571554_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-44991
CVE-2024-38541	31553055_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2023-1999	31480887_0	False	placeholder	placeholder	True	RHSA-2023:1791: firefox security update (Important)	RHSA-2023:1791	https://access_redhat_com/errata/RHSA-2023:1791
CVE-2020-1472	95082_0	False	placeholder	placeholder	True	RHSA-2020:5439: samba security and bug fix update (Moderate)	RHSA-2020:5439	https://access_redhat_com/errata/RHSA-2020:5439
CVE-2023-0767	1124834_0	False	placeholder	placeholder	True	RHSA-2023:1332: nss security update (Important)	RHSA-2023:1332	https://access_redhat_com/errata/RHSA-2023:1332
CVE-2021-37576	1081642_0	False	placeholder	placeholder	True	RHSA-2021:3801: kernel security and bug fix update (Important)	RHSA-2021:3801	https://access_redhat_com/errata/RHSA-2021:3801
CVE-2024-47666	31582527_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47666
CVE-2024-42304	4142786_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42304
CVE-2020-16042	77422_0	False	placeholder	placeholder	True	RHSA-2020:5561: firefox security update (Important)	RHSA-2020:5561	https://access_redhat_com/errata/RHSA-2020:5561
CVE-2021-38498	1168031_0	False	placeholder	placeholder	True	RHSA-2021:3791: firefox security update (Important)	RHSA-2021:3791	https://access_redhat_com/errata/RHSA-2021:3791
CVE-2022-38178	1101102_0	False	placeholder	placeholder	True	RHSA-2022:6765: bind security update (Important)	RHSA-2022:6765	https://access_redhat_com/errata/RHSA-2022:6765
CVE-2022-46344	1263248_0	False	placeholder	placeholder	True	RHSA-2023:0045: tigervnc security update (Important)	RHSA-2023:0045	https://access_redhat_com/errata/RHSA-2023:0045
CVE-2024-47669	31582531_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-47669
CVE-2024-46679	22180887_0	False	placeholder	placeholder	True	RHSA-2024:8856: kernel security update (Moderate)	RHSA-2024:8856	https://access_redhat_com/errata/RHSA-2024:8856
CVE-2022-21541	253194_0	False	placeholder	placeholder	True	RHSA-2022:5698: java-1_8_0-openjdk security	RHSA-2022:5698	https://access_redhat_com/errata/RHSA-2022:5698
CVE-2020-8696	129170_0	False	placeholder	placeholder	True	RHBA-2021:0623: microcode_ctl bug fix and enhancement update (Moderate)	placeholder	placeholder
CVE-2023-4128	62434_0	False	placeholder	placeholder	True	RHSA-2023:7423: kernel security update (Important)	RHSA-2023:7423	https://access_redhat_com/errata/RHSA-2023:7423
CVE-2022-22741	1264067_0	False	placeholder	placeholder	True	RHSA-2022:0124: firefox security update (Important)	RHSA-2022:0124	https://access_redhat_com/errata/RHSA-2022:0124
CVE-2022-26485	1264106_0	False	placeholder	placeholder	True	RHSA-2022:0824: firefox security and bug fix update (Critical)	RHSA-2022:0824	https://access_redhat_com/errata/RHSA-2022:0824
CVE-2022-41974	1234386_0	False	placeholder	placeholder	True	RHSA-2022:7186: device-mapper-multipath security update (Important)	RHSA-2022:7186	https://access_redhat_com/errata/RHSA-2022:7186
CVE-2024-42312	4142839_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-42312
CVE-2020-1983	31479580_0	False	placeholder	placeholder	True	RHSA-2020:4079: qemu-kvm security update (Important)	RHSA-2020:4079	https://access_redhat_com/errata/RHSA-2020:4079
CVE-2022-1196	240205_0	False	placeholder	placeholder	True	RHSA-2022:1284: firefox security update (Important)	RHSA-2022:1284	https://access_redhat_com/errata/RHSA-2022:1284
CVE-2024-46866	31579479_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-46866
CVE-2024-45012	15016264_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-45012
CVE-2024-43899	6467753_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43899
CVE-2019-20934	219885_0	False	placeholder	placeholder	True	RHSA-2021:2725: kernel security and bug fix update (Important)	RHSA-2021:2725	https://access_redhat_com/errata/RHSA-2021:2725
CVE-2023-1393	1107875_0	False	placeholder	placeholder	True	RHSA-2023:1594: tigervnc and xorg-x11-server security update (Important)	RHSA-2023:1594	https://access_redhat_com/errata/RHSA-2023:1594
CVE-2019-18282	117274_0	False	placeholder	placeholder	True	RHSA-2020:5437: kernel security and bug fix update (Important)	RHSA-2020:5437	https://access_redhat_com/errata/RHSA-2020:5437
CVE-2024-43826	4143249_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43826
CVE-2020-8698	129171_0	False	placeholder	placeholder	True	RHSA-2021:3028: microcode_ctl security	RHSA-2021:3028	https://access_redhat_com/errata/RHSA-2021:3028
CVE-2024-43857	4919892_0	False	placeholder	placeholder	True	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	USN-7154-2 -- Linux kernel (HWE) vulnerabilities	https://ubuntu_com/security/CVE-2024-43857
CVE-2020-14360	1186354_0	False	placeholder	placeholder	True	RHSA-2020:5408: xorg-x11-server security update (Important)	RHSA-2020:5408	https://access_redhat_com/errata/RHSA-2020:5408
CVE-2022-21166	14557_0	False	placeholder	placeholder	True	RHSA-2022:5937: kernel security and bug fix update (Moderate)	RHSA-2022:5937	https://access_redhat_com/errata/RHSA-2022:5937
CVE-2023-4055	1077620_0	False	placeholder	placeholder	True	RHSA-2023:4461: firefox security update (Important)	RHSA-2023:4461	https://access_redhat_com/errata/RHSA-2023:4461
CVE-2020-26960	1046896_0	False	placeholder	placeholder	True	RHSA-2020:5239: firefox security update (Important)	RHSA-2020:5239	https://access_redhat_com/errata/RHSA-2020:5239
\.


--
-- PostgreSQL database dump complete
--

