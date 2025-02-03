
    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2019-11091'}), (e:Evidence {vul_id: 'CVE-2019-11091'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2018-12126'}), (e:Evidence {vul_id: 'CVE-2018-12126'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2018-12130'}), (e:Evidence {vul_id: 'CVE-2018-12130'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2022-21123'}), (e:Evidence {vul_id: 'CVE-2022-21123'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2020-0550'}), (e:Evidence {vul_id: 'CVE-2020-0550'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2020-0549'}), (e:Evidence {vul_id: 'CVE-2020-0549'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2022-21125'}), (e:Evidence {vul_id: 'CVE-2022-21125'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'Event-Log-Crasher'}), (e:Evidence {vul_id: 'Event-Log-Crasher'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2018-12127'}), (e:Evidence {vul_id: 'CVE-2018-12127'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'POWERSHELL-V2-INFO-DISCLOSURE'}), (e:Evidence {vul_id: 'POWERSHELL-V2-INFO-DISCLOSURE'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2022-21166'}), (e:Evidence {vul_id: 'CVE-2022-21166'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2013-3900'}), (e:Evidence {vul_id: 'CVE-2013-3900'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'SNMP Agent Default Community Name (public)'}), (e:Evidence {vul_id: 'SNMP Agent Default Community Name (public)'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2018-3639'}), (e:Evidence {vul_id: 'CVE-2018-3639'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED'}), (e:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    

    SELECT * FROM cypher('security_graph', $$
    MATCH (v:Vulnerability {vul_id: 'CVE-2017-5715'}), (e:Evidence {vul_id: 'CVE-2017-5715'})
    CREATE (v)-[:HAS_EVIDENCE]->(e)
    $$) AS (r agtype);
    
