
    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2013-3900', epss_score: '0.23734', name: 'WinVerifyTrust Signature Validation Vulnerability', severity: 'High', base_score: '7.4', exploitability_score: '7.4', impact_score: '7.4', fix_description: 'Add WinVerifyTrust Signature', url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900', problem_group_id: '2'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2017-5715', epss_score: '0.97469', name: 'Branch Target Injection (Spectre-v2)', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Install BIOS/firmware update and enable Windows support', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2018-12126', epss_score: '0.00077', name: 'Microarchitectural Data Sampling', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2018-12127', epss_score: '0.00077', name: 'Microarchitectural Data Sampling', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2018-12130', epss_score: '0.00077', name: 'Microarchitectural Data Sampling', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2018-3639', epss_score: '0.00771', name: 'Speculative Store Bypass', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2019-11091', epss_score: '0.00096', name: 'Microarchitectural Data Sampling', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2020-0549', epss_score: '0.00049', name: 'Fill Buffer Stale Data Propagator', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2020-0549', epss_score: '0.00082', name: 'Fill Buffer Stale Data Propagator', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2020-0550', epss_score: '0.00044', name: 'Shared Buffers Data Read', severity: 'Medium', base_score: '5.6', exploitability_score: '1.1', impact_score: '4', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2022-21123', epss_score: '0.00049', name: 'Primary Stale Data Propagator', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2022-21125', epss_score: '0.00059', name: 'Primary Stale Data Propagator', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'CVE-2022-21166', epss_score: '0.00049', name: 'Primary Stale Data Propagator', severity: 'Medium', base_score: '5.5', exploitability_score: '1.8', impact_score: '3.6', fix_description: 'Enable Windows mitigation', url: 'https://support.microsoft.com/help/4073119', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'Event-Log-Crasher', epss_score: '0', name: 'Event-Log-Crasher', severity: 'Medium', base_score: '6.4', exploitability_score: '6.4', impact_score: '6.4', fix_description: 'Unofficial security patches', url: 'NONE', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'POWERSHELL-V2-INFO-DISCLOSURE', epss_score: '0.23734', name: 'powershellv2', severity: 'Medium', base_score: '6.4', exploitability_score: '6.4', impact_score: '6.4', fix_description: 'Disable Windows PowerShell 2.0 on the system', url: 'https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-70637', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'SNMP Agent Default Community Name (public)', epss_score: '0', name: 'SNMP Agent Default Community Name (public)', severity: 'High', base_score: '7.5', exploitability_score: '7.5', impact_score: '7.5', fix_description: 'Disable the SNMP service on the remote host if you do not use it. Either filter incoming UDP packets going to this port, or change the default community string.', url: 'NONE', problem_group_id: '3'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Vulnerability {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', name: 'unquoted service path', severity: 'High', base_score: '7.8', exploitability_score: '7.8', impact_score: '7.8', fix_description: 'Make sure that any services that have a space in their path are enclosed in quotes', url: 'https://isgovern.com/blog/how-to-fix-the-windows-unquoted-service-path-vulnerability/', problem_group_id: '2'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows 10 Pro', os_version: '10.0.19045', os_build: '19045'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2022 Standard Evaluation', os_version: '10.0.20348', os_build: '20348'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2022 Standard', os_version: '10.0.20348', os_build: '20348'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows 10 Home Single Language', os_version: '10.0.19045', os_build: '19045'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2019 Datacenter', os_version: '10.0.17763', os_build: '17763'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2019 Standard', os_version: '10.0.17763', os_build: '17763'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows 11 Pro', os_version: '10.0.22631', os_build: '22631'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows 11 Pro Insider Preview', os_version: '10.0.23612', os_build: '23612'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2016 Standard', os_version: '10.0.14393', os_build: '14393'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows Server 2012 R2 Standard Evaluation', os_version: '6.3.9600', os_build: '9600'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Windows NT', os_version: '10', os_build: '17763'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'Microsoft Windows 10 Pro', os_version: '10.0.19043', os_build: '19043'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:OperatingSystem {os_name: 'brother', os_version: 'Firmware Ver.1.05  (12.10.02)', os_build: 'Brother NC-8200h'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2013-3900', epss_score: '0.23734', evidence: 'Registry key : \'HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Cryptography/Wintrust/Config/EnableCertPaddingCheck\' , Value : 0'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2013-3900', epss_score: '0.23734', evidence: 'Registry key : \'HKEY_LOCAL_MACHINE/Software/Wow6432Node/Microsoft/Cryptography/Wintrust/Config/EnableCertPaddingCheck\' , Value : None'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2017-5715', epss_score: '0.97469', evidence: 'Check performed: Branch Target Injection\nHardware vulnerable: True\nWindows mitigation enabled: False\nCPU microcode update status: \nOS support for branch target injection mitigation is present: True\nWindows OS support for branch target injection mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2018-12126', epss_score: '0.00077', evidence: 'Check performed: Microarchitectural Data Sampling\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to MDS: True\nWindows OS support for MDS mitigation is present: True\nWindows OS support for MDS mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2018-12127', epss_score: '0.00077', evidence: 'Check performed: Microarchitectural Data Sampling\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to MDS: True\nWindows OS support for MDS mitigation is present: True\nWindows OS support for MDS mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2018-12130', epss_score: '0.00077', evidence: 'Check performed: Microarchitectural Data Sampling\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to MDS: True\nWindows OS support for MDS mitigation is present: True\nWindows OS support for MDS mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2018-3639', epss_score: '0.00771', evidence: 'Check performed: Speculative Store Bypass\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to speculative store bypass: True\nWindows OS support for speculative store bypass disable is present: True\nWindows OS support for speculative store bypass disable is enabled system-wide: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2019-11091', epss_score: '0.00096', evidence: 'Check performed: Microarchitectural Data Sampling\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to MDS: True\nWindows OS support for MDS mitigation is present: True\nWindows OS support for MDS mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2020-0549', epss_score: '0.00049', evidence: 'Check performed: Fill Buffer Stale Data Propagator\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to SSDP/FBSDP/PSDP: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is present: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2020-0550', epss_score: '0.00044', evidence: 'Check performed: Shared Buffers Data Read\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to SSDP/FBSDP/PSDP: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is present: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2022-21123', epss_score: '0.00049', evidence: 'Check performed: Primary Stale Data Propagator\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to SSDP/FBSDP/PSDP: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is present: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2022-21125', epss_score: '0.00059', evidence: 'Check performed: Primary Stale Data Propagator\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to SSDP/FBSDP/PSDP: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is present: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'CVE-2022-21166', epss_score: '0.00049', evidence: 'Check performed: Primary Stale Data Propagator\nHardware vulnerable: True\nWindows mitigation enabled: False\nHardware is vulnerable to SSDP/FBSDP/PSDP: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is present: True\nWindows OS support for SSDP/FBSDP/PSDP mitigation is enabled: False'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'Event-Log-Crasher', epss_score: '0', evidence: 'Windows Server 2019 is vulnerable to the Event-Log-Crasher'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'Event-Log-Crasher', epss_score: '0', evidence: 'Windows 10 is vulnerable to the Event-Log-Crasher'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'Event-Log-Crasher', epss_score: '0', evidence: 'Windows Server 2022 is vulnerable to the Event-Log-Crasher'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'Event-Log-Crasher', epss_score: '0', evidence: 'Windows Server 2012 R2 is vulnerable to the Event-Log-Crasher'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'Event-Log-Crasher', epss_score: '0', evidence: 'Windows 11 is vulnerable to the Event-Log-Crasher'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'POWERSHELL-V2-INFO-DISCLOSURE', epss_score: '0.23734', evidence: 'Powershellv2 is Enabled'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'system root \\system32\\svchost'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'c://program files//a subfolder//b subfolder//c subfolder//someexecutable.exe'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'c://program files//sonicwall//client protection service//sonicwallclientprotectionservice.exe'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'c://program files (x86)//anydesk//anydesk.exe'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'c://program files//sonicwall//client protection service//swclientprotectionservice.exe'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'UNQUOTED-SERVICE-PATH-DETECTED', epss_score: '0', evidence: 'c://program files//remote utilities - host//rman service//file, c://program files//a subfolder//b subfolder//c subfolder//someexecutable.exe'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Evidence {vul_id: 'SNMP Agent Default Community Name (public)', epss_score: '0', evidence: 'NONE'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:14:31', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "07e844eb-b001-4747-ad4d-5eed14c609fd", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 12:43:29', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '67329.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 12:43:31', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4027', company_id: '9645', tenantid: '241996091870937089', id: '39776', created: '2025-01-23 12:43:29', updated: '2025-01-24 7:14:31', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:14:31', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39776', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98204', created_vulnerability: '2025-01-23 12:43:33', updated_vulnerability: '2025-01-23 12:43:33', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'WIN-J7J1G5810LF', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:29:23', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "03f9bc98-07f4-e211-bf94-28d2441cee45", "1003502001493", "28:d2:44:1c:ee:45", "1c:3e:84:e5:76:e1"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 9:15:55', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LENOVO', physical_memory: '8589934592.0', uptime: '70776.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 9:15:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3965', company_id: '9622', tenantid: '241996091870937089', id: '39383', created: '2025-01-22 9:15:55', updated: '2025-01-24 6:29:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:29:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39383', company_id_vulnerability: '9622', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98407', created_vulnerability: '2025-01-24 6:29:23', updated_vulnerability: '2025-01-24 6:29:23', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'CCNS-DC7', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:05:27', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5042881", "5043167", "925673", "2538243", "2565063", "5037570", "5040711", "", "5042349", "890830"]', os_install_date: '1691513178.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '10.0.0.3', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2694', unique_id: '["ccns-dc7", "d0:27:88:e6:0e:a2"]', host_name: 'CCNS-DC7.ad.mycybercns.com', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-20 7:03:50', icon: 'windows.svg', status: 'true', hardware_model: 'AT-7000 Series', importance: '25', serial_number: 'THF10V040533000010', mac: 'd0:27:88:e6:0e:a2', manufacturer: 'Foxconn', physical_memory: '8589934592.0', uptime: '2665100.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:52:23', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3972', company_id: '9624', tenantid: '241996091870937089', id: '39195', created: '2025-01-20 7:03:50', updated: '2025-01-24 8:05:27', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:05:27', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.27', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39195', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97229', created_vulnerability: '2025-01-20 7:04:05', updated_vulnerability: '2025-01-20 7:04:05', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:14:31', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "07e844eb-b001-4747-ad4d-5eed14c609fd", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 12:43:29', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '67329.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 12:43:31', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4027', company_id: '9645', tenantid: '241996091870937089', id: '39776', created: '2025-01-23 12:43:29', updated: '2025-01-24 7:14:31', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:14:31', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39776', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98421', created_vulnerability: '2025-01-24 7:14:32', updated_vulnerability: '2025-01-24 7:14:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-R1I4U1S', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 11:17:51', logged_user_time: '1737543915.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5011048", "5015684", "5033052", "5049981", "5014032", "5025315", "5041579", "5043935", "5043130", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1646835591.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Home Single Language', ip: '172.168.1.11', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["5dvgn42", "fc:77:74:39:ed:b0", "desktop-r1i4u1s", "4c4c4544-0044-5610-8047-b5c04f4e3432"]', host_name: 'DESKTOP-R1I4U1S', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 5:27:10', icon: 'windows.svg', status: 'true', hardware_model: 'Inspiron 5370', importance: '25', serial_number: '5DVGN42', mac: '0a:00:27:00:00:16', manufacturer: 'Dell Inc.', physical_memory: '8589934592.0', uptime: '436.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 5:27:14', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4006', company_id: '8136', tenantid: '241996091870937089', id: '39247', created: '2025-01-22 5:27:10', updated: '2025-01-22 11:17:51', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 11:17:51', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39247', company_id_vulnerability: '8136', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97676', created_vulnerability: '2025-01-22 5:27:16', updated_vulnerability: '2025-01-22 5:27:16', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96661', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96662', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96663', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'INSPECT-365-EU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:57:30', logged_user_time: '1732882692.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5044025", "5044281", "5044414", "4052623", "890830", "5044099", "2267602"]', os_install_date: '1732882639.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '208.76.221.39', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2760', unique_id: '["inspect-365-eu", "5840671b-bda5-44b4-a0f9-ffb191e782b4", "79493383", "56:00:05:30:01:cf"]', host_name: 'Inspect-365-EU', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-22 10:08:37', icon: 'windows.svg', status: 'true', hardware_model: 'VOC', importance: '25', serial_number: '79493383', mac: '56:00:05:30:01:cf', manufacturer: 'Vultr', physical_memory: '4294967296.0', uptime: '4822302.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 12:56:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4018', company_id: '9638', tenantid: '241996091870937089', id: '39391', created: '2025-01-22 10:08:37', updated: '2025-01-24 7:57:30', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:57:30', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2762', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39391', company_id_vulnerability: '9638', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98367', created_vulnerability: '2025-01-24 1:17:20', updated_vulnerability: '2025-01-24 1:17:20', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:04:09', logged_user_time: '1737745949.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "aeb90eeb-594a-49ef-9a20-e3693e8be749", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV.lego.in', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 8:41:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '148018.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:58:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4015', company_id: '9633', tenantid: '241996091870937089', id: '39379', created: '2025-01-22 8:41:34', updated: '2025-01-24 6:04:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:04:09', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39379', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98379', created_vulnerability: '2025-01-24 5:08:27', updated_vulnerability: '2025-01-24 5:08:27', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SVN2RHJ', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 8:09:23', logged_user_time: '1737523556.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5041579", "5043935", "5043130", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1724908067.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.28', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-svn2rhj", "310782b9-7c22-4dab-b410-509999dba9c8", "66:6b:0c:9f:2c:61"]', host_name: 'DESKTOP-SVN2RHJ', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-21 13:01:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '66:6b:0c:9f:2c:61', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '69742.0', asset_category: 'placeholder', last_reset_time: '2025-01-21 13:01:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3936', company_id: '9612', tenantid: '241996091870937089', id: '39244', created: '2025-01-21 13:01:20', updated: '2025-01-22 8:09:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 8:09:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39244', company_id_vulnerability: '9612', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97584', created_vulnerability: '2025-01-21 13:01:35', updated_vulnerability: '2025-01-21 13:01:35', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96664', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WINDOWS-11', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:17:09', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049624", "5027397", "5041655", "5050021", "5050113", "4052623", "5007651", "890830", "2267602", "4023057"]', os_install_date: '1735021631.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 11 Pro', ip: '10.0.1.38', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.22621.4746', unique_id: '["windows-11", "4d1d8cbb-e846-490e-be2f-678cee927c7d", "0e:c8:99:16:ab:a4"]', host_name: 'Windows-11', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 10:13:44', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '0e:c8:99:16:ab:a4', manufacturer: 'QEMU', physical_memory: '4294967296.0', uptime: '167268.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:55:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4017', company_id: '9633', tenantid: '241996091870937089', id: '39631', created: '2025-01-23 10:13:44', updated: '2025-01-24 8:17:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:17:09', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '22631.4751', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39631', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98129', created_vulnerability: '2025-01-23 10:13:47', updated_vulnerability: '2025-01-23 10:13:47', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-R1I4U1S', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 11:17:51', logged_user_time: '1737543915.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5011048", "5015684", "5033052", "5049981", "5014032", "5025315", "5041579", "5043935", "5043130", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1646835591.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Home Single Language', ip: '172.168.1.11', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["5dvgn42", "fc:77:74:39:ed:b0", "desktop-r1i4u1s", "4c4c4544-0044-5610-8047-b5c04f4e3432"]', host_name: 'DESKTOP-R1I4U1S', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 5:27:10', icon: 'windows.svg', status: 'true', hardware_model: 'Inspiron 5370', importance: '25', serial_number: '5DVGN42', mac: '0a:00:27:00:00:16', manufacturer: 'Dell Inc.', physical_memory: '8589934592.0', uptime: '436.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 5:27:14', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4006', company_id: '8136', tenantid: '241996091870937089', id: '39247', created: '2025-01-22 5:27:10', updated: '2025-01-22 11:17:51', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 11:17:51', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39247', company_id_vulnerability: '8136', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '97893', created_vulnerability: '2025-01-22 11:17:57', updated_vulnerability: '2025-01-22 11:17:57', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96665', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96666', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96667', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:14:31', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "07e844eb-b001-4747-ad4d-5eed14c609fd", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 12:43:29', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '67329.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 12:43:31', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4027', company_id: '9645', tenantid: '241996091870937089', id: '39776', created: '2025-01-23 12:43:29', updated: '2025-01-24 7:14:31', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:14:31', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39776', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98422', created_vulnerability: '2025-01-24 7:14:32', updated_vulnerability: '2025-01-24 7:14:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96668', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'CCNS-DC7', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:05:27', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5042881", "5043167", "925673", "2538243", "2565063", "5037570", "5040711", "", "5042349", "890830"]', os_install_date: '1691513178.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '10.0.0.3', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2694', unique_id: '["ccns-dc7", "d0:27:88:e6:0e:a2"]', host_name: 'CCNS-DC7.ad.mycybercns.com', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-20 7:03:50', icon: 'windows.svg', status: 'true', hardware_model: 'AT-7000 Series', importance: '25', serial_number: 'THF10V040533000010', mac: 'd0:27:88:e6:0e:a2', manufacturer: 'Foxconn', physical_memory: '8589934592.0', uptime: '2665100.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:52:23', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3972', company_id: '9624', tenantid: '241996091870937089', id: '39195', created: '2025-01-20 7:03:50', updated: '2025-01-24 8:05:27', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:05:27', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.27', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39195', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97230', created_vulnerability: '2025-01-20 7:04:05', updated_vulnerability: '2025-01-20 7:04:05', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96669', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '96670', created_vulnerability: '2025-01-17 10:56:32', updated_vulnerability: '2025-01-17 10:56:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:52:37', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:50:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '22819.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:50:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39535"}, {"status": true, "protocol": "NMAP", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39891', created: '2025-01-23 18:50:11', updated: '2025-01-23 18:52:37', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:52:37', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39891', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98284', created_vulnerability: '2025-01-23 18:50:18', updated_vulnerability: '2025-01-23 18:50:18', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98393', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:52:37', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:50:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '22819.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:50:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39535"}, {"status": true, "protocol": "NMAP", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39891', created: '2025-01-23 18:50:11', updated: '2025-01-23 18:52:37', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:52:37', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39891', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98293', created_vulnerability: '2025-01-23 18:52:38', updated_vulnerability: '2025-01-23 18:52:38', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'INSPECT-365-EU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:57:30', logged_user_time: '1732882692.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5044025", "5044281", "5044414", "4052623", "890830", "5044099", "2267602"]', os_install_date: '1732882639.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '208.76.221.39', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2760', unique_id: '["inspect-365-eu", "5840671b-bda5-44b4-a0f9-ffb191e782b4", "79493383", "56:00:05:30:01:cf"]', host_name: 'Inspect-365-EU', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-22 10:08:37', icon: 'windows.svg', status: 'true', hardware_model: 'VOC', importance: '25', serial_number: '79493383', mac: '56:00:05:30:01:cf', manufacturer: 'Vultr', physical_memory: '4294967296.0', uptime: '4822302.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 12:56:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4018', company_id: '9638', tenantid: '241996091870937089', id: '39391', created: '2025-01-22 10:08:37', updated: '2025-01-24 7:57:30', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:57:30', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2762', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39391', company_id_vulnerability: '9638', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98369', created_vulnerability: '2025-01-24 1:17:20', updated_vulnerability: '2025-01-24 1:17:20', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SVN2RHJ', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 8:09:23', logged_user_time: '1737523556.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5041579", "5043935", "5043130", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1724908067.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.28', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-svn2rhj", "310782b9-7c22-4dab-b410-509999dba9c8", "66:6b:0c:9f:2c:61"]', host_name: 'DESKTOP-SVN2RHJ', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-21 13:01:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '66:6b:0c:9f:2c:61', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '69742.0', asset_category: 'placeholder', last_reset_time: '2025-01-21 13:01:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3936', company_id: '9612', tenantid: '241996091870937089', id: '39244', created: '2025-01-21 13:01:20', updated: '2025-01-22 8:09:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 8:09:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39244', company_id_vulnerability: '9612', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '97823', created_vulnerability: '2025-01-22 8:09:23', updated_vulnerability: '2025-01-22 8:09:23', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SVN2RHJ', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 8:09:23', logged_user_time: '1737523556.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5041579", "5043935", "5043130", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1724908067.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.28', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-svn2rhj", "310782b9-7c22-4dab-b410-509999dba9c8", "66:6b:0c:9f:2c:61"]', host_name: 'DESKTOP-SVN2RHJ', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-21 13:01:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '66:6b:0c:9f:2c:61', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '69742.0', asset_category: 'placeholder', last_reset_time: '2025-01-21 13:01:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3936', company_id: '9612', tenantid: '241996091870937089', id: '39244', created: '2025-01-21 13:01:20', updated: '2025-01-22 8:09:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 8:09:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39244', company_id_vulnerability: '9612', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97824', created_vulnerability: '2025-01-22 8:09:23', updated_vulnerability: '2025-01-22 8:09:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98044', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:14:31', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "07e844eb-b001-4747-ad4d-5eed14c609fd", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 12:43:29', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '67329.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 12:43:31', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4027', company_id: '9645', tenantid: '241996091870937089', id: '39776', created: '2025-01-23 12:43:29', updated: '2025-01-24 7:14:31', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:14:31', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39776', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98423', created_vulnerability: '2025-01-24 7:14:32', updated_vulnerability: '2025-01-24 7:14:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'CONNECTSECURE-F', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:52:53', logged_user_time: '1737701437.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["925673", "2565063", "3045323", "3045324", "3158271", "4032542", "4019091", "4019099", "4022619", "4505217", "4505419", "4500180", "4052623", "5029184", "5029185", "5007651", "890830", "2267602"]', os_install_date: '1711388083.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 11 Pro Insider Preview', ip: '10.0.4.4', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.23612.1000', unique_id: '["connectsecure-fr\u00e9d\u00e9ration\ud83d\udc22", "9a:4b:a5:b7:45:e0"]', host_name: 'Connectsecure-Frédération🐢', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-21 7:32:45', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '9a:4b:a5:b7:45:e0', manufacturer: 'QEMU', physical_memory: '4299161600.0', uptime: '94590.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 7:44:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Workstation"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39214', created: '2025-01-21 7:32:45', updated: '2025-01-24 8:52:53', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:52:53', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '23612.1', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39214', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97451', created_vulnerability: '2025-01-22 7:44:34', updated_vulnerability: '2025-01-22 7:44:34', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98045', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'INSPECT-365-EU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:57:30', logged_user_time: '1732882692.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5044025", "5044281", "5044414", "4052623", "890830", "5044099", "2267602"]', os_install_date: '1732882639.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '208.76.221.39', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2760', unique_id: '["inspect-365-eu", "5840671b-bda5-44b4-a0f9-ffb191e782b4", "79493383", "56:00:05:30:01:cf"]', host_name: 'Inspect-365-EU', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-22 10:08:37', icon: 'windows.svg', status: 'true', hardware_model: 'VOC', importance: '25', serial_number: '79493383', mac: '56:00:05:30:01:cf', manufacturer: 'Vultr', physical_memory: '4294967296.0', uptime: '4822302.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 12:56:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4018', company_id: '9638', tenantid: '241996091870937089', id: '39391', created: '2025-01-22 10:08:37', updated: '2025-01-24 7:57:30', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:57:30', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2762', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39391', company_id_vulnerability: '9638', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97863', created_vulnerability: '2025-01-22 12:56:18', updated_vulnerability: '2025-01-22 12:56:18', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98394', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98435', created_vulnerability: '2025-01-24 8:14:44', updated_vulnerability: '2025-01-24 8:14:44', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:52:37', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:50:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '22819.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:50:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39535"}, {"status": true, "protocol": "NMAP", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39891', created: '2025-01-23 18:50:11', updated: '2025-01-23 18:52:37', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:52:37', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39891', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98291', created_vulnerability: '2025-01-23 18:52:38', updated_vulnerability: '2025-01-23 18:52:38', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97874', created_vulnerability: '2025-01-22 10:34:56', updated_vulnerability: '2025-01-22 10:34:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98145', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98146', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'CCNS-DC7', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:05:27', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5042881", "5043167", "925673", "2538243", "2565063", "5037570", "5040711", "", "5042349", "890830"]', os_install_date: '1691513178.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '10.0.0.3', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2694', unique_id: '["ccns-dc7", "d0:27:88:e6:0e:a2"]', host_name: 'CCNS-DC7.ad.mycybercns.com', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-20 7:03:50', icon: 'windows.svg', status: 'true', hardware_model: 'AT-7000 Series', importance: '25', serial_number: 'THF10V040533000010', mac: 'd0:27:88:e6:0e:a2', manufacturer: 'Foxconn', physical_memory: '8589934592.0', uptime: '2665100.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:52:23', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3972', company_id: '9624', tenantid: '241996091870937089', id: '39195', created: '2025-01-20 7:03:50', updated: '2025-01-24 8:05:27', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:05:27', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.27', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39195', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98373', created_vulnerability: '2025-01-24 3:54:52', updated_vulnerability: '2025-01-24 3:54:52', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98046', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'INSPECT-365-EU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:57:30', logged_user_time: '1732882692.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5044025", "5044281", "5044414", "4052623", "890830", "5044099", "2267602"]', os_install_date: '1732882639.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '208.76.221.39', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2760', unique_id: '["inspect-365-eu", "5840671b-bda5-44b4-a0f9-ffb191e782b4", "79493383", "56:00:05:30:01:cf"]', host_name: 'Inspect-365-EU', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-22 10:08:37', icon: 'windows.svg', status: 'true', hardware_model: 'VOC', importance: '25', serial_number: '79493383', mac: '56:00:05:30:01:cf', manufacturer: 'Vultr', physical_memory: '4294967296.0', uptime: '4822302.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 12:56:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4018', company_id: '9638', tenantid: '241996091870937089', id: '39391', created: '2025-01-22 10:08:37', updated: '2025-01-24 7:57:30', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:57:30', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2762', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39391', company_id_vulnerability: '9638', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98368', created_vulnerability: '2025-01-24 1:17:20', updated_vulnerability: '2025-01-24 1:17:20', suppressed_till: '2123-12-31 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98047', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98147', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98148', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98149', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98150', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98151', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:52:37', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:50:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '22819.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:50:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39535"}, {"status": true, "protocol": "NMAP", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39891', created: '2025-01-23 18:50:11', updated: '2025-01-23 18:52:37', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:52:37', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39891', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98294', created_vulnerability: '2025-01-23 18:52:38', updated_vulnerability: '2025-01-23 18:52:38', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98048', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98049', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:04:09', logged_user_time: '1737745949.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "aeb90eeb-594a-49ef-9a20-e3693e8be749", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV.lego.in', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 8:41:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '148018.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:58:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4015', company_id: '9633', tenantid: '241996091870937089', id: '39379', created: '2025-01-22 8:41:34', updated: '2025-01-24 6:04:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:04:09', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39379', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97828', created_vulnerability: '2025-01-23 10:58:36', updated_vulnerability: '2025-01-23 10:58:36', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98395', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97873', created_vulnerability: '2025-01-22 10:34:56', updated_vulnerability: '2025-01-22 10:34:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97875', created_vulnerability: '2025-01-22 10:34:56', updated_vulnerability: '2025-01-22 10:34:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97954', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98396', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97876', created_vulnerability: '2025-01-22 10:34:56', updated_vulnerability: '2025-01-22 10:34:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97877', created_vulnerability: '2025-01-22 10:34:56', updated_vulnerability: '2025-01-22 10:34:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98050', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98051', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98052', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98053', created_vulnerability: '2025-01-23 7:01:12', updated_vulnerability: '2025-01-23 7:01:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97955', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97956', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98391', created_vulnerability: '2025-01-24 5:43:28', updated_vulnerability: '2025-01-24 5:43:28', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-CQMLC1GEVCU', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 6:41:52', logged_user_time: '1737462420.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4512577", "4512578"]', os_install_date: '1709288946.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.235', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-cqmlc1gevcu", "b6:da:01:5f:bc:55"]', host_name: 'WIN-CQMLC1GEVCU', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:29:13', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'b6:da:01:5f:bc:55', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '64895.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 6:29:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39280', created: '2025-01-22 6:29:13', updated: '2025-01-22 6:41:52', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 6:41:52', scan_status: 'false', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39280', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97697', created_vulnerability: '2025-01-22 6:29:19', updated_vulnerability: '2025-01-22 6:29:19', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98397', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98152', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98153', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98154', created_vulnerability: '2025-01-23 11:07:12', updated_vulnerability: '2025-01-23 11:07:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:48:23', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:30:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '107021.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:22', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39285', created: '2025-01-22 6:30:20', updated: '2025-01-23 18:48:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:48:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39285', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97698', created_vulnerability: '2025-01-23 7:01:30', updated_vulnerability: '2025-01-23 7:01:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:55:54', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "28:d2:44:1c:ee:45"]', host_name: 'WIN-J7J1G5810LF', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:50:39', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '28859.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:55:52', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39894', created: '2025-01-23 18:50:39', updated: '2025-01-23 18:55:54', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:55:54', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39894', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98301', created_vulnerability: '2025-01-23 18:55:59', updated_vulnerability: '2025-01-23 18:55:59', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'WIN-J7J1G5810LF', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:29:23', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "03f9bc98-07f4-e211-bf94-28d2441cee45", "1003502001493", "28:d2:44:1c:ee:45", "1c:3e:84:e5:76:e1"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 9:15:55', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LENOVO', physical_memory: '8589934592.0', uptime: '70776.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 9:15:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3965', company_id: '9622', tenantid: '241996091870937089', id: '39383', created: '2025-01-22 9:15:55', updated: '2025-01-24 6:29:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:29:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39383', company_id_vulnerability: '9622', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98408', created_vulnerability: '2025-01-24 6:29:23', updated_vulnerability: '2025-01-24 6:29:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WINDOWS-11', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:17:09', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049624", "5027397", "5041655", "5050021", "5050113", "4052623", "5007651", "890830", "2267602", "4023057"]', os_install_date: '1735021631.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 11 Pro', ip: '10.0.1.38', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.22621.4746', unique_id: '["windows-11", "4d1d8cbb-e846-490e-be2f-678cee927c7d", "0e:c8:99:16:ab:a4"]', host_name: 'Windows-11', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 10:13:44', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '0e:c8:99:16:ab:a4', manufacturer: 'QEMU', physical_memory: '4294967296.0', uptime: '167268.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:55:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4017', company_id: '9633', tenantid: '241996091870937089', id: '39631', created: '2025-01-23 10:13:44', updated: '2025-01-24 8:17:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:17:09', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '22631.4751', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39631', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98439', created_vulnerability: '2025-01-24 8:17:09', updated_vulnerability: '2025-01-24 8:17:09', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98398', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98415', created_vulnerability: '2025-01-24 6:43:29', updated_vulnerability: '2025-01-24 6:43:29', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98414', created_vulnerability: '2025-01-24 6:43:29', updated_vulnerability: '2025-01-24 6:43:29', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97957', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97958', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97959', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97960', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97961', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:48:23', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:30:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '107021.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:22', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39285', created: '2025-01-22 6:30:20', updated: '2025-01-23 18:48:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:48:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39285', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98278', created_vulnerability: '2025-01-23 18:48:24', updated_vulnerability: '2025-01-23 18:48:24', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98399', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98400', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98401', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:55:54', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "28:d2:44:1c:ee:45"]', host_name: 'WIN-J7J1G5810LF', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:50:39', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '28859.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:55:52', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39894', created: '2025-01-23 18:50:39', updated: '2025-01-23 18:55:54', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:55:54', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39894', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98302', created_vulnerability: '2025-01-23 18:55:59', updated_vulnerability: '2025-01-23 18:55:59', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WINDOWS-11', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:17:09', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049624", "5027397", "5041655", "5050021", "5050113", "4052623", "5007651", "890830", "2267602", "4023057"]', os_install_date: '1735021631.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 11 Pro', ip: '10.0.1.38', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.22621.4746', unique_id: '["windows-11", "4d1d8cbb-e846-490e-be2f-678cee927c7d", "0e:c8:99:16:ab:a4"]', host_name: 'Windows-11', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 10:13:44', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '0e:c8:99:16:ab:a4', manufacturer: 'QEMU', physical_memory: '4294967296.0', uptime: '167268.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:55:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4017', company_id: '9633', tenantid: '241996091870937089', id: '39631', created: '2025-01-23 10:13:44', updated: '2025-01-24 8:17:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:17:09', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '22631.4751', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39631', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98438', created_vulnerability: '2025-01-24 8:17:09', updated_vulnerability: '2025-01-24 8:17:09', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97711', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-CQMLC1GEVCU', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 6:41:52', logged_user_time: '1737462420.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4512577", "4512578"]', os_install_date: '1709288946.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.235', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-cqmlc1gevcu", "b6:da:01:5f:bc:55"]', host_name: 'WIN-CQMLC1GEVCU', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:29:13', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'b6:da:01:5f:bc:55', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '64895.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 6:29:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39280', created: '2025-01-22 6:29:13', updated: '2025-01-22 6:41:52', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 6:41:52', scan_status: 'false', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39280', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '97707', created_vulnerability: '2025-01-22 6:41:54', updated_vulnerability: '2025-01-22 6:41:54', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-CQMLC1GEVCU', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 6:41:52', logged_user_time: '1737462420.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4512577", "4512578"]', os_install_date: '1709288946.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.235', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-cqmlc1gevcu", "b6:da:01:5f:bc:55"]', host_name: 'WIN-CQMLC1GEVCU', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:29:13', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'b6:da:01:5f:bc:55', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '64895.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 6:29:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39280', created: '2025-01-22 6:29:13', updated: '2025-01-22 6:41:52', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 6:41:52', scan_status: 'false', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39280', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '97709', created_vulnerability: '2025-01-22 6:41:54', updated_vulnerability: '2025-01-22 6:41:54', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-CQMLC1GEVCU', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 6:41:52', logged_user_time: '1737462420.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4512577", "4512578"]', os_install_date: '1709288946.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.235', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-cqmlc1gevcu", "b6:da:01:5f:bc:55"]', host_name: 'WIN-CQMLC1GEVCU', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:29:13', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'b6:da:01:5f:bc:55', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '64895.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 6:29:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39280', created: '2025-01-22 6:29:13', updated: '2025-01-22 6:41:52', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 6:41:52', scan_status: 'false', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39280', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97708', created_vulnerability: '2025-01-22 6:41:54', updated_vulnerability: '2025-01-22 6:41:54', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97962', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97963', created_vulnerability: '2025-01-22 17:26:37', updated_vulnerability: '2025-01-22 17:26:37', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98402', created_vulnerability: '2025-01-24 6:05:49', updated_vulnerability: '2025-01-24 6:05:49', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'CCNS-DC7', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:05:27', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5042881", "5043167", "925673", "2538243", "2565063", "5037570", "5040711", "", "5042349", "890830"]', os_install_date: '1691513178.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard', ip: '10.0.0.3', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2694', unique_id: '["ccns-dc7", "d0:27:88:e6:0e:a2"]', host_name: 'CCNS-DC7.ad.mycybercns.com', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-20 7:03:50', icon: 'windows.svg', status: 'true', hardware_model: 'AT-7000 Series', importance: '25', serial_number: 'THF10V040533000010', mac: 'd0:27:88:e6:0e:a2', manufacturer: 'Foxconn', physical_memory: '8589934592.0', uptime: '2665100.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:52:23', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3972', company_id: '9624', tenantid: '241996091870937089', id: '39195', created: '2025-01-20 7:03:50', updated: '2025-01-24 8:05:27', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:05:27', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.27', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39195', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98374', created_vulnerability: '2025-01-24 3:54:52', updated_vulnerability: '2025-01-24 3:54:52', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98244', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98062', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98063', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98064', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98065', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97712', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97713', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98066', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97714', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98417', created_vulnerability: '2025-01-24 7:08:43', updated_vulnerability: '2025-01-24 7:08:43', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97715', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97716', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97717', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97718', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97719', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97720', created_vulnerability: '2025-01-22 6:43:00', updated_vulnerability: '2025-01-22 6:43:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98419', created_vulnerability: '2025-01-24 7:08:43', updated_vulnerability: '2025-01-24 7:08:43', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:43:07', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:37:31', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '106810.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39863', created: '2025-01-23 18:37:31', updated: '2025-01-23 18:43:07', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:43:07', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39863', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98241', created_vulnerability: '2025-01-23 18:37:40', updated_vulnerability: '2025-01-23 18:37:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98127', created_vulnerability: '2025-01-23 9:57:46', updated_vulnerability: '2025-01-23 9:57:46', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98067', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98068', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97764', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98069', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98070', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98071', created_vulnerability: '2025-01-23 7:24:40', updated_vulnerability: '2025-01-23 7:24:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98418', created_vulnerability: '2025-01-24 7:08:43', updated_vulnerability: '2025-01-24 7:08:43', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:43:07', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:37:31', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '106810.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39863', created: '2025-01-23 18:37:31', updated: '2025-01-23 18:43:07', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:43:07', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39863', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98270', created_vulnerability: '2025-01-23 18:43:08', updated_vulnerability: '2025-01-23 18:43:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'TEST-PROD', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:32:33', logged_user_time: '1737704004.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["3192137", "5034862", "5034767", "3193497", "4052623", "2267602"]', os_install_date: '1708689530.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2016 Standard', ip: '10.0.1.69', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.14393.6707', unique_id: '["test-prod", "8e:fc:4e:96:91:c2"]', host_name: 'Test-Prod.Connect.com', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-24 6:32:35', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '8e:fc:4e:96:91:c2', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '165199.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:32:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3359', company_id: '49', tenantid: '241996091870937089', id: '39999', created: '2025-01-24 6:32:35', updated: '2025-01-24 8:32:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:32:33', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '14393.6709', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39999', company_id_vulnerability: '49', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98410', created_vulnerability: '2025-01-24 6:32:40', updated_vulnerability: '2025-01-24 6:32:40', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN2012MS-TSNM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 12:01:06', logged_user_time: '1737633212.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["2894852", "2919355", "2919442", "2920189", "2938066", "2938772", "2939471", "2949621", "2954879", "2966826", "2966828", "2967917", "2968296", "2972103", "2972213", "2973114", "2973201", "2975061", "2976897", "2989930", "2999226", "3000483", "3000850", "3003057", "3004545", "3008242", "3010788", "3012702", "3013172", "3013410", "3013538", "3013791", "3013816", "3014442", "3019978", "3023219", "3023266", "3024751", "3024755", "3027209", "3030947", "3033446", "3036612", "3037576", "3038002", "3042058", "3042085", "3043812", "3044374", "3044673", "3045634", "3045685", "3045717", "3045719", "3045999", "3046017", "3046737", "3054203", "3054256", "3054464", "3055323", "3059317", "3060681", "3060793", "3061512", "3063843", "3071663", "3071756", "3072307", "3074545", "3077715", "3078405", "3080149", "3082089", "3084135", "3086255", "3087137", "3091297", "3094486", "3097992", "3100473", "3103616", "3103696", "3103709", "3109103", "3109976", "3110329", "3121261", "3122651", "3123245", "3126434", "3126587", "3127222", "3133043", "3133690", "3134179", "3137728", "3138602", "3139914", "3140219", "3145384", "3145432", "3146604", "3146751", "3147071", "3149157", "3156059", "3159398", "3161949", "3172614", "3178539", "3179574", "3185319", "4033428", "4040981", "4486105", "5012170", "5022508", "5022525", "5029915", "5030329", "5031003", "5031419", "925673", "2538243", "2565063", "4041085", "4049017", "5031228", "890830"]', os_install_date: '1692856120.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2012 R2 Standard Evaluation', ip: '10.0.1.36', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '6.3.9600.21620', unique_id: '["win2012ms-tsnm", "00:aa:bb:cc:dd:ee"]', host_name: 'WIN2012MS-Tsnm', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 9:51:46', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:aa:bb:cc:dd:ee', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '329.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 9:51:47', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3979', company_id: '9624', tenantid: '241996091870937089', id: '39390', created: '2025-01-22 9:51:46', updated: '2025-01-23 12:01:06', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 12:01:06', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB3013769", "KB3084905", "KB3102429"]', full_os_build: '9600.2162', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39390', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98176', created_vulnerability: '2025-01-23 12:01:22', updated_vulnerability: '2025-01-23 12:01:22', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN2012MS-TSNM', platform: 'windows', system_type: 'placeholder', agent_type: 'ONETIMESCAN', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 12:22:57', logged_user_time: '1737633212.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["2894852", "2919355", "2919442", "2920189", "2938066", "2938772", "2939471", "2949621", "2954879", "2966826", "2966828", "2967917", "2968296", "2972103", "2972213", "2973114", "2973201", "2975061", "2976897", "2989930", "2999226", "3000483", "3000850", "3003057", "3004545", "3008242", "3010788", "3012702", "3013172", "3013410", "3013538", "3013791", "3013816", "3014442", "3019978", "3023219", "3023266", "3024751", "3024755", "3027209", "3030947", "3033446", "3036612", "3037576", "3038002", "3042058", "3042085", "3043812", "3044374", "3044673", "3045634", "3045685", "3045717", "3045719", "3045999", "3046017", "3046737", "3054203", "3054256", "3054464", "3055323", "3059317", "3060681", "3060793", "3061512", "3063843", "3071663", "3071756", "3072307", "3074545", "3077715", "3078405", "3080149", "3082089", "3084135", "3086255", "3087137", "3091297", "3094486", "3097992", "3100473", "3103616", "3103696", "3103709", "3109103", "3109976", "3110329", "3121261", "3122651", "3123245", "3126434", "3126587", "3127222", "3133043", "3133690", "3134179", "3137728", "3138602", "3139914", "3140219", "3145384", "3145432", "3146604", "3146751", "3147071", "3149157", "3156059", "3159398", "3161949", "3172614", "3178539", "3179574", "3185319", "4033428", "4040981", "4486105", "5012170", "5022508", "5022525", "5029915", "5030329", "5031003", "5031419", "925673", "2538243", "2565063", "4041085", "4049017", "5031228", "890830"]', os_install_date: '1692856120.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2012 R2 Standard Evaluation', ip: '10.0.1.36', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '6.3.9600.21620', unique_id: '["win2012ms-tsnm", "9435a30d-993c-40aa-8e4b-b5c9989cb452"]', host_name: 'WIN2012MS-Tsnm', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:48:03', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:aa:bb:cc:dd:ee', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '1077.0', asset_category: 'offline', last_reset_time: '2025-01-23 12:22:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: 'placeholder', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4026', company_id: '9645', tenantid: '241996091870937089', id: '39755', created: '2025-01-23 11:48:03', updated: '2025-01-23 12:22:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 12:22:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB3013769", "KB3084905", "KB3102429"]', full_os_build: 'placeholder', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39755', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98196', created_vulnerability: '2025-01-23 12:22:57', updated_vulnerability: '2025-01-23 12:22:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98433', created_vulnerability: '2025-01-24 7:35:23', updated_vulnerability: '2025-01-24 7:35:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98092', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98093', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98094', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98095', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98432', created_vulnerability: '2025-01-24 7:35:23', updated_vulnerability: '2025-01-24 7:35:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:57:57', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["2e:c5:19:7e:06:7a", "win10-114"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:57:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '23306.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:57:55', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39345', created: '2025-01-22 6:57:11', updated: '2025-01-23 18:57:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:57:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39345', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98310', created_vulnerability: '2025-01-23 18:58:02', updated_vulnerability: '2025-01-23 18:58:02', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:58:41', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["28:d2:44:1c:ee:45", "win-j7j1g5810lf"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 6:54:19', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '29339.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:32:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": "39547"}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39334', created: '2025-01-22 6:54:19', updated: '2025-01-23 18:58:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:58:41', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'28:d2:44:1c:ee:45\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-J7J1G5810LF\', \'domain\': \'WIN-J7J1G5810LF\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.1.35\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:23:38.548994+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-J7J1G5810LF\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'WIN-J7J1G5810LF\', \'server_security\': \'SIGNING_ENABLED (not required)\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 37601, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 779.96, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:23:28.693281\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 779.96, \'max_rtt\': 1022.58, \'min_rtt\': 86.74, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 39.35, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389_error\': \'socket connection error while opening: [WinError 10061] No connection could be made because the target machine actively refused it\'}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:24PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.1.35\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-J7J1G5810LF\'}, \'basic_asset\': {\'mac\': \'28:d2:44:1c:ee:45\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-j7j1g5810lf\'], \'os_version\': \'10.0\', \'manufacturer\': \'\'', is_allowed: 'true', is_oval: 'false', asset_id: '39334', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98304', created_vulnerability: '2025-01-23 18:56:15', updated_vulnerability: '2025-01-23 18:56:15', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:57:57', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["2e:c5:19:7e:06:7a", "win10-114"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:57:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '23306.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:57:55', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39345', created: '2025-01-22 6:57:11', updated: '2025-01-23 18:57:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:57:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39345', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97742', created_vulnerability: '2025-01-23 18:58:00', updated_vulnerability: '2025-01-23 18:58:00', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98319', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-H9PVL6D65O8', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:42:48', logged_user_time: '1737728108.0', logged_in_user: 'hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5008882", "5011497", "5010523", "4052623", "2267602"]', os_install_date: '1719405249.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.217', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.587', unique_id: '["win-h9pvl6d65o8", "00:0c:29:5b:b2:27"]', host_name: 'WIN-H9PVL6D65O8.bingo.in', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 10:34:50', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9e 96 49 34 0a e9-32 c3 bf d8 5a 5b b2 27', mac: '00:0c:29:5b:b2:27', manufacturer: 'VMware, Inc.', physical_memory: '5716836352.0', uptime: '1534.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 10:34:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3291', company_id: '8344', tenantid: '241996091870937089', id: '39396', created: '2025-01-22 10:34:50', updated: '2025-01-24 6:42:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:42:48', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.587', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39396', company_id_vulnerability: '8344', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98392', created_vulnerability: '2025-01-24 5:43:28', updated_vulnerability: '2025-01-24 5:43:28', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:58:41', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["28:d2:44:1c:ee:45", "win-j7j1g5810lf"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 6:54:19', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '29339.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:32:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": "39547"}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39334', created: '2025-01-22 6:54:19', updated: '2025-01-23 18:58:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:58:41', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'28:d2:44:1c:ee:45\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-J7J1G5810LF\', \'domain\': \'WIN-J7J1G5810LF\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.1.35\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:23:38.548994+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-J7J1G5810LF\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'WIN-J7J1G5810LF\', \'server_security\': \'SIGNING_ENABLED (not required)\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 37601, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 779.96, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:23:28.693281\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 779.96, \'max_rtt\': 1022.58, \'min_rtt\': 86.74, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 39.35, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389_error\': \'socket connection error while opening: [WinError 10061] No connection could be made because the target machine actively refused it\'}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:24PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.1.35\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-J7J1G5810LF\'}, \'basic_asset\': {\'mac\': \'28:d2:44:1c:ee:45\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-j7j1g5810lf\'], \'os_version\': \'10.0\', \'manufacturer\': \'\'', is_allowed: 'true', is_oval: 'false', asset_id: '39334', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98305', created_vulnerability: '2025-01-23 18:56:15', updated_vulnerability: '2025-01-23 18:56:15', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98096', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98097', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98098', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98099', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98100', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98101', created_vulnerability: '2025-01-23 7:34:30', updated_vulnerability: '2025-01-23 7:34:30', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98245', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98320', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98321', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SVN2RHJ', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 8:09:23', logged_user_time: '1737523556.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5041579", "5043935", "5043130", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1724908067.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.28', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-svn2rhj", "310782b9-7c22-4dab-b410-509999dba9c8", "66:6b:0c:9f:2c:61"]', host_name: 'DESKTOP-SVN2RHJ', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-21 13:01:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '66:6b:0c:9f:2c:61', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '69742.0', asset_category: 'placeholder', last_reset_time: '2025-01-21 13:01:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3936', company_id: '9612', tenantid: '241996091870937089', id: '39244', created: '2025-01-21 13:01:20', updated: '2025-01-22 8:09:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 8:09:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39244', company_id_vulnerability: '9612', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '97825', created_vulnerability: '2025-01-22 8:09:23', updated_vulnerability: '2025-01-22 8:09:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97768', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:57:57', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["2e:c5:19:7e:06:7a", "win10-114"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:57:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '23306.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:57:55', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39345', created: '2025-01-22 6:57:11', updated: '2025-01-23 18:57:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:57:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39345', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98312', created_vulnerability: '2025-01-23 18:58:02', updated_vulnerability: '2025-01-23 18:58:02', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'true', remediated_on: '2025-01-23 18:56:44'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97759', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97760', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97761', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97762', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97763', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98444', created_vulnerability: '2025-01-24 8:53:52', updated_vulnerability: '2025-01-24 8:53:52', suppressed_till: '2025-01-21 18:31:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-72C84BF', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 9:24:44', logged_user_time: '1737623971.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4601554", "5000736", "5020683", "5048652", "5043130", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "2267602"]', os_install_date: '1729567942.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.27', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-72c84bf", "e19471d9-20ae-4dff-b2bb-e9e9d679a13a", "d2:71:cc:bd:e0:4f"]', host_name: 'DESKTOP-72C84BF', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 9:24:40', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: 'd2:71:cc:bd:e0:4f', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '10231.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 9:24:42', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4024', company_id: '9614', tenantid: '241996091870937089', id: '39526', created: '2025-01-23 9:24:40', updated: '2025-01-23 9:24:44', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:24:44', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19043.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39526', company_id_vulnerability: '9614', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98117', created_vulnerability: '2025-01-23 9:24:44', updated_vulnerability: '2025-01-23 9:24:44', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97765', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97766', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97767', created_vulnerability: '2025-01-22 7:07:27', updated_vulnerability: '2025-01-22 7:07:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98323', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN2012MS-TSNM', platform: 'windows', system_type: 'placeholder', agent_type: 'ONETIMESCAN', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 12:22:57', logged_user_time: '1737633212.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["2894852", "2919355", "2919442", "2920189", "2938066", "2938772", "2939471", "2949621", "2954879", "2966826", "2966828", "2967917", "2968296", "2972103", "2972213", "2973114", "2973201", "2975061", "2976897", "2989930", "2999226", "3000483", "3000850", "3003057", "3004545", "3008242", "3010788", "3012702", "3013172", "3013410", "3013538", "3013791", "3013816", "3014442", "3019978", "3023219", "3023266", "3024751", "3024755", "3027209", "3030947", "3033446", "3036612", "3037576", "3038002", "3042058", "3042085", "3043812", "3044374", "3044673", "3045634", "3045685", "3045717", "3045719", "3045999", "3046017", "3046737", "3054203", "3054256", "3054464", "3055323", "3059317", "3060681", "3060793", "3061512", "3063843", "3071663", "3071756", "3072307", "3074545", "3077715", "3078405", "3080149", "3082089", "3084135", "3086255", "3087137", "3091297", "3094486", "3097992", "3100473", "3103616", "3103696", "3103709", "3109103", "3109976", "3110329", "3121261", "3122651", "3123245", "3126434", "3126587", "3127222", "3133043", "3133690", "3134179", "3137728", "3138602", "3139914", "3140219", "3145384", "3145432", "3146604", "3146751", "3147071", "3149157", "3156059", "3159398", "3161949", "3172614", "3178539", "3179574", "3185319", "4033428", "4040981", "4486105", "5012170", "5022508", "5022525", "5029915", "5030329", "5031003", "5031419", "925673", "2538243", "2565063", "4041085", "4049017", "5031228", "890830"]', os_install_date: '1692856120.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2012 R2 Standard Evaluation', ip: '10.0.1.36', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '6.3.9600.21620', unique_id: '["win2012ms-tsnm", "9435a30d-993c-40aa-8e4b-b5c9989cb452"]', host_name: 'WIN2012MS-Tsnm', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:48:03', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:aa:bb:cc:dd:ee', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '1077.0', asset_category: 'offline', last_reset_time: '2025-01-23 12:22:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: 'placeholder', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4026', company_id: '9645', tenantid: '241996091870937089', id: '39755', created: '2025-01-23 11:48:03', updated: '2025-01-23 12:22:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 12:22:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB3013769", "KB3084905", "KB3102429"]', full_os_build: 'placeholder', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39755', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98197', created_vulnerability: '2025-01-23 12:22:57', updated_vulnerability: '2025-01-23 12:22:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-CQMLC1GEVCU', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 6:41:52', logged_user_time: '1737462420.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4512577", "4512578"]', os_install_date: '1709288946.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.235', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-cqmlc1gevcu", "b6:da:01:5f:bc:55"]', host_name: 'WIN-CQMLC1GEVCU', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:29:13', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'b6:da:01:5f:bc:55', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '64895.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 6:29:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39280', created: '2025-01-22 6:29:13', updated: '2025-01-22 6:41:52', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 6:41:52', scan_status: 'false', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39280', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '97710', created_vulnerability: '2025-01-22 6:41:54', updated_vulnerability: '2025-01-22 6:41:54', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98253', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN2012MS-TSNM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 12:01:06', logged_user_time: '1737633212.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["2894852", "2919355", "2919442", "2920189", "2938066", "2938772", "2939471", "2949621", "2954879", "2966826", "2966828", "2967917", "2968296", "2972103", "2972213", "2973114", "2973201", "2975061", "2976897", "2989930", "2999226", "3000483", "3000850", "3003057", "3004545", "3008242", "3010788", "3012702", "3013172", "3013410", "3013538", "3013791", "3013816", "3014442", "3019978", "3023219", "3023266", "3024751", "3024755", "3027209", "3030947", "3033446", "3036612", "3037576", "3038002", "3042058", "3042085", "3043812", "3044374", "3044673", "3045634", "3045685", "3045717", "3045719", "3045999", "3046017", "3046737", "3054203", "3054256", "3054464", "3055323", "3059317", "3060681", "3060793", "3061512", "3063843", "3071663", "3071756", "3072307", "3074545", "3077715", "3078405", "3080149", "3082089", "3084135", "3086255", "3087137", "3091297", "3094486", "3097992", "3100473", "3103616", "3103696", "3103709", "3109103", "3109976", "3110329", "3121261", "3122651", "3123245", "3126434", "3126587", "3127222", "3133043", "3133690", "3134179", "3137728", "3138602", "3139914", "3140219", "3145384", "3145432", "3146604", "3146751", "3147071", "3149157", "3156059", "3159398", "3161949", "3172614", "3178539", "3179574", "3185319", "4033428", "4040981", "4486105", "5012170", "5022508", "5022525", "5029915", "5030329", "5031003", "5031419", "925673", "2538243", "2565063", "4041085", "4049017", "5031228", "890830"]', os_install_date: '1692856120.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2012 R2 Standard Evaluation', ip: '10.0.1.36', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '6.3.9600.21620', unique_id: '["win2012ms-tsnm", "00:aa:bb:cc:dd:ee"]', host_name: 'WIN2012MS-Tsnm', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 9:51:46', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:aa:bb:cc:dd:ee', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '329.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 9:51:47', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3979', company_id: '9624', tenantid: '241996091870937089', id: '39390', created: '2025-01-22 9:51:46', updated: '2025-01-23 12:01:06', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 12:01:06', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB3013769", "KB3084905", "KB3102429"]', full_os_build: '9600.2162', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39390', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98177', created_vulnerability: '2025-01-23 12:01:22', updated_vulnerability: '2025-01-23 12:01:22', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98338', created_vulnerability: '2025-01-23 18:59:12', updated_vulnerability: '2025-01-23 18:59:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '98340', created_vulnerability: '2025-01-23 19:01:57', updated_vulnerability: '2025-01-23 19:01:57', suppressed_till: '2123-12-30 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98339', created_vulnerability: '2025-01-23 18:59:12', updated_vulnerability: '2025-01-23 18:59:12', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98437', created_vulnerability: '2025-01-24 8:14:44', updated_vulnerability: '2025-01-24 8:14:44', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98345', created_vulnerability: '2025-01-23 20:02:01', updated_vulnerability: '2025-01-23 20:02:01', suppressed_till: 'placeholder', is_remediated: 'true', remediated_on: '2025-01-24 2:03:28'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98314', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98315', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98316', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98317', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'placeholder', platform: 'Printer', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:46:18', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '[]', os_install_date: 'placeholder', os_autoupdate: 'placeholder', os_vendor: 'brother', snmp_info: '\'oids\': {\'1.3.6.1.4.1.6876.1.1.0\': [], \'1.3.6.1.4.1.6876.1.2.0\': [], \'1.3.6.1.4.1.6876.1.4.0\': [], \'1.3.6.1.2.1.25.3.2.1.3.1\': [\'Brother DCP-7065DN\'], \'1.3.6.1.2.1.47.1.1.1.1.9\': [], \'1.3.6.1.4.1.6574.1.5.1.0\': [], \'1.3.6.1.4.1.6574.1.5.2.0\': [], \'1.3.6.1.4.1.6574.1.5.3.0\': [], \'1.3.6.1.4.1.6574.1.5.4.0\': [], \'1.3.6.1.2.1.47.1.1.1.1.10\': [], \'1.3.6.1.2.1.47.1.1.1.1.12\': [], \'1.3.6.1.2.1.47.1.1.1.1.13\': [], \'1.3.6.1.2.1.47.1.1.1.1.18\': [], \'1.3.6.1.4.1.14988.1.1.4.4\': [], \'1.3.6.1.4.1.2604.5.1.1.2.0\': [], \'1.3.6.1.4.1.2604.5.1.1.3.0\': [], \'1.3.6.1.4.1.2604.5.1.1.4.0\': [], \'1.3.6.1.4.1.21067.2.1.1.1.0\': [], \'1.3.6.1.4.1.21067.2.1.1.2.0\': [], \'1.3.6.1.4.1.21067.2.1.1.3.0\': [], \'1.3.6.1.4.1.11.2.3.9.1.1.7.0\': [\'MFG:Brother;CMD:PJL,HBP;MDL:DCP-7065DN;CLS:PRINTER;CID:Brother Laser Type1;\'], \'1.3.6.1.4.1.1347.40.1.1.1.8.1\': [], \'1.3.6.1.4.1.674.10892.5.1.1.2\': [], \'1.3.6.1.4.1.674.10892.5.1.1.8\': [], \'1.3.6.1.4.1.25053.3.1.5.15.5.0\': [], \'1.3.6.1.4.1.25053.3.1.5.15.8.0\': [], \'1.3.6.1.4.1.11.2.4.3.1.12.1.2.4\': [], \'1.3.6.1.4.1.11.2.4.3.1.12.1.2.6\': []}, \'serial\': \'\', \'sysName\': \'BRN30055C2B025D\', \'isPrinter\': True, \'sysContact\': \'\', \'description\': \'Brother NC-8200h, Firmware Ver.1.05  (12.10.02),MID 8C5-E05,FID 2\', \'sysObjectId\': \'.1.3.6.1.4.1.2435.2.3.9.1\', \'deviceLocation\': \'\', \'default_snmp_string\': True, \'default_community_string\': \'public\'', codename: 'placeholder', ip: '10.0.0.221', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: 'placeholder', unique_id: '["brn30055c2b025d", "30:05:5c:2b:02:5d"]', host_name: 'BRN30055C2B025D', architecture: 'placeholder', cpu_core: 'placeholder', discovered: '2025-01-23 18:34:22', icon: 'brotheri.png', status: 'true', hardware_model: 'Brother NC-8200h', importance: '25', serial_number: 'placeholder', mac: '30:05:5C:2B:02:5D', manufacturer: 'Brother industries', physical_memory: 'placeholder', uptime: 'placeholder', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:34:25', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SNMP", "credential_id": "public"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39855', created: '2025-01-23 18:34:22', updated: '2025-01-23 18:46:18', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:46:18', scan_status: 'true', ad_check: 'placeholder', configuration_id: 'placeholder', install_required_patches: '[]', full_os_build: 'placeholder', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39855', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98275', created_vulnerability: '2025-01-23 18:46:20', updated_vulnerability: '2025-01-23 18:46:20', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98318', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:59:08', logged_user_time: '1737632412.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685", "2267602"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 18:58:43', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '26127.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:59:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39904', created: '2025-01-23 18:58:43', updated: '2025-01-23 18:59:08', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:59:08', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39904', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98322', created_vulnerability: '2025-01-23 18:59:08', updated_vulnerability: '2025-01-23 18:59:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98246', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98247', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98248', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98249', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98250', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98251', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98252', created_vulnerability: '2025-01-23 18:39:02', updated_vulnerability: '2025-01-23 18:39:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-TE7LP7E', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:14:41', logged_user_time: '1737613608.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732617397.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.18', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-te7lp7e", "00:0c:29:66:50:86"]', host_name: 'DESKTOP-TE7LP7E', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 7:34:24', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 72 b7 1a fc 39 31-d3 97 6d 05 de 66 50 86', mac: '00:0c:29:66:50:86', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '89092.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:34:28', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"MAC": ["Machine"], "hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4023', company_id: '6', tenantid: '241996091870937089', id: '39468', created: '2025-01-23 7:34:24', updated: '2025-01-24 8:14:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:14:41', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39468', company_id_vulnerability: '6', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98436', created_vulnerability: '2025-01-24 8:14:44', updated_vulnerability: '2025-01-24 8:14:44', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:04:09', logged_user_time: '1737745949.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "aeb90eeb-594a-49ef-9a20-e3693e8be749", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV.lego.in', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 8:41:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '148018.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 10:58:32', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4015', company_id: '9633', tenantid: '241996091870937089', id: '39379', created: '2025-01-22 8:41:34', updated: '2025-01-24 6:04:09', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:04:09', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39379', company_id_vulnerability: '9633', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98380', created_vulnerability: '2025-01-24 5:08:27', updated_vulnerability: '2025-01-24 5:08:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:39:02', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:38:27', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43262.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:39:00', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39866', created: '2025-01-23 18:38:27', updated: '2025-01-23 18:39:02', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:39:02', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39866', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98267', created_vulnerability: '2025-01-23 18:39:07', updated_vulnerability: '2025-01-23 18:39:07', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:48:23', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:30:20', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '107021.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:22', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39285', created: '2025-01-22 6:30:20', updated: '2025-01-23 18:48:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:48:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39285', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98279', created_vulnerability: '2025-01-23 18:48:24', updated_vulnerability: '2025-01-23 18:48:24', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-49UKSG837PV', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:43:07', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049608", "4512577", "4577586", "4589208", "5012170", "4512578", "5050110", "4052623", "890830", "5050182", "2267602"]', os_install_date: '1737525817.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.0.244', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-49uksg837pv", "be:cf:df:b5:63:ab"]', host_name: 'WIN-49UKSG837PV', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:37:31', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: 'be:cf:df:b5:63:ab', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '106810.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39863', created: '2025-01-23 18:37:31', updated: '2025-01-23 18:43:07', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:43:07', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39863', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98271', created_vulnerability: '2025-01-23 18:43:08', updated_vulnerability: '2025-01-23 18:43:08', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'WIN-J7J1G5810LF', auth_scan_status: 'true', last_discovered_time: '2025-01-24 6:29:23', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "03f9bc98-07f4-e211-bf94-28d2441cee45", "1003502001493", "28:d2:44:1c:ee:45", "1c:3e:84:e5:76:e1"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 9:15:55', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LENOVO', physical_memory: '8589934592.0', uptime: '70776.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 9:15:57', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3965', company_id: '9622', tenantid: '241996091870937089', id: '39383', created: '2025-01-22 9:15:55', updated: '2025-01-24 6:29:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 6:29:23', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39383', company_id_vulnerability: '9622', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98409', created_vulnerability: '2025-01-24 6:29:23', updated_vulnerability: '2025-01-24 6:29:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:14:31', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "07e844eb-b001-4747-ad4d-5eed14c609fd", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 12:43:29', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '67329.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 12:43:31', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4027', company_id: '9645', tenantid: '241996091870937089', id: '39776', created: '2025-01-23 12:43:29', updated: '2025-01-24 7:14:31', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:14:31', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39776', company_id_vulnerability: '9645', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98424', created_vulnerability: '2025-01-24 7:14:32', updated_vulnerability: '2025-01-24 7:14:32', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97621', created_vulnerability: '2025-01-21 17:43:56', updated_vulnerability: '2025-01-21 17:43:56', suppressed_till: 'placeholder', is_remediated: 'true', remediated_on: '2025-01-21 4:27:16'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:52:37', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["win10-114", "2e:c5:19:7e:06:7a"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-23 18:50:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '22819.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:50:15', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39535"}, {"status": true, "protocol": "NMAP", "credential_id": "39535"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39891', created: '2025-01-23 18:50:11', updated: '2025-01-23 18:52:37', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:52:37', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39891', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98292', created_vulnerability: '2025-01-23 18:52:38', updated_vulnerability: '2025-01-23 18:52:38', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:45:33', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 6:59:38', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware', physical_memory: '6077546496.0', uptime: '43566.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:01:06', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39547"}, {"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39438', created: '2025-01-23 6:59:38', updated: '2025-01-23 18:45:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:45:33', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:2c:9c:5f\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-23\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-B4FGOT8OSFM\', \'domain\': \'BANANNA\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.0.211\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-23T01:24:03.345915+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dns_tree_name\': \'bananna.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'bananna.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 63622, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 11.48, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-23T12:28:57.032699\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 11.48, \'max_rtt\': 23.17, \'min_rtt\': 0, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 27.199, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.0.211:389\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.0.211:3268\', \'dnsHostName\': \'WIN-B4FGOT8OSFM.bananna.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-B4FGOT8OSFM,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=bananna,DC=com\', \'namingContexts\': [\'DC=bananna,DC=com\', \'CN=Configuration,DC=bananna,DC=com\', \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'DC=DomainDnsZones,DC=bananna,DC=com\', \'DC=ForestDnsZones,DC=bananna,DC=com\'], \'ldapServiceName\': \'bananna.com:win-b4fgot8osfm$@BANANNA.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=bananna,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=bananna,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 23 2025 12:29PM [UTC+4] (Thu)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.0.211\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-B4FGOT8OSFM\'}, \'basic_asset\': {\'mac\': \'00:0c:29:2c:9c:5f\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-b4fgot8osfm\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39438', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98274', created_vulnerability: '2025-01-23 18:45:34', updated_vulnerability: '2025-01-23 18:45:34', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:57:57', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["2e:c5:19:7e:06:7a", "win10-114"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:57:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '23306.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:57:55', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39345', created: '2025-01-22 6:57:11', updated: '2025-01-23 18:57:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:57:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39345', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98311', created_vulnerability: '2025-01-23 18:58:02', updated_vulnerability: '2025-01-23 18:58:02', suppressed_till: 'placeholder', is_remediated: 'true', remediated_on: '2025-01-23 18:56:44'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-R1I4U1S', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 11:17:51', logged_user_time: '1737543915.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5011048", "5015684", "5033052", "5049981", "5014032", "5025315", "5041579", "5043935", "5043130", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1646835591.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Home Single Language', ip: '172.168.1.11', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["5dvgn42", "fc:77:74:39:ed:b0", "desktop-r1i4u1s", "4c4c4544-0044-5610-8047-b5c04f4e3432"]', host_name: 'DESKTOP-R1I4U1S', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 5:27:10', icon: 'windows.svg', status: 'true', hardware_model: 'Inspiron 5370', importance: '25', serial_number: '5DVGN42', mac: '0a:00:27:00:00:16', manufacturer: 'Dell Inc.', physical_memory: '8589934592.0', uptime: '436.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 5:27:14', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4006', company_id: '8136', tenantid: '241996091870937089', id: '39247', created: '2025-01-22 5:27:10', updated: '2025-01-22 11:17:51', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 11:17:51', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39247', company_id_vulnerability: '8136', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97894', created_vulnerability: '2025-01-22 11:17:57', updated_vulnerability: '2025-01-22 11:17:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:55:54', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["win-j7j1g5810lf", "28:d2:44:1c:ee:45"]', host_name: 'WIN-J7J1G5810LF', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 18:50:39', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '28859.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:55:52', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "SMB", "credential_id": "39536"}, {"status": true, "protocol": "NMAP", "credential_id": "39536"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39894', created: '2025-01-23 18:50:39', updated: '2025-01-23 18:55:54', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:55:54', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39894', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98303', created_vulnerability: '2025-01-23 18:55:59', updated_vulnerability: '2025-01-23 18:55:59', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-LFTCTR2', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 9:23:36', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227779.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.2', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5247', unique_id: '["desktop-lftctr2", "00:0c:29:18:37:35"]', host_name: 'DESKTOP-LFTCTR2', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-23 11:07:04', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d ac db 52 24 eb 1a-ac 51 d4 c9 d2 18 37 35', mac: '00:0c:29:18:37:35', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '93119.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 11:07:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4025', company_id: '9644', tenantid: '241996091870937089', id: '39669', created: '2025-01-23 11:07:04', updated: '2025-01-24 9:23:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 9:23:36', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5247', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39669', company_id_vulnerability: '9644', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98416', created_vulnerability: '2025-01-24 6:43:29', updated_vulnerability: '2025-01-24 6:43:29', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-R1I4U1S', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-22 11:17:51', logged_user_time: '1737543915.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5042056", "5011048", "5015684", "5033052", "5049981", "5014032", "5025315", "5041579", "5043935", "5043130", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1646835591.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Home Single Language', ip: '172.168.1.11', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["5dvgn42", "fc:77:74:39:ed:b0", "desktop-r1i4u1s", "4c4c4544-0044-5610-8047-b5c04f4e3432"]', host_name: 'DESKTOP-R1I4U1S', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 5:27:10', icon: 'windows.svg', status: 'true', hardware_model: 'Inspiron 5370', importance: '25', serial_number: '5DVGN42', mac: '0a:00:27:00:00:16', manufacturer: 'Dell Inc.', physical_memory: '8589934592.0', uptime: '436.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 5:27:14', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4006', company_id: '8136', tenantid: '241996091870937089', id: '39247', created: '2025-01-22 5:27:10', updated: '2025-01-22 11:17:51', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-22 11:17:51', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39247', company_id_vulnerability: '8136', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '97895', created_vulnerability: '2025-01-22 11:17:57', updated_vulnerability: '2025-01-22 11:17:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-J7J1G5810LF', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:58:41', logged_user_time: '1737628534.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049617", "5049983", "5044414", "5050117", "925673", "2538243", "2565063", "3085538", "2920724", "2920678", "2920720", "3114903", "3115081", "3115407", "3118262", "3118264", "3118263", "3191929", "3152281", "3213650", "3213551", "4011259", "4011574", "4011634", "4022193", "4022176", "4022219", "2920717", "4464538", "4032236", "4032254", "4011629", "4484145", "2920709", "4052623", "4484171", "4462117", "4484103", "3114524", "3118335", "4484104", "4462148", "5002251", "3191869", "5002244", "4011621", "4475581", "4464587", "5029497", "5002522", "5002469", "5002466", "5002340", "5002050", "5002567", "5002585", "5002594", "5002575", "5002634", "5002566", "5002635", "5002619", "4475587", "2920716", "5002652", "5002632", "890830", "5002656", "5002595", "5002675", "5002673", "5002670", "5050187", "2267602"]', os_install_date: '1730309747.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.1.35', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.3089', unique_id: '["28:d2:44:1c:ee:45", "win-j7j1g5810lf"]', host_name: 'WIN-J7J1G5810LF.ad.mycybercns.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-22 6:54:19', icon: 'windows.svg', status: 'true', hardware_model: '20217', importance: '25', serial_number: '1.0035E+12', mac: '28:d2:44:1c:ee:45', manufacturer: 'LCFC(HeFei) Electronics Technology', physical_memory: '8589934592.0', uptime: '29339.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:32:09', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": "39547"}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39334', created: '2025-01-22 6:54:19', updated: '2025-01-23 18:58:41', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:58:41', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.3091', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'28:d2:44:1c:ee:45\', \'fp.os.cpe23\': \'cpe:/o:microsoft:windows_10:-\', \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'\', \'ip.ttl.osGuess\': \'Windows\', \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': \'windows-10\'}, \'DNS\': {\'name\': \'WIN-J7J1G5810LF\', \'domain\': \'WIN-J7J1G5810LF\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.1.35\', \'os_version\': \'Windows NT 10.0 Build 20348\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:23:38.548994+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-J7J1G5810LF\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'WIN-J7J1G5810LF\', \'server_security\': \'SIGNING_ENABLED (not required)\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 37601, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 779.96, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:23:28.693281\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 779.96, \'max_rtt\': 1022.58, \'min_rtt\': 86.74, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 39.35, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389_error\': \'socket connection error while opening: [WinError 10061] No connection could be made because the target machine actively refused it\'}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:24PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.1.35\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-J7J1G5810LF\'}, \'basic_asset\': {\'mac\': \'28:d2:44:1c:ee:45\', \'os_name\': \'Windows NT\', \'os_build\': \'20348\', \'host_name\': [\'win-j7j1g5810lf\'], \'os_version\': \'10.0\', \'manufacturer\': \'\'', is_allowed: 'true', is_oval: 'false', asset_id: '39334', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98306', created_vulnerability: '2025-01-23 18:56:15', updated_vulnerability: '2025-01-23 18:56:15', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-261DKMI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:08:33', logged_user_time: '1737704001.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049613", "5015684", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736227690.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.15', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.2965', unique_id: '["desktop-261dkmi", "00:0c:29:7a:7b:4c"]', host_name: 'DESKTOP-261DKMI', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-24 6:05:42', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 39 29 c6 fa 31 a7-7c 05 e3 50 93 7a 7b 4c', mac: '00:0c:29:7a:7b:4c', manufacturer: 'VMware, Inc.', physical_memory: '4294967296.0', uptime: '87204.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 6:05:46', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4028', company_id: '9648', tenantid: '241996091870937089', id: '39998', created: '2025-01-24 6:05:42', updated: '2025-01-24 8:08:33', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:08:33', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: '["KB5011048"]', full_os_build: '19045.2965', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39998', company_id_vulnerability: '9648', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98420', created_vulnerability: '2025-01-24 7:08:43', updated_vulnerability: '2025-01-24 7:08:43', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN10-114', platform: 'windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 18:57:57', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5050576", "5028951", "5011048", "5015684", "5020683", "5033052", "5050081", "5014032", "5025315", "5026879", "5028318", "5028380", "5029709", "5031539", "5039336", "5040565", "5041579", "5041581", "5043935", "5043130", "5046823", "5050388", "5050111", "925673", "4052623", "5001148", "5037570", "5001716", "5047486", "890830", "5050593", "2267602", "4023057"]', os_install_date: '1687259061.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.17', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5435', unique_id: '["2e:c5:19:7e:06:7a", "win10-114"]', host_name: 'WIN10-114', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-22 6:57:11', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '2e:c5:19:7e:06:7a', manufacturer: 'QEMU', physical_memory: '2149580800.0', uptime: '23306.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 18:57:55', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}, {"status": true, "protocol": "SMB", "credential_id": "39547"}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Workstation"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39345', created: '2025-01-22 6:57:11', updated: '2025-01-23 18:57:57', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 18:57:57', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5435', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39345', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98313', created_vulnerability: '2025-01-23 18:58:02', updated_vulnerability: '2025-01-23 18:58:02', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-LPBKU1NSM0O', platform: 'Windows', system_type: 'placeholder', agent_type: 'PROBE', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 19:01:55', logged_user_time: '1737458892.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5020627", "5048661", "5020374", "5034863", "5043126", "4052623", "5020685"]', os_install_date: '1730957148.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.2.21', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6640', unique_id: '["win-lpbku1nsm0o", "00:0c:29:91:49:0f"]', host_name: 'WIN-LPBKU1NSM0O', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 7:05:49', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d a9 05 e1 09 18 06-90 9a 60 66 9f 91 49 0f', mac: '00:0c:29:91:49:0f', manufacturer: 'VMware', physical_memory: '4294967296.0', uptime: '70504.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 19:01:53', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "NMAP", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"sc": ["dsf"], "abc": ["def"], "qwer": ["123"], "JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "magggg": ["21"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3987', company_id: '9624', tenantid: '241996091870937089', id: '39364', created: '2025-01-22 7:05:49', updated: '2025-01-23 19:01:55', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 19:01:55', scan_status: 'true', ad_check: 'Domain Joined', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6659', finger_print: '\'ARP\': {\'source\': \'arp\', \'arp.mac\': \'00:0c:29:91:49:0f\', \'fp.os.cpe23\': None, \'fp.os.source\': \'rz-ttl\', \'arp.macVendor\': \'VMware, Inc.\', \'ip.ttl.osGuess\': None, \'arp.macDateAdded\': \'2025-01-22\', \'ip.ttl.osGuessDetail\': None}, \'DNS\': {\'name\': \'WIN-LPBKU1NSM0O\', \'domain\': \'PING\', \'product\': None, \'dns.rtts\': None, \'protocol\': \'dns\', \'dns.addrs\': \'10.0.2.21\', \'os_version\': \'Windows NT 10.0 Build 17763\', \'dns.replies\': [], \'current_time\': \'2025-01-22T01:34:30.644053+00:00\', \'Max_read_size\': \'8.0 MB (8388608 bytes)\', \'SMBv1_enabled\': False, \'dns.id.server\': None, \'dns.resolvers\': [], \'dns_host_name\': \'WIN-LPBKU1NSM0O.ping.com\', \'dns_tree_name\': \'ping.com\', \'Max_write_size\': \'8.0 MB (8388608 bytes)\', \'dns_domain_name\': \'ping.com\', \'server_security\': \'SIGNING_ENABLED | SIGNING_REQUIRED\', \'dns.version.bind\': None, \'prefered_dialect\': \'SMB 3.0\', \'dns.hostname.bind\': None, \'dns.version.server\': None}, \'TLS\': {}, \'ICMP\': {\'ip.id\': 19946, \'ip.len\': 28, \'ip.tos\': 0, \'ip.ttl\': 128, \'ip.frag\': 0, \'icmp.rtt\': 1016.94, \'ip.flags\': \'\', \'ip.proto\': 1, \'path.mtu\': 1400, \'timestamp\': \'2025-01-22T12:34:54.740663\', \'ip.options\': \'null\', \'ping_stats\': {\'avg_rtt\': 1016.94, \'max_rtt\': 1052.78, \'min_rtt\': 1002.69, \'packet_loss\': 0}, \'icmp.typeCode\': \'EchoReply\', \'scan_duration\': 44.895, \'icmp.typeCodeN\': \'0/0\', \'duplicate_packets\': False}, \'LDAP\': {\'ldap_389\': {\'port\': 389, \'serverName\': \'ldap://10.0.2.21:389\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}, \'ldap_3268\': {\'port\': 3268, \'serverName\': \'ldap://10.0.2.21:3268\', \'dnsHostName\': \'WIN-LPBKU1NSM0O.ping.com\', \'dsServiceName\': \'CN=NTDS Settings,CN=WIN-LPBKU1NSM0O,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=ping,DC=com\', \'namingContexts\': [\'DC=ping,DC=com\', \'CN=Configuration,DC=ping,DC=com\', \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'DC=DomainDnsZones,DC=ping,DC=com\', \'DC=ForestDnsZones,DC=ping,DC=com\'], \'ldapServiceName\': \'ping.com:win-lpbku1nsm0o$@PING.COM\', \'domainFunctionality\': \'7\', \'forestFunctionality\': \'7\', \'schemaNamingContext\': \'CN=Schema,CN=Configuration,DC=ping,DC=com\', \'supportedLDAPVersions\': [\'3\', \'2\'], \'rootDomainNamingContext\': \'DC=ping,DC=com\', \'domainControllerFunctionality\': \'7\'}}, \'MDNS\': {\'ts\': \'Jan 22 2025 12:35PM [UTC+4] (Wed)\', \'protocol\': \'mdns\'}, \'SNMP\': {}, \'23/TCP\': {}, \'BANNER\': {}, \'VMWARE\': {}, \'NETBIOS\': {\'status\': \'unknown\', \'address\': \'10.0.2.21\', \'protocol\': \'netbios-ns\', \'host_name\': None, \'netbios_name\': \'WIN-LPBKU1NSM0O\'}, \'basic_asset\': {\'mac\': \'00:0c:29:91:49:0f\', \'os_name\': \'Windows NT\', \'os_build\': \'17763\', \'host_name\': [\'win-lpbku1nsm0o\'], \'os_version\': \'10.0\', \'manufacturer\': \'VMware, Inc.\'', is_allowed: 'true', is_oval: 'false', asset_id: '39364', company_id_vulnerability: '9624', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98341', created_vulnerability: '2025-01-23 19:01:57', updated_vulnerability: '2025-01-23 19:01:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-5T086BK', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:35:23', logged_user_time: '1737540944.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144225.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.0.185', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-5t086bk", "609a4d56-e285-c7e6-f233-97dba3683b7e", "vmware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e", "00:0c:29:68:3b:7e"]', host_name: 'DESKTOP-5T086BK', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 17:26:31', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 9a 60 85 e2 e6 c7-f2 33 97 db a3 68 3b 7e', mac: '00:0c:29:68:3b:7e', manufacturer: 'VMware, Inc.', physical_memory: '4349493248.0', uptime: '162911.0', asset_category: 'placeholder', last_reset_time: '2025-01-22 17:26:34', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3934', company_id: '9610', tenantid: '241996091870937089', id: '39400', created: '2025-01-22 17:26:31', updated: '2025-01-24 7:35:23', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:35:23', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39400', company_id_vulnerability: '9610', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98434', created_vulnerability: '2025-01-24 7:35:23', updated_vulnerability: '2025-01-24 7:35:23', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-SI6HCLS', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'placeholder', last_discovered_time: '2025-01-23 9:57:43', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5045936", "5000736", "5011048", "5015684", "5020683", "5033052", "5049981", "5046823", "5050388", "5001405", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1736144322.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '[]', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.87', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["desktop-si6hcls", "756a4d56-abd0-6f1b-a252-5bbdf54bfafc", "vmware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc", "00:0c:29:4b:fa:fc", "desktop-si6hcls"]', host_name: 'DESKTOP-SI6HCLS', architecture: '64-bit', cpu_core: '3.0', discovered: '2025-01-22 6:42:57', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d 6a 75 d0 ab 1b 6f-a2 52 5b bd f5 4b fa fc', mac: '00:0c:29:4b:fa:fc', manufacturer: 'placeholder', physical_memory: '4349493248.0', uptime: '649.0', asset_category: 'placeholder', last_reset_time: 'placeholder', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["NOTAGS"], "compatible": ["100"], "Scan Status": ["Not Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"]}', manual_tags: '{}', agent_id: '3951', company_id: '9615', tenantid: '241996091870937089', id: '39315', created: '2025-01-22 6:42:57', updated: '2025-01-23 9:57:43', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:57:43', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39315', company_id_vulnerability: '9615', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98128', created_vulnerability: '2025-01-23 9:57:46', updated_vulnerability: '2025-01-23 9:57:46', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-B4FGOT8OSFM', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:43:36', logged_user_time: '1737694302.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5041948", "5048654", "5043167", "5044414", "4052623", "5042349", "890830", "2267602"]', os_install_date: '1719405545.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2022 Standard Evaluation', ip: '10.0.0.211', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.20348.2965', unique_id: '["win-b4fgot8osfm", "vmware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f", "a2d74d56-f846-eff6-e0b9-52487a2c9c5f", "00:0c:29:2c:9c:5f"]', host_name: 'WIN-B4FGOT8OSFM.bananna.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2025-01-23 7:24:35', icon: 'windows.svg', status: 'true', hardware_model: 'VMware Virtual Platform', importance: '25', serial_number: 'VMware-56 4d d7 a2 46 f8 f6 ef-e0 b9 52 48 7a 2c 9c 5f', mac: '00:0c:29:2c:9c:5f', manufacturer: 'VMware, Inc.', physical_memory: '6077546496.0', uptime: '93988.0', asset_category: 'placeholder', last_reset_time: '2025-01-23 7:24:38', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '4021', company_id: '9549', tenantid: '241996091870937089', id: '39458', created: '2025-01-23 7:24:35', updated: '2025-01-24 8:43:36', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:43:36', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '20348.2966', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39458', company_id_vulnerability: '9549', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98370', created_vulnerability: '2025-01-24 2:03:28', updated_vulnerability: '2025-01-24 2:03:28', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-ANU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:21:48', logged_user_time: '1737741801.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '[]', os_install_date: '1695189436.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.68', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["29742791-4494-4be9-942d-2ec882d30d64", "00:de:ad:be:af:01", "desktop-anu"]', host_name: 'Desktop-Anu', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-24 8:21:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:de:ad:be:af:01', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '3328.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 8:21:41', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": [], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4029', company_id: '8152', tenantid: '241996091870937089', id: '40002', created: '2025-01-24 8:21:34', updated: '2025-01-24 8:21:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:21:48', scan_status: 'true', ad_check: 'placeholder', configuration_id: 'placeholder', install_required_patches: '[]', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '40002', company_id_vulnerability: '8152', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98440', created_vulnerability: '2025-01-24 8:21:48', updated_vulnerability: '2025-01-24 8:21:48', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-ANU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:21:48', logged_user_time: '1737741801.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '[]', os_install_date: '1695189436.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.68', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["29742791-4494-4be9-942d-2ec882d30d64", "00:de:ad:be:af:01", "desktop-anu"]', host_name: 'Desktop-Anu', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-24 8:21:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:de:ad:be:af:01', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '3328.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 8:21:41', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": [], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4029', company_id: '8152', tenantid: '241996091870937089', id: '40002', created: '2025-01-24 8:21:34', updated: '2025-01-24 8:21:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:21:48', scan_status: 'true', ad_check: 'placeholder', configuration_id: 'placeholder', install_required_patches: '[]', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '40002', company_id_vulnerability: '8152', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98441', created_vulnerability: '2025-01-24 8:21:57', updated_vulnerability: '2025-01-24 8:21:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-ANU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:21:48', logged_user_time: '1737741801.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '[]', os_install_date: '1695189436.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.68', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["29742791-4494-4be9-942d-2ec882d30d64", "00:de:ad:be:af:01", "desktop-anu"]', host_name: 'Desktop-Anu', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-24 8:21:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:de:ad:be:af:01', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '3328.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 8:21:41', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": [], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4029', company_id: '8152', tenantid: '241996091870937089', id: '40002', created: '2025-01-24 8:21:34', updated: '2025-01-24 8:21:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:21:48', scan_status: 'true', ad_check: 'placeholder', configuration_id: 'placeholder', install_required_patches: '[]', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '40002', company_id_vulnerability: '8152', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98442', created_vulnerability: '2025-01-24 8:21:57', updated_vulnerability: '2025-01-24 8:21:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-ANU', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:21:48', logged_user_time: '1737741801.0', logged_in_user: 'Administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '[]', os_install_date: '1695189436.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.68', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["29742791-4494-4be9-942d-2ec882d30d64", "00:de:ad:be:af:01", "desktop-anu"]', host_name: 'Desktop-Anu', architecture: '64-bit', cpu_core: '1.0', discovered: '2025-01-24 8:21:34', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (Q35 + ICH9, 2009)', importance: '25', serial_number: 'placeholder', mac: '00:de:ad:be:af:01', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '3328.0', asset_category: 'placeholder', last_reset_time: '2025-01-24 8:21:41', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": [], "Scan Status": ["Scanned"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '4029', company_id: '8152', tenantid: '241996091870937089', id: '40002', created: '2025-01-24 8:21:34', updated: '2025-01-24 8:21:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:21:48', scan_status: 'true', ad_check: 'placeholder', configuration_id: 'placeholder', install_required_patches: '[]', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '40002', company_id_vulnerability: '8152', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98443', created_vulnerability: '2025-01-24 8:21:57', updated_vulnerability: '2025-01-24 8:21:57', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'EC2AMAZ-J266UJL', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 8:53:48', logged_user_time: 'placeholder', logged_in_user: 'placeholder', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049615", "4470502", "4470788", "4480056", "4486153", "4493510", "4499728", "4504369", "4512577", "4512937", "4521862", "4523204", "4535680", "4539571", "4549947", "4558997", "4562562", "4566424", "4570332", "4577667", "4587735", "4589208", "4598480", "4601393", "5000859", "5001404", "5003243", "5003711", "5005112", "5012170", "5050008", "5006754", "5008287", "5009642", "5011574", "5012675", "5014031", "5014797", "5015896", "5017400", "5020374", "5023789", "5028316", "5030505", "5031589", "5032306", "5034863", "5035963", "5037017", "5039335", "5040563", "5041577", "5043126", "5050110", "5005701", "925673", "4052623", "5037570", "", "890830", "5050182", "2267602"]', os_install_date: '1673234326.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Datacenter', ip: '172.26.8.234', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.6766', unique_id: '["ec2amaz-j266ujl", "02:2b:eb:8b:3e:50"]', host_name: 'EC2AMAZ-J266UJL', architecture: '64-bit', cpu_core: '2.0', discovered: '2025-01-17 10:56:22', icon: 'windows.svg', status: 'true', hardware_model: 'HVM domU', importance: '25', serial_number: 'ec2ef86d-6459-3faa-4b78-6df548d42394', mac: '00:60:73:5f:27:d5', manufacturer: 'Xen', physical_memory: '4294967296.0', uptime: '743437.0', asset_category: 'placeholder', last_reset_time: '2025-01-17 10:56:30', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"Asset Type": ["Server"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3943', company_id: '9617', tenantid: '241996091870937089', id: '39065', created: '2025-01-17 10:56:22', updated: '2025-01-24 8:53:48', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 8:53:48', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.6775', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '39065', company_id_vulnerability: '9617', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'false', id_vulnerability: '98445', created_vulnerability: '2025-01-24 8:53:52', updated_vulnerability: '2025-01-24 8:53:52', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-E1GK3Q04EUI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:28:17', logged_user_time: '1737538902.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4486153", "4512577", "4512578", "5034863", "5035963", "5037017", "5039335", "4052623"]', os_install_date: '1709014606.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.8.8', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-e1gk3q04eui", "6a:41:26:35:e1:9f"]', host_name: 'WIN-E1GK3Q04EUI.shanu.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2024-12-13 12:18:30', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '6a:41:26:35:e1:9f', manufacturer: 'QEMU', physical_memory: '4299161600.0', uptime: '164629.0', asset_category: 'placeholder', last_reset_time: '2025-01-13 12:09:17', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3614', company_id: '8972', tenantid: '241996091870937089', id: '35690', created: '2024-12-13 12:18:30', updated: '2025-01-24 7:28:17', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:28:17', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35690', company_id_vulnerability: '8972', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'true', id_vulnerability: '98372', created_vulnerability: '2025-01-24 3:23:27', updated_vulnerability: '2025-01-24 3:23:27', suppressed_till: '2123-12-17 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-P407S6R', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 9:59:46', logged_user_time: '1737538893.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732866336.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.33', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["72:d2:91:9a:0c:7e", "desktop-p407s6r"]', host_name: 'DESKTOP-P407S6R', architecture: '64-bit', cpu_core: '2.0', discovered: '2024-12-14 4:37:35', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '72:d2:91:9a:0c:7e', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '87407.0', asset_category: 'placeholder', last_reset_time: '2024-12-14 4:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3646', company_id: '8025', tenantid: '241996091870937089', id: '35787', created: '2024-12-14 4:37:35', updated: '2025-01-23 9:59:46', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:59:46', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35787', company_id_vulnerability: '8025', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '97980', created_vulnerability: '2025-01-22 20:04:56', updated_vulnerability: '2025-01-22 20:04:56', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-E1GK3Q04EUI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:28:17', logged_user_time: '1737538902.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4486153", "4512577", "4512578", "5034863", "5035963", "5037017", "5039335", "4052623"]', os_install_date: '1709014606.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.8.8', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-e1gk3q04eui", "6a:41:26:35:e1:9f"]', host_name: 'WIN-E1GK3Q04EUI.shanu.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2024-12-13 12:18:30', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '6a:41:26:35:e1:9f', manufacturer: 'QEMU', physical_memory: '4299161600.0', uptime: '164629.0', asset_category: 'placeholder', last_reset_time: '2025-01-13 12:09:17', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3614', company_id: '8972', tenantid: '241996091870937089', id: '35690', created: '2024-12-13 12:18:30', updated: '2025-01-24 7:28:17', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:28:17', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35690', company_id_vulnerability: '8972', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '98371', created_vulnerability: '2025-01-24 3:23:27', updated_vulnerability: '2025-01-24 3:23:27', suppressed_till: 'placeholder', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-P407S6R', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 9:59:46', logged_user_time: '1737538893.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732866336.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.33', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["72:d2:91:9a:0c:7e", "desktop-p407s6r"]', host_name: 'DESKTOP-P407S6R', architecture: '64-bit', cpu_core: '2.0', discovered: '2024-12-14 4:37:35', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '72:d2:91:9a:0c:7e', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '87407.0', asset_category: 'placeholder', last_reset_time: '2024-12-14 4:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3646', company_id: '8025', tenantid: '241996091870937089', id: '35787', created: '2024-12-14 4:37:35', updated: '2025-01-23 9:59:46', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:59:46', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35787', company_id_vulnerability: '8025', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'true', id_vulnerability: '97979', created_vulnerability: '2025-01-22 20:04:56', updated_vulnerability: '2025-01-22 20:04:56', suppressed_till: '2123-12-17 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-P407S6R', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 9:59:46', logged_user_time: '1737538893.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732866336.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.33', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["72:d2:91:9a:0c:7e", "desktop-p407s6r"]', host_name: 'DESKTOP-P407S6R', architecture: '64-bit', cpu_core: '2.0', discovered: '2024-12-14 4:37:35', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '72:d2:91:9a:0c:7e', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '87407.0', asset_category: 'placeholder', last_reset_time: '2024-12-14 4:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3646', company_id: '8025', tenantid: '241996091870937089', id: '35787', created: '2024-12-14 4:37:35', updated: '2025-01-23 9:59:46', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:59:46', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35787', company_id_vulnerability: '8025', tenantid_vulnerability: '241996091870937089', is_confirmed: 'false', is_suppressed: 'true', id_vulnerability: '97981', created_vulnerability: '2025-01-22 20:04:56', updated_vulnerability: '2025-01-22 20:04:56', suppressed_till: '2123-12-17 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'WIN-E1GK3Q04EUI', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-24 7:28:17', logged_user_time: '1737538902.0', logged_in_user: 'administrator', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["4514366", "4486153", "4512577", "4512578", "5034863", "5035963", "5037017", "5039335", "4052623"]', os_install_date: '1709014606.0', os_autoupdate: 'Error', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows Server 2019 Standard', ip: '10.0.8.8', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.17763.737', unique_id: '["win-e1gk3q04eui", "6a:41:26:35:e1:9f"]', host_name: 'WIN-E1GK3Q04EUI.shanu.com', architecture: '64-bit', cpu_core: '4.0', discovered: '2024-12-13 12:18:30', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '6a:41:26:35:e1:9f', manufacturer: 'QEMU', physical_memory: '4299161600.0', uptime: '164629.0', asset_category: 'placeholder', last_reset_time: '2025-01-13 12:09:17', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"JAKKA": ["JAOOO"], "PUNHA": ["YEIL"], "Asset Type": ["Server"], "aaaaaaaaaa": ["aaaaaaaaaaaa"], "Scan Status": ["Scanned"], "Windows11Compatible": []}', manual_tags: '{}', agent_id: '3614', company_id: '8972', tenantid: '241996091870937089', id: '35690', created: '2024-12-13 12:18:30', updated: '2025-01-24 7:28:17', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-24 7:28:17', scan_status: 'true', ad_check: 'Domain Controller', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '17763.737', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35690', company_id_vulnerability: '8972', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '90102', created_vulnerability: '2025-01-13 12:09:28', updated_vulnerability: '2025-01-13 12:09:28', suppressed_till: '2123-12-11 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    CREATE (:Asset {name: 'DESKTOP-P407S6R', platform: 'windows', system_type: 'placeholder', agent_type: 'LIGHTWEIGHT', asset_owner: 'placeholder', visible_name: 'placeholder', auth_scan_status: 'true', last_discovered_time: '2025-01-23 9:59:46', logged_user_time: '1737538893.0', logged_in_user: 'Hash', asset_logon_user: 'placeholder', asset_logon_time: 'placeholder', auto_update: 'placeholder', cred_id: 'placeholder', snmp_cred_id: 'placeholder', os_patches: '["5049621", "5022502", "5011048", "5015684", "5020683", "5033052", "5049981", "5014032", "5025315", "5046823", "5050388", "4052623", "5001716", "890830", "5050188", "2267602", "4023057"]', os_install_date: '1732866336.0', os_autoupdate: 'Good', os_vendor: 'placeholder', snmp_info: '', codename: 'Microsoft Windows 10 Pro', ip: '10.0.1.33', ip_extra: 'placeholder', asset_type: 'discovered', is_firewall: 'false', domain: 'placeholder', kernel: '10.0.19041.5369', unique_id: '["72:d2:91:9a:0c:7e", "desktop-p407s6r"]', host_name: 'DESKTOP-P407S6R', architecture: '64-bit', cpu_core: '2.0', discovered: '2024-12-14 4:37:35', icon: 'windows.svg', status: 'true', hardware_model: 'Standard PC (i440FX + PIIX, 1996)', importance: '25', serial_number: 'placeholder', mac: '72:d2:91:9a:0c:7e', manufacturer: 'QEMU', physical_memory: '2147483648.0', uptime: '87407.0', asset_category: 'placeholder', last_reset_time: '2024-12-14 4:37:36', is_deprecated: 'false', deprecated_time: 'placeholder', discovered_protocols: '[{"status": true, "protocol": "LIGHTWEIGHT", "credential_id": ""}]', custom_profile_id: 'placeholder', tags: '{"hem": ["hem"], "key2": ["val3"], "test2": ["6"], "TagXYZ": ["TagXYZValue"], "Asset Type": ["Workstation"], "compatible": ["100"], "Scan Status": ["Scanned"], "zzzzzzzzzzzzzzz": ["zzzzzzzzzzzzzzz"], "Windows11Compatible": ["false"]}', manual_tags: '{}', agent_id: '3646', company_id: '8025', tenantid: '241996091870937089', id: '35787', created: '2024-12-14 4:37:35', updated: '2025-01-23 9:59:46', discoverysettings_id: 'placeholder', last_ping_time: '2025-01-23 9:59:46', scan_status: 'true', ad_check: 'WorkGroup', configuration_id: 'placeholder', install_required_patches: 'placeholder', full_os_build: '19045.5371', finger_print: '', is_allowed: 'true', is_oval: 'false', asset_id: '35787', company_id_vulnerability: '8025', tenantid_vulnerability: '241996091870937089', is_confirmed: 'true', is_suppressed: 'false', id_vulnerability: '90170', created_vulnerability: '2024-12-14 4:37:38', updated_vulnerability: '2024-12-14 4:37:38', suppressed_till: '2123-12-11 0:00:00', is_remediated: 'false', remediated_on: 'placeholder'}) 
    $$) as (n agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39526' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39526' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39345' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39345' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39345' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39345' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39891' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39891' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39894' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39894' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39863' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39863' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39247' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.asset_id = '39247' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39244' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39244' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39891' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39891' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '40002' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '40002' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39391' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39391' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39195' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39195' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39379' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39379' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39755' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.asset_id = '39755' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39247' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.asset_id = '39247' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39334' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39334' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39383' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39383' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39390' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.asset_id = '39390' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39891' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39891' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35787' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '35787' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39345' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39345' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39285' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39285' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39195' AND m.vul_id = 'CVE-2017-5715' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39195' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'CVE-2017-5715' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39280' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39280' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39894' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39894' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39195' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39195' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39631' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.asset_id = '39631' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39631' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.asset_id = '39631' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39776' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39776' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39631' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.asset_id = '39631' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39345' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39345' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35787' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '35787' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39334' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39334' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39379' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39379' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35690' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '35690' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39214' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro Insider Preview' AND m.asset_id = '39214' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 11 Pro Insider Preview' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39776' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39776' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39776' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39776' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '40002' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '40002' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39280' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39280' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39776' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39776' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39391' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39391' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35787' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '35787' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39379' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39379' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39247' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.asset_id = '39247' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39244' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39244' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39383' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39383' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35690' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '35690' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39280' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39280' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39891' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39891' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39391' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39391' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39863' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39863' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39863' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39863' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39244' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39244' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '40002' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '40002' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39383' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39383' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39345' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39345' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39891' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39891' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35690' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '35690' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39400' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39400' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '40002' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '40002' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'UNQUOTED-SERVICE-PATH-DETECTED' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39285' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39285' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39999' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2016 Standard' AND m.asset_id = '39999' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2016 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39280' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39280' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39334' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39334' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39390' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.asset_id = '39390' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '35787' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '35787' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39391' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39391' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39776' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39776' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'POWERSHELL-V2-INFO-DISCLOSURE' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2020-0550' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39195' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.asset_id = '39195' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39866' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39866' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21123' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39468' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39468' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12130' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39998' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39998' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39396' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39396' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39855' AND m.vul_id = 'SNMP Agent Default Community Name (public)' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'brother' AND m.asset_id = '39855' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'brother' AND m.vul_id = 'SNMP Agent Default Community Name (public)' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39438' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39438' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2020-0549' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39247' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.asset_id = '39247' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Home Single Language' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2019-11091' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39065' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.asset_id = '39065' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Datacenter' AND m.vul_id = 'CVE-2018-12126' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39669' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39669' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39364' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Windows NT' AND m.asset_id = '39364' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Windows NT' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39904' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39904' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2022-21125' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39755' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.asset_id = '39755' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2012 R2 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39244' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39244' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'Event-Log-Crasher' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39280' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39280' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39458' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39458' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2022-21166' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39285' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.asset_id = '39285' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2019 Standard' AND m.vul_id = 'CVE-2018-3639' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39315' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.asset_id = '39315' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows 10 Pro' AND m.vul_id = 'CVE-2018-12127' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:Asset), (m:Vulnerability) 
    WHERE n.asset_id = '39894' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Asset) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.asset_id = '39894' 
    CREATE (n)-[:RUNS_ON]->(m) 
    $$) as (r agtype);
    

    SELECT * FROM cypher('security_graph', $$ 
    MATCH (n:OperatingSystem), (m:Vulnerability) 
    WHERE n.os_name = 'Microsoft Windows Server 2022 Standard Evaluation' AND m.vul_id = 'CVE-2013-3900' 
    CREATE (n)-[:HAS_VULNERABILITY]->(m) 
    $$) as (r agtype);
    
