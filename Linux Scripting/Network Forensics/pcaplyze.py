import subprocess
import os
import datetime
import csv
from html import escape

# Define all filters with labels (200+ filters from HTTP, TLS, DNS, TCP, UDP, IP, malware, OSINT, and misc)

filters = {
    # --- HTTP Filters ---
    "HTTP_Authorization": 'http.authorization',
    "HTTP_Login_POST": 'http.request.uri contains "login" && http.request.method == "POST"',
    "HTTP_Password_Form": 'http.form_data contains "password"',
    "HTTP_Cookie": 'http.cookie',
    "HTTP_Basic_Auth": 'http.authorization contains "Basic"',
    "HTTP_3xx_Response": 'http.response.code >= 300 && http.response.code < 400',
    "HTTP_Request": 'http.request',
    "HTTP_POST_Only": 'http.request.method == "POST"',
    "HTTP_To_Host": 'http.host == "example.com"',
    "HTTP_User_Agent_Firefox": 'http.user_agent contains "Firefox"',
    "HTTP_Set_Cookie": 'http.set_cookie',
    "HTTP_URI_Login": 'http.request.uri contains "login"',
    "HTTP_Auth_Basic_Field": 'http.authbasic',
    "Unencrypted_HTTP": 'http',
    "HTTP_Response_Code_200": 'http.response.code == 200',
    "HTTP_User_Agent_Contains_Curl": 'http.user_agent contains "curl"',
    "HTTP_Content_Type_JSON": 'http.content_type contains "json"',
    "HTTP_Content_Type_HTML": 'http.content_type contains "html"',
    "HTTP_User_Agent_Missing": 'not http.user_agent',
    "HTTP_Method_PUT": 'http.request.method == "PUT"',
    "HTTP_Referer_Header": 'http.referer',
    "HTTP_Host_Match_IP": 'http.host matches "\\d+\\.\\d+\\.\\d+\\.\\d+"',

    # --- TLS/SSL Filters ---
    "TLS_Certificate_Exchange": 'ssl.handshake.type == 11',
    "TLS_Handshake_Error": 'ssl.handshake.type == 12',
    "TLS_Traffic": 'tls',
    "TLS_Client_Hello": 'tls.handshake.type == 1',
    "TLS_Server_Hello": 'tls.handshake.type == 2',
    "TLS_1_2": 'tls.record.version == 0x0303',
    "TLS_1_3": 'tls.record.version == 0x0304',
    "TLS_App_Data": 'tls.record.content_type == 23',
    "TLS_RSA_Key_Exchange": 'ssl.handshake.key_exchange_algorithm == 1',
    "TLS_ECDHE_Key_Exchange": 'ssl.handshake.key_exchange_algorithm == 16',
    "TLS_Ext_SNI": 'tls.handshake.extensions_server_name',
    "TLS_Encrypted_Handshake": 'tls.record.content_type == 22 && tls.handshake.type == 11',
    "TLS_Unknown_Cipher": 'tls.handshake.ciphersuite == 0x00ff',
    "TLS_Renegotiation": 'ssl.handshake.type == 20',
    "TLS_Session_Resumption": 'tls.handshake.session_id_length > 0',

    # --- DNS Filters ---
    "DNS_Query_Example": 'dns.qry.name contains "example.com"',
    "DNS_Query": 'dns.flags.response == 0',
    "DNS_Response": 'dns.flags.response == 1',
    "DNS_A_Records": 'dns.a',
    "DNS_Query_Type_A": 'dns.qry.type == 1',
    "DNS_Query_Type_AAAA": 'dns.qry.type == 28',
    "DNS_Query_Type_MX": 'dns.qry.type == 15',
    "All_DNS": 'dns',
    "DNS_Over_HTTPS_HTTP2": 'dns && tls.handshake.extensions.type == 5',
    "DNS_Tunneling_Pattern": 'dns.qry.name contains "co." && dns.qry.type == 16',
    "DNS_High_Entropy": 'dns.qry.name matches "[A-Za-z0-9]{30,}"',

    # --- TCP Filters ---
    "TCP_SYN": 'tcp.flags.syn == 1 && tcp.flags.ack == 0',
    "TCP_FIN": 'tcp.flags.fin == 1',
    "TCP_443": 'tcp.port == 443',
    "TCP_80": 'tcp.port == 80',
    "TCP_Retransmit": 'tcp.analysis.retransmission',
    "TCP_With_Data": 'tcp.len > 0',
    "Non_Standard_TCP_Ports": 'tcp.port != 80 && tcp.port != 443',
    "All_TCP": 'tcp',
    "TCP_ACK_Only": 'tcp.flags.ack == 1 && tcp.flags.syn == 0 && tcp.flags.fin == 0 && tcp.len == 0',
    "TCP_Reset": 'tcp.flags.reset == 1',
    "TCP_Contains_GET": 'tcp contains "GET"',
    "TCP_Window_Size_Zero": 'tcp.window_size_value == 0',
    "TCP_Suspicious_Payload_Size": 'tcp.len > 1000',

    # --- UDP Filters ---
    "UDP_53": 'udp.port == 53',
    "UDP_123": 'udp.port == 123',
    "UDP_Large": 'udp.length > 100',
    "All_UDP": 'udp',
    "UDP_DNS_Response": 'udp.port == 53 && dns.flags.response == 1',
    "UDP_Small_Packets": 'udp.length < 20',

    # --- IP and Ethernet Filters ---
    "Traffic_To_From_IP": 'ip.addr == 192.168.1.10',
    "Src_IP_Only": 'ip.src == 192.168.1.1',
    "Dst_IP_Only": 'ip.dst == 8.8.8.8',
    "Any_Eth_MAC": 'eth.addr == aa:bb:cc:dd:ee:ff',
    "Src_Eth_MAC": 'eth.src == 00:11:22:33:44:55',
    "IPv6_Traffic": 'ipv6',
    "Fragmented_IP": 'ip.flags.m == 1 || ip.frag_offset > 0',
    "Multicast_Traffic": 'eth.dst[0] & 1',
    "Broadcast_Traffic": 'eth.dst == ff:ff:ff:ff:ff:ff',
    "IPv4_Traffic": 'ip',
    "IP_TTL_Less_64": 'ip.ttl < 64',
    "Private_IP_Traffic": 'ip.addr matches "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\."',
    "Public_IP_Traffic": 'not ip.addr matches "^10\\.|^192\\.168\\.|^172\\.(1[6-9]|2[0-9]|3[0-1])\\."',

    # --- OSINT & Malware Filters ---
    "Tor_Traffic": 'ip.addr == 185.220.100.255',
    "Malicious_Domain": 'dns.qry.name contains "malwaredomain.com"',
    "C2_Traffic_Pattern": 'tcp.len > 0 && frame.len < 150',
    "Suspicious_User_Agent": 'http.user_agent contains "python"',
    "Shellcode_Injection": 'frame contains "\\x90\\x90\\x90\\x90"',
    "Encoded_Payload": 'frame contains "%2f%2e%2e%2f"',
    "Base64_Encoded_String": 'frame matches "[A-Za-z0-9+/=]{20,}"',
    "HTTP_Command_Execution": 'http.request.uri contains "cmd="',
    "Malware_Beaconing": 'frame.time_delta < 1 && tcp.len == 0',
    "Suspicious_DNS_Query_Length": 'strlen(dns.qry.name) > 50',

    # --- Miscellaneous Filters ---
    "Telnet_Traffic": 'telnet',
    "FTP_Login": 'ftp.request.command == "USER" || ftp.request.command == "PASS"',
    "SMB_Traffic": 'smb',
    "Frame_Contains_Password": 'frame contains "password"',
    "ICMP": 'icmp',
    "ICMP_Echo": 'icmp.type == 8',
    "ARP_Traffic": 'arp',
    "No_ARP": 'not arp',
    "Multicast_DNS": 'udp.port == 5353',
    "DHCP_Discover": 'bootp.option.type == 53 && bootp.option.value == 1',
    "ICMP_Destination_Unreachable": 'icmp.type == 3',
    "ICMP_TTL_Exceeded": 'icmp.type == 11',
    "SMB_Negotiate_Protocol": 'smb.cmd == 0x72',
    
        # --- Email Protocol Filters ---
    "SMTP_Auth": 'smtp.req.command == "AUTH"',
    "SMTP_Mail_From": 'smtp.req.command == "MAIL"',
    "SMTP_RCPT_To": 'smtp.req.command == "RCPT"',
    "POP3_User": 'pop.request.command == "USER"',
    "POP3_Pass": 'pop.request.command == "PASS"',
    "IMAP_Login": 'imap.request.command == "LOGIN"',

    # --- Wireless Traffic Filters ---
    "WiFi_Deauth_Attack": 'wlan.fc.type_subtype == 12',
    "WiFi_Probe_Requests": 'wlan.fc.type_subtype == 4',
    "WiFi_Beacon_Frames": 'wlan.fc.type_subtype == 8',
    "WiFi_Association_Request": 'wlan.fc.type_subtype == 0',
    "RadioTap_Packets": 'radiotap',

    # --- VoIP / RTP / SIP ---
    "SIP_Invite": 'sip.Method == "INVITE"',
    "SIP_Register": 'sip.Method == "REGISTER"',
    "RTP_Traffic": 'rtp',
    "RTCP_Traffic": 'rtcp',

    # --- VPN / Tunneling Protocols ---
    "OpenVPN_Traffic": 'openvpn',
    "GRE_Tunnel": 'gre',
    "IPSec_ESP": 'esp',
    "ISAKMP_Key_Exchange": 'isakmp',
    "L2TP_Traffic": 'l2tp',

    # --- IoT / SCADA Protocols ---
    "Modbus_TCP": 'modbus',
    "MQTT_Traffic": 'mqtt',
    "CoAP_Traffic": 'coap',
    "BACnet": 'bacnet',
    "ZigBee_Traffic": 'zigbee',

    # --- Blockchain / Crypto ---
    "Bitcoin_Protocol": 'bitcoin',
    "Ethereum_Protocol": 'ethereum',

    # --- Advanced Malware & OSINT ---
    "Tor_Onion_Domain": 'dns.qry.name contains ".onion"',
    "C2_Beacon_Timing": 'frame.time_delta < 2 && tcp.len == 0',
    "Encoded_Command_Pattern": 'http.request.uri contains "powershell" && http.request.uri contains "Base64"',
    "Suspicious_HTTP_GET_Binary": 'http.request.uri contains ".exe" || http.request.uri contains ".dll"',
    "High_Entropy_DGA_Domain": 'dns.qry.name matches "[a-z0-9]{15,}"',
    "Obfuscated_JS_Snippet": 'frame contains "<script>" && frame matches "[a-zA-Z]{30,}"',
    "Reverse_Shell_Signs": 'tcp.port == 4444 || tcp.port == 1337',
    "Suspicious_Ping_Tunnel": 'icmp && frame.len > 100',
    "Hidden_Executable_Drop": 'data-text-lines contains "MZ"',
    "AutoIt_Script_Traffic": 'frame contains "AutoIt"',
        # --- NetBIOS & Name Resolution ---
    "NetBIOS_Name_Service": 'nbns',
    "LLMNR_Traffic": 'udp.port == 5355',
    "NBNS_Traffic": 'udp.port == 137',

    # --- NTP / Time Services ---
    "NTP_Traffic": 'udp.port == 123',
    "NTP_Monlist": 'ntp.flags == 0x06',

    # --- SNMP / Device Monitoring ---
    "SNMP_V1": 'snmp.version == 0',
    "SNMP_V2c": 'snmp.version == 1',
    "SNMP_V3": 'snmp.version == 3',

    # --- LDAP & Kerberos ---
    "LDAP_Traffic": 'ldap',
    "LDAP_Bind_Request": 'ldap.message == 0',
    "Kerberos_AS_REQ": 'kerberos.msg_type == 10',
    "Kerberos_TGS_REQ": 'kerberos.msg_type == 12',

    # --- RADIUS Authentication ---
    "RADIUS_Access_Request": 'radius.code == 1',
    "RADIUS_Access_Accept": 'radius.code == 2',

    # --- SSDP / UPnP / mDNS / Multicast ---
    "SSDP_Search": 'udp.port == 1900',
    "SSDP_NOTIFY": 'http.request.uri contains "notify"',
    "mDNS_Traffic": 'udp.port == 5353',
    "Multicast_UDP": 'udp.dstport >= 224.0.0.0',

    # --- DNP3 / Industrial ---
    "DNP3_Traffic": 'dnp3',
    "DNP3_Function_Write": 'dnp3.func_code == 0x02',

    # --- HTTP Behavior Filters ---
    "HTTP_REFERRER": 'http.referer',
    "HTTP_X_Forwarded_For": 'http.x_forwarded_for',
    "HTTP_Long_URI": 'strlen(http.request.uri) > 100',
    "HTTP_JS_Response": 'http.content_type contains "javascript"',

    # --- File & MIME-Type Analysis ---
    "Download_EXE": 'http.content_type contains "application/x-msdownload"',
    "Download_ZIP": 'http.content_type contains "zip"',
    "Download_PDF": 'http.content_type contains "pdf"',
    "Upload_Data": 'http.request.method == "POST" && frame.len > 1000',

    # --- Anomalies ---
    "TTL_Suspicious": 'ip.ttl == 1 || ip.ttl > 200',
    "Short_Packets": 'frame.len < 64',
    "Large_Packets": 'frame.len > 1500',
    "Abnormal_TCP_Window": 'tcp.window_size > 65535',
    "Reused_TCP_Ports": 'tcp.analysis.reused_ports',
    "Reset_Attack": 'tcp.flags.reset == 1 && frame.len < 60',

    # --- TCP Scans ---
    "NULL_Scan": 'tcp.flags == 0x00',
    "FIN_Scan": 'tcp.flags.fin == 1 && tcp.flags.ack == 0',
    "XMAS_Scan": 'tcp.flags.fin == 1 && tcp.flags.urg == 1 && tcp.flags.push == 1',

    # --- Beaconing & C2 Detection ---
    "Low_Delay_TCP_Reconnects": 'frame.time_delta < 1 && tcp.len == 0',
    "Consistent_Packet_Size": 'frame.len == 150',
    "Base64_Command_Execution": 'frame matches "powershell.*[A-Za-z0-9+/=]{20,}"',

    # --- JA3 / TLS Fingerprinting (if TLS fingerprint plugin is enabled) ---
    "JA3_TLS_Fingerprint": 'tls.handshake && ssl.handshake.ja3',
    "Rare_TLS_Ciphers": 'tls.handshake.ciphersuite not in {0x1301, 0x1302, 0x1303}',

    # --- DNS Tunneling / Abuse ---
    "DNS_Low_TTL": 'dns.resp.ttl < 60',
    "DNS_Suspicious_Query_Length": 'strlen(dns.qry.name) > 50',
    "DNS_Possible_Exfiltration": 'dns.qry.name matches "[a-z0-9]{40,}"',
    "DNS_TXT_Records": 'dns.qry.type == 16',

    # --- Suspicious Ports ---
    "Port_4444_Metasploit": 'tcp.port == 4444',
    "Port_1337_Shells": 'tcp.port == 1337',
    "Port_6667_IRC": 'tcp.port == 6667',
    "Port_8080_HTTP_Alt": 'tcp.port == 8080',
    "Port_3389_RDP": 'tcp.port == 3389',

    # --- GeoIP / External (optional post-processing) ---
    "To_External_IPs": '!(ip.addr contains "192.168." || ip.addr contains "10." || ip.addr contains "172.16.")',
    "Unusual_Countries": 'frame contains "CN" || frame contains "RU"',

    # --- Proxy / VPN Detection ---
    "HTTP_Via_Proxy": 'http.header contains "via"',
    "SOCKS_Proxy_Traffic": 'tcp.port == 1080',
    "VPN_OpenVPN_Port": 'udp.port == 1194',
    "VPN_PPTP": 'tcp.port == 1723',

    # --- File Injection / Exploit Indicators ---
    "MZ_Header_In_Payload": 'frame contains "MZ"',
    "PE_File_Drop": 'tcp contains "This program"',
    "Java_Exploit": 'frame contains "com.sun.jndi.ldap"',
    "Shellshock_Attempt": 'http.request.uri contains "(){"',

    # --- DNS Over HTTPS (DoH) ---
    "DoH_Traffic": 'http2 && dns && tls',
    "DNS_Over_TLS": 'tcp.port == 853',

    # --- HTTP3 / QUIC ---
    "QUIC_Traffic": 'quic',
    "HTTP3_Traffic": 'http3',

    # --- IPv6-Specific ---
    "IPv6_Extension_Header": 'ipv6.nxt != 6 && ipv6.nxt != 17',
    "IPv6_Fragmented": 'ipv6.fragment',

    # --- ARP Poisoning ---
    "Gratuitous_ARP": 'arp.opcode == 2 && arp.src.proto_ipv4 != arp.dst.proto_ipv4',

    # --- Remote Desktop / Admin Access ---
    "VNC_Traffic": 'tcp.port == 5900',
    "TeamViewer_Traffic": 'tcp.port == 5938',

    # --- Email Exfil ---
    "SMTP_With_Attachment": 'smtp.data && frame.len > 1000',

    # --- IoT Beaconing ---
    "Frequent_Small_UDP": 'udp.length < 50 && frame.time_delta < 1',
    
    # --- VoIP Protocol Filters ---

    "SIP_Traffic": 'sip',
    "SIP_Invite": 'sip.Method == "INVITE"',
    "SIP_Register": 'sip.Method == "REGISTER"',
    "RTP_Traffic": 'rtp',
    "RTCP_Traffic": 'rtcp',
    "H225_Traffic": 'h225',
    "H245_Traffic": 'h245',
    "MGCP_Traffic": 'mgcp',
    "IAX2_Traffic": 'iax2',
    "Skinny_Protocol_Traffic": 'skinny',


# --- Wireless (802.11) Filters ---

    "Beacon_Frames": 'wlan.fc.type_subtype == 0x08',
    "Probe_Request_Frames": 'wlan.fc.type_subtype == 0x04',
    "Probe_Response_Frames": 'wlan.fc.type_subtype == 0x05',
    "Authentication_Frames": 'wlan.fc.type_subtype == 0x0B',
    "Association_Request_Frames": 'wlan.fc.type_subtype == 0x00',
    "Association_Response_Frames": 'wlan.fc.type_subtype == 0x01',
    "Deauthentication_Frames": 'wlan.fc.type_subtype == 0x0C',
    "Disassociation_Frames": 'wlan.fc.type_subtype == 0x0A',
    "RTS_Frames": 'wlan.fc.type_subtype == 0x1B',
    "CTS_Frames": 'wlan.fc.type_subtype == 0x1C',
    "ACK_Frames": 'wlan.fc.type_subtype == 0x1D',
    "QoS_Data_Frames": 'wlan.fc.type_subtype == 0x28',


# --- Gaming Protocol Filters ---

    "Steam_Traffic": 'tcp.port == 27015',
    "Xbox_Live_Traffic": 'udp.port == 3074',
    "PlayStation_Network_Traffic": 'tcp.port == 3478',


# --- Enterprise Application Filters ---

    "Microsoft_Teams_Traffic": 'ip.addr == 52.112.0.0/14',
    "Zoom_Traffic": 'ip.addr == 170.114.0.0/16',
    "Slack_Traffic": 'tcp.port == 443 && tls.handshake.extensions_server_name contains "slack.com"',


# --- Industrial Control Systems (ICS) Filters ---

    "Modbus_Traffic": 'modbus',
    "DNP3_Traffic": 'dnp3',
    "IEC60870_5_104_Traffic": 'iec104',
    "OPC_UA_Traffic": 'opcua',
    "S7comm_Traffic": 's7comm',
    "BACnet_Traffic": 'bacnet',
    "Profinet_Traffic": 'pn_io',
    "EtherNet_IP_Traffic": 'enip',


# --- MITM Detection Filters ---


    "SSL_Certificate_Anomaly": 'ssl.handshake.certificate && !ssl.handshake.extensions_server_name',
    "Suspicious_TLS_Certificate": 'ssl.certificates.certificate_authority == 0 && ssl.handshake.type == 11',
    "SSL_Fake_Certificate": 'ssl.handshake.certificate_spki_sha1 == 0x...',
    "SSL_Possible_Certificate_Forgery": 'ssl.handshake.extensions_server_name != "expected_host"',
    "DNS_Spoofing": 'dns.flags.response == 1 && dns.a && dns.qry.name contains "example.com"',
    "ARP_Spoofing": 'arp.opcode == 2',
    "TCP_Options_Mitm": 'tcp.options.mss_size != 1460',
    "SSL_Forwarded_Header": 'http.request.headers contains "X-Forwarded-For"',
    "Unusual_DNS_Responses": 'dns.flags.response == 1 && dns.a && dns.qry.type == 1',
    "Invalid_Certificate_Signature": 'ssl.handshake.certificate.signature_algorithm != "sha256WithRSAEncryption"',
    "Suspicious_Proxy_IP": 'ip.addr == 192.168.0.100',  # Replace with known proxy server IP
    "TCP_Packet_Injection": 'tcp.analysis.out_of_order && tcp.analysis.retransmission',
    "TLS_Downgrade_Attack": 'tls.record.version == 0x0301',  # SSLv3
    "HTTP_Hijacked_Session": 'http.cookie contains "JSESSIONID"',
    "Man_in_the_Middle_Traffic": 'tcp.analysis.flags && ip.src != ip.dst',
    "SSL_Handshake_Anomaly": 'ssl.handshake.type == 1 && ssl.record.version != 0x0303',
    "HTTPS_Over_HTTP": 'http.request.uri contains "https://"',
    "DNS_Tunnel_Anomaly": 'dns.qry.name matches "^[a-z0-9]{32,}$"',


# --- Social Media Filters ---


    # --- Facebook ---
    "Facebook_Traffic": 'http.host contains "facebook.com"',
    "Facebook_HTTP_Request": 'http.request.uri contains "facebook.com"',
    "Facebook_Login": 'http.request.uri contains "login" && http.host contains "facebook.com"',
    "Facebook_API_Traffic": 'http.host contains "graph.facebook.com"',
    
    # --- Instagram ---
    "Instagram_Traffic": 'http.host contains "instagram.com"',
    "Instagram_Login": 'http.request.uri contains "accounts/login/" && http.host contains "instagram.com"',
    "Instagram_API_Traffic": 'http.host contains "i.instagram.com"',

    # --- Twitter ---
    "Twitter_Traffic": 'http.host contains "twitter.com"',
    "Twitter_Login": 'http.request.uri contains "login" && http.host contains "twitter.com"',
    "Twitter_API_Traffic": 'http.host contains "api.twitter.com"',
    
    # --- LinkedIn ---
    "LinkedIn_Traffic": 'http.host contains "linkedin.com"',
    "LinkedIn_Login": 'http.request.uri contains "uas/login" && http.host contains "linkedin.com"',
    "LinkedIn_API_Traffic": 'http.host contains "www.linkedin.com"',
    
    # --- Snapchat ---
    "Snapchat_Traffic": 'http.host contains "snapchat.com"',
    "Snapchat_Login": 'http.request.uri contains "accounts/login" && http.host contains "snapchat.com"',
    
    # --- TikTok ---
    "TikTok_Traffic": 'http.host contains "tiktok.com"',
    "TikTok_Login": 'http.request.uri contains "login" && http.host contains "tiktok.com"',
    "TikTok_API_Traffic": 'http.host contains "api2.musical.ly"',
    
    # --- WhatsApp ---
    "WhatsApp_Traffic": 'http.host contains "web.whatsapp.com"',
    "WhatsApp_Login": 'http.request.uri contains "login" && http.host contains "web.whatsapp.com"',
    
    # --- YouTube ---
    "YouTube_Traffic": 'http.host contains "youtube.com"',
    "YouTube_Login": 'http.request.uri contains "signin" && http.host contains "youtube.com"',
    "YouTube_API_Traffic": 'http.host contains "www.googleapis.com"',
    
    # --- Pinterest ---
    "Pinterest_Traffic": 'http.host contains "pinterest.com"',
    "Pinterest_Login": 'http.request.uri contains "login" && http.host contains "pinterest.com"',
    
    # --- Reddit ---
    "Reddit_Traffic": 'http.host contains "reddit.com"',
    "Reddit_Login": 'http.request.uri contains "login" && http.host contains "reddit.com"',
    
    # --- Tumblr ---
    "Tumblr_Traffic": 'http.host contains "tumblr.com"',
    "Tumblr_Login": 'http.request.uri contains "login" && http.host contains "tumblr.com"',
    
    # --- Discord ---
    "Discord_Traffic": 'http.host contains "discord.com"',
    "Discord_Login": 'http.request.uri contains "login" && http.host contains "discord.com"',
    "Discord_API_Traffic": 'http.host contains "discordapp.com"',
    
    # --- Telegram ---
    "Telegram_Traffic": 'http.host contains "web.telegram.org"',
    "Telegram_Login": 'http.request.uri contains "login" && http.host contains "web.telegram.org"',
    
    # --- TikTok ---
    "TikTok_Traffic": 'http.host contains "tiktok.com"',
    "TikTok_Login": 'http.request.uri contains "login" && http.host contains "tiktok.com"',
    "TikTok_API_Traffic": 'http.host contains "api2.musical.ly"',


# --- Job-related Social Media and Job Boards Filters ---


    # --- LinkedIn Jobs ---
    "LinkedIn_Jobs_Traffic": 'http.host contains "linkedin.com" && http.request.uri contains "/jobs/"',
    "LinkedIn_Job_Postings": 'http.host contains "linkedin.com" && http.request.uri contains "jobs/view"',
    "LinkedIn_Job_Apply": 'http.host contains "linkedin.com" && http.request.uri contains "apply"',
    
    # --- Indeed ---
    "Indeed_Traffic": 'http.host contains "indeed.com"',
    "Indeed_Job_Postings": 'http.host contains "indeed.com" && http.request.uri contains "job/"',
    "Indeed_Job_Apply": 'http.host contains "indeed.com" && http.request.uri contains "apply"',
    
    # --- Glassdoor ---
    "Glassdoor_Traffic": 'http.host contains "glassdoor.com"',
    "Glassdoor_Job_Postings": 'http.host contains "glassdoor.com" && http.request.uri contains "/Job/"',
    "Glassdoor_Job_Apply": 'http.host contains "glassdoor.com" && http.request.uri contains "apply"',
    
    # --- Monster ---
    "Monster_Traffic": 'http.host contains "monster.com"',
    "Monster_Job_Postings": 'http.host contains "monster.com" && http.request.uri contains "job/"',
    "Monster_Job_Apply": 'http.host contains "monster.com" && http.request.uri contains "apply"',
    
    # --- CareerBuilder ---
    "CareerBuilder_Traffic": 'http.host contains "careerbuilder.com"',
    "CareerBuilder_Job_Postings": 'http.host contains "careerbuilder.com" && http.request.uri contains "job/"',
    "CareerBuilder_Job_Apply": 'http.host contains "careerbuilder.com" && http.request.uri contains "apply"',
    
    # --- SimplyHired ---
    "SimplyHired_Traffic": 'http.host contains "simplyhired.com"',
    "SimplyHired_Job_Postings": 'http.host contains "simplyhired.com" && http.request.uri contains "job/"',
    "SimplyHired_Job_Apply": 'http.host contains "simplyhired.com" && http.request.uri contains "apply"',
    
    # --- ZipRecruiter ---
    "ZipRecruiter_Traffic": 'http.host contains "ziprecruiter.com"',
    "ZipRecruiter_Job_Postings": 'http.host contains "ziprecruiter.com" && http.request.uri contains "/jobs/"',
    "ZipRecruiter_Job_Apply": 'http.host contains "ziprecruiter.com" && http.request.uri contains "apply"',
    
    # --- FlexJobs ---
    "FlexJobs_Traffic": 'http.host contains "flexjobs.com"',
    "FlexJobs_Job_Postings": 'http.host contains "flexjobs.com" && http.request.uri contains "job/"',
    "FlexJobs_Job_Apply": 'http.host contains "flexjobs.com" && http.request.uri contains "apply"',
    
    # --- Remote.co ---
    "Remote_co_Traffic": 'http.host contains "remote.co"',
    "Remote_co_Job_Postings": 'http.host contains "remote.co" && http.request.uri contains "job/"',
    "Remote_co_Job_Apply": 'http.host contains "remote.co" && http.request.uri contains "apply"',
    
    # --- AngelList (Now Wellfound) ---
    "AngelList_Traffic": 'http.host contains "angel.co"',
    "AngelList_Job_Postings": 'http.host contains "angel.co" && http.request.uri contains "jobs/"',
    "AngelList_Job_Apply": 'http.host contains "angel.co" && http.request.uri contains "apply"',
    
    # --- We Work Remotely ---
    "WeWorkRemotely_Traffic": 'http.host contains "weworkremotely.com"',
    "WeWorkRemotely_Job_Postings": 'http.host contains "weworkremotely.com" && http.request.uri contains "job/"',
    "WeWorkRemotely_Job_Apply": 'http.host contains "weworkremotely.com" && http.request.uri contains "apply"',
    
    # --- Jobvite ---
    "Jobvite_Traffic": 'http.host contains "jobvite.com"',
    "Jobvite_Job_Postings": 'http.host contains "jobvite.com" && http.request.uri contains "job/"',
    "Jobvite_Job_Apply": 'http.host contains "jobvite.com" && http.request.uri contains "apply"',
    
    # --- Workable ---
    "Workable_Traffic": 'http.host contains "workable.com"',
    "Workable_Job_Postings": 'http.host contains "workable.com" && http.request.uri contains "jobs/"',
    "Workable_Job_Apply": 'http.host contains "workable.com" && http.request.uri contains "apply"',
    
    # --- Idealist ---
    "Idealist_Traffic": 'http.host contains "idealist.org"',
    "Idealist_Job_Postings": 'http.host contains "idealist.org" && http.request.uri contains "job/"',
    "Idealist_Job_Apply": 'http.host contains "idealist.org" && http.request.uri contains "apply"',
    
    # --- Jobscan ---
    "Jobscan_Traffic": 'http.host contains "jobscan.co"',
    "Jobscan_Job_Postings": 'http.host contains "jobscan.co" && http.request.uri contains "job/"',
    "Jobscan_Job_Apply": 'http.host contains "jobscan.co" && http.request.uri contains "apply"',


# --- Password-related Filters ---


    # --- General Login or Authentication Pages ---
    "Login_Page_Traffic": 'http.request.uri contains "login" || http.request.uri contains "signin" || http.request.uri contains "auth"',
    "Login_Form_Submission": 'http.request.method == "POST" && http.request.uri contains "login" || http.request.uri contains "signin" || http.request.uri contains "auth"',

    # --- Password Reset Pages ---
    "Password_Reset_Page": 'http.request.uri contains "reset" || http.request.uri contains "forgot-password" || http.request.uri contains "recover-password"',
    "Password_Reset_Submission": 'http.request.method == "POST" && http.request.uri contains "reset" || http.request.uri contains "forgot-password" || http.request.uri contains "recover-password"',
    
    # --- Social Media Passwords (Facebook, Twitter, Instagram) ---
    "Facebook_Login": 'http.host contains "facebook.com" && http.request.uri contains "/login/"',
    "Facebook_Password_Reset": 'http.host contains "facebook.com" && http.request.uri contains "password/reset"',
    "Twitter_Login": 'http.host contains "twitter.com" && http.request.uri contains "/login/"',
    "Twitter_Password_Reset": 'http.host contains "twitter.com" && http.request.uri contains "password/reset"',
    "Instagram_Login": 'http.host contains "instagram.com" && http.request.uri contains "/accounts/login/"',
    "Instagram_Password_Reset": 'http.host contains "instagram.com" && http.request.uri contains "accounts/password/reset"',
    
    # --- Google Login and Password Reset ---
    "Google_Login": 'http.host contains "google.com" && http.request.uri contains "/accounts/login/"',
    "Google_Password_Reset": 'http.host contains "google.com" && http.request.uri contains "accounts/password/reset"',
    
    # --- Microsoft Login and Password Reset ---
    "Microsoft_Login": 'http.host contains "login.live.com" && http.request.uri contains "login.srf"',
    "Microsoft_Password_Reset": 'http.host contains "login.live.com" && http.request.uri contains "password/reset"',
    
    # --- Apple ID Login and Password Reset ---
    "Apple_Login": 'http.host contains "appleid.apple.com" && http.request.uri contains "/account/login"',
    "Apple_Password_Reset": 'http.host contains "appleid.apple.com" && http.request.uri contains "/account/reset"',
    
    # --- Amazon Login and Password Reset ---
    "Amazon_Login": 'http.host contains "amazon.com" && http.request.uri contains "ap/signin"',
    "Amazon_Password_Reset": 'http.host contains "amazon.com" && http.request.uri contains "password/reset"',
    
    # --- PayPal Login and Password Reset ---
    "PayPal_Login": 'http.host contains "paypal.com" && http.request.uri contains "login"',
    "PayPal_Password_Reset": 'http.host contains "paypal.com" && http.request.uri contains "password/reset"',
    
    # --- Banking or Financial Services Login ---
    "Bank_Login": 'http.request.uri contains "login" && (http.host contains "bank" || http.host contains "fin")',
    "Bank_Password_Reset": 'http.request.uri contains "reset" && (http.host contains "bank" || http.host contains "fin")',
    
    # --- VPN Service Login ---
    "VPN_Service_Login": 'http.request.uri contains "login" && http.host contains "vpn"',
    "VPN_Service_Password_Reset": 'http.request.uri contains "reset" && http.host contains "vpn"',
    
    # --- Other Passwords, Login or Authentication Related Traffic ---
    "General_Authentication_Traffic": 'http.request.uri contains "auth" || http.request.uri contains "login" || http.request.uri contains "signin" || http.request.uri contains "logout"',
    "General_Password_Submission": 'http.request.method == "POST" && (http.request.uri contains "login" || http.request.uri contains "auth" || http.request.uri contains "signin")',


# --- WhatsApp Detection Filters ---


    # --- WhatsApp Web Traffic ---
    "WhatsApp_Web_Login_Page": 'http.host contains "web.whatsapp.com" && http.request.uri contains "login"',
    "WhatsApp_Web_Traffic": 'http.host contains "web.whatsapp.com"',
    
    # --- WhatsApp WebSocket Traffic (for real-time communication) ---
    "WhatsApp_WebSocket": 'tcp.port == 443 && ssl.record.version == 0x0303 && (tcp contains "websocket" || tls.record.content_type == 23)',
    
    # --- WhatsApp API Traffic ---
    "WhatsApp_API_Traffic": 'http.host contains "api.whatsapp.com"',
    "WhatsApp_API_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    "WhatsApp_API_Receive_Message": 'http.host contains "api.whatsapp.com" && http.request.uri contains "receiveMessage"',
    
    # --- WhatsApp Mobile Traffic (Encrypted) ---
    "WhatsApp_Mobile_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36)',  # example IPs associated with WhatsApp
    "WhatsApp_Mobile_Communication": 'tls.handshake.extensions_server_name contains "whatsapp.net" || tls.handshake.extensions_server_name contains "whatsapp.com"',
    
    # --- WhatsApp Mobile App Traffic Detection ---
    "WhatsApp_Mobile_App_Traffic": 'ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36 || ip.addr == 72.5.9.76',  # common WhatsApp mobile IPs
    "WhatsApp_Mobile_Encrypted_Connection": 'tls && (tcp.port == 443 || tcp.port == 80) && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36)',
    
    # --- WhatsApp Voice/Call Traffic ---
    "WhatsApp_Voice_Call_Traffic": 'udp.port == 3478 && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36)',  # Voice call ports
    "WhatsApp_Voice_Communication": 'tcp.port == 443 && tls.handshake.extensions_server_name contains "call.whatsapp.net"',

    # --- WhatsApp Media Traffic (Images/Videos/Audio) ---
    "WhatsApp_Media_Traffic": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',

    # --- WhatsApp Chat Sync Traffic (Mobile App Syncing) ---
    "WhatsApp_Sync_Traffic": 'http.host contains "sync.whatsapp.net" && http.request.uri contains "sync"',


# --- WhatsApp Detection Filters for Different OS ---


    # --- WhatsApp on Android ---
    "WhatsApp_Android_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36) && (tls.handshake.extensions_server_name contains "whatsapp.com" || tls.handshake.extensions_server_name contains "whatsapp.net")',
    "WhatsApp_Android_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_Android_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    
    # --- WhatsApp on iOS ---
    "WhatsApp_iOS_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36) && (tls.handshake.extensions_server_name contains "whatsapp.com" || tls.handshake.extensions_server_name contains "whatsapp.net")',
    "WhatsApp_iOS_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_iOS_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    
    # --- WhatsApp on MacOS ---
    "WhatsApp_MacOS_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36) && (tls.handshake.extensions_server_name contains "whatsapp.com" || tls.handshake.extensions_server_name contains "whatsapp.net")',
    "WhatsApp_MacOS_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_MacOS_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    
    # --- WhatsApp on Windows ---
    "WhatsApp_Windows_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36) && (tls.handshake.extensions_server_name contains "whatsapp.com" || tls.handshake.extensions_server_name contains "whatsapp.net")',
    "WhatsApp_Windows_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_Windows_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    
    # --- WhatsApp on Linux ---
    "WhatsApp_Linux_Traffic": 'ssl && (ip.addr == 185.220.100.255 || ip.addr == 31.13.71.36) && (tls.handshake.extensions_server_name contains "whatsapp.com" || tls.handshake.extensions_server_name contains "whatsapp.net")',
    "WhatsApp_Linux_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_Linux_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',
    
    # --- General WhatsApp Web Traffic ---
    "WhatsApp_Web_Traffic": 'http.host contains "web.whatsapp.com"',
    "WhatsApp_Web_Login": 'http.host contains "web.whatsapp.com" && http.request.uri contains "login"',
    "WhatsApp_Web_Media": 'http.host contains "mmg.whatsapp.net" && http.request.uri contains "media"',
    "WhatsApp_Web_Message_Send": 'http.host contains "api.whatsapp.com" && http.request.uri contains "sendMessage"',


# --- OTT Streaming Filters ---


    # --- Netflix ---
    "Netflix_Traffic": 'ssl && (ip.addr == 137.254.0.0 || ip.addr == 52.230.200.0 || ip.addr == 54.230.200.0) && (tls.handshake.extensions_server_name contains "netflix.com")',
    "Netflix_Video_Stream": 'http.host contains "netflix.com" && http.request.uri contains "/video"',
    "Netflix_Login": 'http.host contains "netflix.com" && http.request.uri contains "/login"',
    
    # --- Hulu ---
    "Hulu_Traffic": 'ssl && (ip.addr == 104.96.0.0 || ip.addr == 198.45.42.0) && (tls.handshake.extensions_server_name contains "hulu.com")',
    "Hulu_Video_Stream": 'http.host contains "hulu.com" && http.request.uri contains "/stream"',
    "Hulu_Login": 'http.host contains "hulu.com" && http.request.uri contains "/login"',
    
    # --- Amazon Prime Video ---
    "Amazon_Prime_Traffic": 'ssl && (ip.addr == 54.239.28.0 || ip.addr == 13.224.0.0) && (tls.handshake.extensions_server_name contains "amazonaws.com" && tls.handshake.extensions_server_name contains "primevideo.com")',
    "Amazon_Prime_Video_Stream": 'http.host contains "primevideo.com" && http.request.uri contains "/stream"',
    "Amazon_Prime_Login": 'http.host contains "amazon.com" && http.request.uri contains "/ap/signin"',
    
    # --- YouTube ---
    "YouTube_Traffic": 'ssl && (ip.addr == 142.250.0.0 || ip.addr == 216.58.0.0) && (tls.handshake.extensions_server_name contains "youtube.com")',
    "YouTube_Video_Stream": 'http.host contains "youtube.com" && http.request.uri contains "/watch"',
    "YouTube_Login": 'http.host contains "youtube.com" && http.request.uri contains "/signin"',
    
    # --- Disney+ ---
    "DisneyPlus_Traffic": 'ssl && (ip.addr == 13.227.96.0 || ip.addr == 23.62.40.0) && (tls.handshake.extensions_server_name contains "disneyplus.com")',
    "DisneyPlus_Video_Stream": 'http.host contains "disneyplus.com" && http.request.uri contains "/stream"',
    "DisneyPlus_Login": 'http.host contains "disneyplus.com" && http.request.uri contains "/login"',
    
    # --- Apple TV+ ---
    "AppleTVPlus_Traffic": 'ssl && (ip.addr == 17.172.224.0 || ip.addr == 17.176.0.0) && (tls.handshake.extensions_server_name contains "apple.com" && tls.handshake.extensions_server_name contains "tv.apple.com")',
    "AppleTVPlus_Video_Stream": 'http.host contains "tv.apple.com" && http.request.uri contains "/video"',
    "AppleTVPlus_Login": 'http.host contains "apple.com" && http.request.uri contains "/signin"',
    
    # --- Peacock (NBCUniversal) ---
    "Peacock_Traffic": 'ssl && (ip.addr == 151.101.128.0 || ip.addr == 23.7.0.0) && (tls.handshake.extensions_server_name contains "peacocktv.com")',
    "Peacock_Video_Stream": 'http.host contains "peacocktv.com" && http.request.uri contains "/stream"',
    "Peacock_Login": 'http.host contains "peacocktv.com" && http.request.uri contains "/login"',
    
    # --- Paramount+ ---
    "ParamountPlus_Traffic": 'ssl && (ip.addr == 52.87.0.0 || ip.addr == 13.32.0.0) && (tls.handshake.extensions_server_name contains "paramountplus.com")',
    "ParamountPlus_Video_Stream": 'http.host contains "paramountplus.com" && http.request.uri contains "/stream"',
    "ParamountPlus_Login": 'http.host contains "paramountplus.com" && http.request.uri contains "/signin"',


# --- Music Streaming Filters ---


    # --- Spotify ---
    "Spotify_Traffic": 'ssl && (ip.addr == 35.186.224.0 || ip.addr == 52.30.0.0) && (tls.handshake.extensions_server_name contains "spotify.com")',
    "Spotify_Stream": 'http.host contains "spotify.com" && http.request.uri contains "/track"',
    "Spotify_Login": 'http.host contains "spotify.com" && http.request.uri contains "/login"',
    
    # --- Apple Music ---
    "AppleMusic_Traffic": 'ssl && (ip.addr == 17.142.0.0 || ip.addr == 17.172.224.0) && (tls.handshake.extensions_server_name contains "music.apple.com")',
    "AppleMusic_Stream": 'http.host contains "music.apple.com" && http.request.uri contains "/music"',
    "AppleMusic_Login": 'http.host contains "apple.com" && http.request.uri contains "/signin"',
    
    # --- Tidal ---
    "Tidal_Traffic": 'ssl && (ip.addr == 185.5.230.0 || ip.addr == 35.190.0.0) && (tls.handshake.extensions_server_name contains "tidal.com")',
    "Tidal_Stream": 'http.host contains "tidal.com" && http.request.uri contains "/stream"',
    "Tidal_Login": 'http.host contains "tidal.com" && http.request.uri contains "/login"',
    
    # --- YouTube Music ---
    "YouTubeMusic_Traffic": 'ssl && (ip.addr == 142.250.0.0 || ip.addr == 216.58.0.0) && (tls.handshake.extensions_server_name contains "music.youtube.com")',
    "YouTubeMusic_Stream": 'http.host contains "music.youtube.com" && http.request.uri contains "/watch"',
    "YouTubeMusic_Login": 'http.host contains "youtube.com" && http.request.uri contains "/signin"',
    
    # --- Amazon Music ---
    "AmazonMusic_Traffic": 'ssl && (ip.addr == 54.239.28.0 || ip.addr == 13.224.0.0) && (tls.handshake.extensions_server_name contains "amazon.com" && tls.handshake.extensions_server_name contains "music.amazon.com")',
    "AmazonMusic_Stream": 'http.host contains "music.amazon.com" && http.request.uri contains "/stream"',
    "AmazonMusic_Login": 'http.host contains "amazon.com" && http.request.uri contains "/ap/signin"',
    
    # --- Deezer ---
    "Deezer_Traffic": 'ssl && (ip.addr == 185.18.168.0 || ip.addr == 52.30.0.0) && (tls.handshake.extensions_server_name contains "deezer.com")',
    "Deezer_Stream": 'http.host contains "deezer.com" && http.request.uri contains "/track"',
    "Deezer_Login": 'http.host contains "deezer.com" && http.request.uri contains "/login"',
    
    # --- SoundCloud ---
    "SoundCloud_Traffic": 'ssl && (ip.addr == 13.224.0.0 || ip.addr == 185.45.30.0) && (tls.handshake.extensions_server_name contains "soundcloud.com")',
    "SoundCloud_Stream": 'http.host contains "soundcloud.com" && http.request.uri contains "/track"',
    "SoundCloud_Login": 'http.host contains "soundcloud.com" && http.request.uri contains "/login"',


# --- Adult Content Filters ---


    # --- Adult Websites Traffic ---
    "Porn_Sites_Traffic": 'http.host contains "porn" || http.host contains "xxx" || http.host contains "sex" || http.host contains "adult"',
    "Porn_Sites_HTTPS": 'ssl && (tls.handshake.extensions_server_name contains "porn" || tls.handshake.extensions_server_name contains "xxx" || tls.handshake.extensions_server_name contains "sex" || tls.handshake.extensions_server_name contains "adult")',
    
    # --- Popular Adult Websites ---
    "Pornhub_Traffic": 'http.host contains "pornhub.com" || ssl && tls.handshake.extensions_server_name contains "pornhub.com"',
    "XVideos_Traffic": 'http.host contains "xvideos.com" || ssl && tls.handshake.extensions_server_name contains "xvideos.com"',
    "Xhamster_Traffic": 'http.host contains "xhamster.com" || ssl && tls.handshake.extensions_server_name contains "xhamster.com"',
    "RedTube_Traffic": 'http.host contains "redtube.com" || ssl && tls.handshake.extensions_server_name contains "redtube.com"',
    "YouPorn_Traffic": 'http.host contains "youporn.com" || ssl && tls.handshake.extensions_server_name contains "youporn.com"',
    "TXXX_Traffic": 'http.host contains "txxx.com" || ssl && tls.handshake.extensions_server_name contains "txxx.com"',
    "Spankwire_Traffic": 'http.host contains "spankwire.com" || ssl && tls.handshake.extensions_server_name contains "spankwire.com"',
    
    # --- Other Adult Content Platforms ---
    "Brazzers_Traffic": 'http.host contains "brazzers.com" || ssl && tls.handshake.extensions_server_name contains "brazzers.com"',
    "NaughtyAmerica_Traffic": 'http.host contains "naughtyamerica.com" || ssl && tls.handshake.extensions_server_name contains "naughtyamerica.com"',
    "Hustler_Traffic": 'http.host contains "hustler.com" || ssl && tls.handshake.extensions_server_name contains "hustler.com"',
    "Bangbros_Traffic": 'http.host contains "bangbros.com" || ssl && tls.handshake.extensions_server_name contains "bangbros.com"',
    "Pornstar_Traffic": 'http.host contains "pornstar.com" || ssl && tls.handshake.extensions_server_name contains "pornstar.com"',
    
    # --- Adult Content Platforms with Videos ---
    "AdultTime_Traffic": 'http.host contains "adulttime.com" || ssl && tls.handshake.extensions_server_name contains "adulttime.com"',
    "RealityKings_Traffic": 'http.host contains "realitykings.com" || ssl && tls.handshake.extensions_server_name contains "realitykings.com"',
    "Fapdu_Traffic": 'http.host contains "fapdu.com" || ssl && tls.handshake.extensions_server_name contains "fapdu.com"',
    
    # --- P2P File Sharing (Adult Content) ---
    "Adult_Torrent_Sites": 'http.host contains "torrent" && (http.host contains "adult" || http.host contains "porn")',
    
    # --- Content-Type Filters for Adult Video Sites ---
    "Porn_Video_Stream": 'http.content_type contains "video" && (http.host contains "porn" || http.host contains "xxx" || http.host contains "sex")',
    
    # --- Adult Website Login Pages ---
    "Porn_Login_Page": 'http.host contains "porn" && http.request.uri contains "/login"',
    
    # --- Adult Content Download Filters ---
    "Porn_Download": 'http.request.uri contains "download" && (http.host contains "porn" || http.host contains "adult")',
    
    # --- Adult Streaming and Media Files ---
    "Porn_Media_Stream": 'http.request.uri contains ".mp4" || http.request.uri contains ".avi" || http.request.uri contains ".mkv" && (http.host contains "porn" || http.host contains "adult")',
    
    # --- Suspicious Content Based on Content Length ---
    "Adult_Content_Length": 'http.content_length > 5000 && (http.host contains "porn" || http.host contains "xxx" || http.host contains "sex")',
    
    # --- Adult URLs for Traffic Detection ---
    "Porn_Explicit_Traffic": 'http.request.uri contains "porn" || http.request.uri contains "xxx" || http.request.uri contains "sex" || http.request.uri contains "adult" || http.host contains "porn"',
    
    # --- Adult Websites via IP Range ---
    "Porn_IP_Range": 'ip.addr == 185.0.0.0/24 || ip.addr == 104.20.0.0/14 || ip.addr == 45.55.55.0/24 && (http.host contains "porn" || http.host contains "adult")',
    
    # --- Proxy Detection (Common for Adult Sites) ---
    "Porn_Proxy_Detection": 'http.user_agent contains "proxy" && (http.host contains "porn" || http.host contains "adult")',


# --- VPN, Proxy, and Proxychains Filters ---


    # --- General VPN Traffic ---
    "VPN_Traffic": 'ip.addr == 10.0.0.0/8 || ip.addr == 172.16.0.0/12 || ip.addr == 192.168.0.0/16',  # Detects private IP ranges commonly used by VPNs
    "VPN_IPsec": 'ip.proto == 50',  # IPsec VPN protocol
    "VPN_L2TP": 'udp.port == 1701',  # L2TP VPN protocol
    "VPN_OpenVPN": 'udp.port == 1194',  # OpenVPN default port
    "VPN_PPTP": 'tcp.port == 1723',  # PPTP VPN protocol
    "VPN_SSTP": 'tcp.port == 443 && ssl.record.version == 0x0303',  # SSTP VPN over HTTPS
    "VPN_IKEv2": 'udp.port == 500',  # IKEv2 protocol for VPNs
    "VPN_IPv6": 'ipv6 && (ip.proto == 50 || udp.port == 1194 || udp.port == 1701)',  # VPN traffic over IPv6
    "VPN_Tor": 'ip.addr == 185.220.100.0/22',  # Detects Tor exit nodes
    "VPN_Tor_Encrypted": 'tls.handshake.extensions_server_name contains "tor"',  # Tor encrypted traffic detection
    
    # --- Proxy Traffic ---
    "Proxy_Traffic": 'http.proxy',  # Detects traffic passing through proxies
    "Proxy_HTTP": 'http.host contains "proxy"',  # Look for proxy servers in the HTTP requests
    "Proxy_Transparent": 'http.request.uri contains "proxy" && http.host contains "proxy"',  # Transparent proxy traffic
    "SOCKS_Proxy": 'tcp.port == 1080',  # SOCKS proxy default port
    "HTTP_Proxy": 'tcp.port == 3128',  # HTTP proxy default port (Squid Proxy)
    "HTTPS_Proxy": 'tcp.port == 443 && ssl.handshake.extensions_server_name contains "proxy"',  # HTTPS proxy
    "Proxy_Authentication": 'http.request.method == "CONNECT" && http.host contains "proxy"',  # Proxy authentication requests
    
    # --- Proxychains and Other Proxy Tools ---
    "Proxychains_Traffic": 'tcp.port == 9050',  # Proxychains uses SOCKS proxy, usually on port 9050
    "Proxychains_SOCKS": 'tcp.port == 9050 && tcp.flags.syn == 1 && tcp.flags.ack == 0',  # Detecting initial SOCKS proxy connection from Proxychains
    "Proxychains_UDP": 'udp.port == 9050',  # Proxychains using UDP packets
    "Proxychains_DNS": 'udp.port == 53 && ip.addr == 127.0.0.1',  # Proxychains DNS queries sent through local proxy (127.0.0.1)
    "Proxychains_Tor": 'tcp.port == 9050 && ip.addr == 185.220.100.0/22',  # Tor exit node traffic through Proxychains
    "Tor_Proxychains_Detection": 'tcp.port == 9050 && ip.addr == 185.220.100.0/22',  # Detecting Tor traffic from Proxychains
    
    # --- VPN/Proxy Fingerprints ---
    "VPN_Proxy_Headers": 'http.user_agent contains "vpn" || http.user_agent contains "proxy" || http.user_agent contains "proxychains"',  # Detects VPN/proxy headers in User-Agent
    "VPN_Proxy_IP_Fingerprint": 'ip.addr == 178.20.20.20',  # Known proxy or VPN server IP fingerprint (example)
    "VPN_Proxy_Encrypted": 'ssl.record.version == 0x0303',  # SSL/TLS encrypted traffic indicative of VPNs or proxies
    
    # --- VPN/Proxy VPN IP Range Detection ---
    "VPN_Proxy_IP_Ranges": 'ip.addr == 192.223.223.0/24 || ip.addr == 45.61.0.0/16 || ip.addr == 104.20.0.0/14',  # Known proxy/VPN IP ranges (example)
    
    # --- Detection of Known VPN and Proxy Services ---
    "NordVPN": 'ip.addr == 185.234.0.0/16',  # Detects traffic coming from known NordVPN servers
    "ExpressVPN": 'ip.addr == 198.8.255.0/24',  # ExpressVPN server range
    "Tunnelbear": 'ip.addr == 185.204.128.0/22',  # Tunnelbear VPN server range
    "Cyberghost_VPN": 'ip.addr == 185.222.0.0/16',  # Cyberghost VPN server range
    "IPVanish_VPN": 'ip.addr == 64.120.0.0/13',  # IPVanish server range
    "ProtonVPN": 'ip.addr == 185.230.0.0/16',  # ProtonVPN server range
    
    # --- Detection of Proxy Tools & VPN Clients ---
    "OpenVPN_Client": 'udp.port == 1194 && udp.length > 150',  # Identifies OpenVPN client traffic
    "Tunnelblick_VPN": 'tcp.port == 443 && http.user_agent contains "Tunnelblick"',  # Tunnelblick VPN client detection on port 443
    "Cisco_VPN_Client": 'udp.port == 500 && udp.port == 4500',  # Cisco AnyConnect VPN
    "IKEv2_VPN": 'udp.port == 500 && udp.port == 4500 && ip.addr == 192.168.0.0/16',  # IKEv2 VPN
    "Wireguard_VPN": 'udp.port == 51820',  # Wireguard VPN protocol
    
    # --- Detection of Tor Over Proxy ---
    "Tor_Proxy_Detection": 'ip.addr == 185.220.100.0/22 && tcp.port == 9050',  # Detecting Tor traffic routed through a proxy
    
    # --- Miscellaneous VPN/Proxy Tools ---
    "VPN_Traffic_Suspended": 'tcp.flags.syn == 1 && tcp.flags.ack == 0 && tcp.flags.reset == 1',  # VPN traffic detection for suspended connections
    "Proxy_Traffic_Detected": 'ip.addr == 185.60.216.0/22 && tcp.flags.syn == 1',  # Detection of proxy traffic from specific IP ranges


# --- Remote Desktop Filters ---


    # --- RDP (Remote Desktop Protocol) Detection ---
    "RDP": 'tcp.port == 3389',  # Default port for RDP (Remote Desktop Protocol)
    "RDP_Handshake": 'tcp.port == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0',  # RDP connection initiation (SYN)
    "RDP_TLS": 'tcp.port == 3389 && ssl.record.version == 0x0303',  # RDP over SSL/TLS
    "RDP_Version": 'tcp.port == 3389 && data-text-lines contains "Microsoft Terminal Services"',  # Detecting Microsoft RDP version
    "RDP_Encrypted": 'tcp.port == 3389 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "rdp"',  # RDP encrypted traffic

    # --- VNC (Virtual Network Computing) Detection ---
    "VNC": 'tcp.port == 5900',  # Default port for VNC (Virtual Network Computing)
    "VNC_Authentication": 'tcp.port == 5900 && data-text-lines contains "RFB"',  # VNC RFB (Remote Frame Buffer) Protocol Handshake
    "VNC_Encrypted": 'tcp.port == 5900 && ssl.record.version == 0x0303',  # VNC over SSL/TLS
    "VNC_Banner": 'tcp.port == 5900 && data-text-lines contains "RFB 003.003"',  # Banner indicating specific VNC version

    # --- SSH (Secure Shell) Detection ---
    "SSH": 'tcp.port == 22',  # Default port for SSH (Secure Shell)
    "SSH_Handshake": 'tcp.port == 22 && data-text-lines contains "SSH-2.0"',  # SSH Handshake (version detection)
    "SSH_Encrypted": 'tcp.port == 22 && tcp.flags.syn == 1 && tcp.flags.ack == 1',  # Identifying encrypted SSH connection initiation
    "SSH_Kex": 'tcp.port == 22 && data-text-lines contains "KEXINIT"',  # Key exchange in SSH
    "SSH_Authentication": 'tcp.port == 22 && data-text-lines contains "SSH-2.0-OpenSSH"',  # OpenSSH authentication banners

    # --- Telnet (Remote Command Line) Detection ---
    "Telnet": 'tcp.port == 23',  # Default port for Telnet
    "Telnet_Handshake": 'tcp.port == 23 && data-text-lines contains "Escape character is"',  # Telnet Protocol Handshake
    "Telnet_Encrypted": 'tcp.port == 23 && ssl.record.version == 0x0303',  # Telnet over SSL/TLS (if used)
    
    # --- RDP over HTTP (Remote Desktop Web Access) ---
    "RDP_HTTP": 'tcp.port == 443 && http.host contains "remotedesktop"',  # Detecting RDP over HTTPS (Remote Desktop Web Access)
    "RDP_Web": 'tcp.port == 443 && http.request.uri contains "tsweb"',  # Remote Desktop Web Access (TSWeb) detection
    
    # --- XRDP (Linux RDP) Detection ---
    "XRDP": 'tcp.port == 3389',  # Default port for XRDP (RDP for Linux)
    "XRDP_Handshake": 'tcp.port == 3389 && data-text-lines contains "RDP" && data-text-lines contains "xrdp"',  # XRDP protocol initiation
    "XRDP_Session": 'tcp.port == 3389 && data-text-lines contains "Xvnc"',  # XRDP VNC session detection

    # --- Remote Desktop Protocol Miscellaneous ---
    "RDP_Misc": 'tcp.port == 3389 && (data-text-lines contains "RDP")',  # Miscellaneous RDP traffic detection
    "VNC_Misc": 'tcp.port == 5900 && (data-text-lines contains "VNC")',  # Miscellaneous VNC traffic detection
    "Telnet_Misc": 'tcp.port == 23 && (data-text-lines contains "login")',  # Telnet login prompts detection
    "SSH_Misc": 'tcp.port == 22 && (data-text-lines contains "SSH")',  # Miscellaneous SSH traffic detection

    # --- Additional Remote Desktop Fingerprints ---
    "RDP_Fingerprint": 'tcp.port == 3389 && (data-text-lines contains "Microsoft")',  # Detecting Microsoft-specific RDP fingerprints
    "VNC_Fingerprint": 'tcp.port == 5900 && (data-text-lines contains "RFB")',  # Detecting VNC RFB protocol fingerprints
    "SSH_Fingerprint": 'tcp.port == 22 && (data-text-lines contains "SSH")',  # Detecting SSH fingerprints
    "Telnet_Fingerprint": 'tcp.port == 23 && (data-text-lines contains "Escape character")',  # Detecting Telnet escape character


# --- AnyDesk Detection Filters ---

    # Default AnyDesk communication port
    "AnyDesk": 'tcp.port == 7070',
    "AnyDesk_Handshake": 'tcp.port == 7070 && data-text-lines contains "AnyDesk"',
    
    # AnyDesk over SSL/TLS (secure connection)
    "AnyDesk_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "anydesk"',


# --- TeamViewer Detection Filters ---

    # TeamViewer communication port (default is 5938)
    "TeamViewer": 'tcp.port == 5938',
    
    # TeamViewer Handshake (identifies initial connection)
    "TeamViewer_Handshake": 'tcp.port == 5938 && data-text-lines contains "TeamViewer"',
    
    # TeamViewer over SSL/TLS
    "TeamViewer_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "teamviewer"',


# --- Chrome Remote Desktop Detection Filters ---

    # Chrome Remote Desktop communication port (default is 443 for HTTPS)
    "ChromeRemoteDesktop": 'tcp.port == 443 && http.host contains "remotedesktop.google.com"',
    
    # Identifying SSL handshake for Chrome Remote Desktop
    "ChromeRemoteDesktop_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "remotedesktop.google.com"',


# --- RemotePC Detection Filters ---

    # RemotePC communication port (default is 443)
    "RemotePC": 'tcp.port == 443 && http.host contains "remotepc.com"',
    
    # SSL/TLS encryption for RemotePC
    "RemotePC_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "remotepc.com"',


# --- Splashtop Detection Filters ---

    # Splashtop default port is 6783
    "Splashtop": 'tcp.port == 6783',
    
    # Splashtop SSL/TLS connection
    "Splashtop_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "splashtop"',


# --- LogMeIn Detection Filters ---

    # LogMeIn communication port (default port is 443)
    "LogMeIn": 'tcp.port == 443 && http.host contains "logmein.com"',
    
    # SSL/TLS connection for LogMeIn
    "LogMeIn_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "logmein.com"',


# --- NoMachine Detection Filters ---

    # NoMachine port (default is 4000)
    "NoMachine": 'tcp.port == 4000',
    
    # SSL/TLS NoMachine connection
    "NoMachine_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "nx"', 


# --- X2Go Detection Filters ---

    # X2Go default port is 22 (uses SSH)
    "X2Go": 'tcp.port == 22 && data-text-lines contains "X2Go"',
    
    # X2Go over SSL (if configured)
    "X2Go_TLS": 'tcp.port == 443 && ssl.record.version == 0x0303 && ssl.handshake.extensions_server_name contains "x2go"',


# --- Remmina Detection Filters ---

    # Remmina default ports (uses RDP, VNC, SSH, etc.)
    "Remmina_RDP": 'tcp.port == 3389',  # RDP
    "Remmina_VNC": 'tcp.port == 5900',  # VNC
    "Remmina_SSH": 'tcp.port == 22',   # SSH


# --- Wi-Fi & Router Login Page + Password Filters ---

    # Common router IPs (adjust if using different gateways)
    "Router_Login_HTTP_192.168.0.1": 'http.host == "192.168.0.1"',
    "Router_Login_HTTP_192.168.1.1": 'http.host == "192.168.1.1"',
    "Router_Login_HTTP_10.0.0.1": 'http.host == "10.0.0.1"',
    "Router_Login_HTTPS": 'tls.handshake.extensions_server_name contains "192.168"',
    
    # Login form detection via HTTP method POST
    "Router_Login_POST": 'http.request.method == "POST" && (http.host contains "192.168." || http.host contains "10.")',

    # Detection of common login page URIs
    "Router_Login_URI": 'http.request.uri contains "login"',
    "Router_Login_Admin_URI": 'http.request.uri contains "admin"',
    "Router_Login_Setup_URI": 'http.request.uri contains "setup"',

    # Router vendor names in HTTP headers or SSL SNI
    "Router_Linksys": 'http.server contains "Linksys" || tls.handshake.extensions_server_name contains "linksys"',
    "Router_Netgear": 'http.server contains "NETGEAR" || tls.handshake.extensions_server_name contains "netgear"',
    "Router_TP_Link": 'http.server contains "TP-LINK" || tls.handshake.extensions_server_name contains "tplink"',
    "Router_DLink": 'http.server contains "D-Link" || tls.handshake.extensions_server_name contains "dlink"',
    "Router_Asus": 'http.server contains "ASUS" || tls.handshake.extensions_server_name contains "asus"',
    "Router_Huawei": 'http.server contains "Huawei" || tls.handshake.extensions_server_name contains "huawei"',
    "Router_Zyxel": 'http.server contains "Zyxel" || tls.handshake.extensions_server_name contains "zyxel"',

    # Login credentials (username, password, etc.)
    "WiFi_Password_Form_Data": 'http.form_data contains "password"',
    "WiFi_Username_Form_Data": 'http.form_data contains "username"',
    "WiFi_Login_Form_Credentials": 'frame contains "username" && frame contains "password"',
    "WiFi_Basic_Auth": 'http.authorization contains "Basic"',
    "WiFi_Password_In_URL": 'http.request.uri contains "password"',

    # Base64-encoded strings possibly containing credentials
    "WiFi_Base64_Encoded_Creds": 'frame matches "[A-Za-z0-9+/=]{20,}"',

    # Unencrypted credential transmission
    "WiFi_Unencrypted_Login": 'http && http.request.method == "POST" && frame contains "password"',

    # Wi-Fi authentication protocols (not web-based, but useful)
    "EAPOL_Authentication": 'eapol',
    "WPA_Handshake": 'eapol.type == 3',
    "WPA_Authentication_Request": 'eapol.keydes.key_info.key_type == 1',

    # Captive portal detection
    "Captive_Portal_Redirect": 'http.response.code == 302 && http.location contains "login"',
    "Captive_Portal_Location_Header": 'http.location contains "captive"',


# --- Hypervisor / Virtualization Detection Filters ---

    # VirtualBox
    "VirtualBox_MAC": 'eth.addr contains "08:00:27"',  # Default VirtualBox MAC prefix
    "VirtualBox_DHCP_Option": 'bootp.option.vendor_class_id contains "VirtualBox"',

    # VMware
    "VMware_MAC": 'eth.addr matches "00:05:69.*" || eth.addr matches "00:0C:29.*" || eth.addr matches "00:1C:14.*" || eth.addr matches "00:50:56.*"',
    "VMware_DHCP_Option": 'bootp.option.vendor_class_id contains "VMware"',
    "VMware_GuestInfo_Protocol": 'tcp.port == 902',

    # Hyper-V
    "HyperV_MAC": 'eth.addr matches "00:15:5D.*"',
    "HyperV_Protocol_Integration": 'tcp.port == 2179 || tcp.port == 3389',  # RDP + WMI integration

    # KVM/QEMU
    "KVM_MAC": 'eth.addr matches "52:54:00.*"',
    "KVM_SMBIOS_String": 'frame contains "QEMU"',  # Often in system info / SMBIOS response

    # Xen
    "Xen_MAC": 'eth.addr matches "00:16:3E.*"',
    "Xen_SMBIOS": 'frame contains "Xen"',  # e.g., in HTTP headers or DHCP options

    # Parallels
    "Parallels_MAC": 'eth.addr matches "00:1C:42.*"',

    # Generic Virtualization
    "Virtual_Machine_MAC_Common": 'eth.addr matches "00:05:69.*|00:0C:29.*|00:1C:14.*|00:50:56.*|08:00:27.*|00:15:5D.*|52:54:00.*|00:16:3E.*|00:1C:42.*"',
    "Virtualization_DHCP_Hints": 'bootp.option.vendor_class_id contains "Virtual" || bootp.option.vendor_class_id contains "VMware" || bootp.option.vendor_class_id contains "VBox"',
    "Virtualization_SMBIOS_Signature": 'frame contains "Virtual" && (http || smb || dhcp || tls)',


# --- Calling / VoIP / Audio Communication Detection Filters ---


    # SIP (Session Initiation Protocol) - most VoIP apps
    "SIP_Call_Signaling": 'sip',
    "SIP_INVITE": 'sip.Method == "INVITE"',
    "SIP_BYE": 'sip.Method == "BYE"',
    "SIP_Registration": 'sip.Method == "REGISTER"',

    # RTP (Real-Time Transport Protocol) - media/audio stream
    "RTP_Audio_Traffic": 'rtp',
    "RTP_Payload": 'rtp.payload',
    "RTP_Over_UDP": 'udp && rtp',
    "RTP_Over_TCP": 'tcp && rtp',
    
    # VoIP Control and Codecs
    "SDP_Negotiation": 'sdp',
    "H323": 'h323',
    "MGCP": 'mgcp',
    "VoIP_Packet_Analysis": 'voip',
    "G711_Codec": 'rtp.payload_type == 0 || rtp.payload_type == 8',
    "G729_Codec": 'rtp.payload_type == 18',

    # Skype (legacy detection, some UDP)
    "Skype_UDP_Traffic": 'udp.port == 23399 || udp.port == 33435',
    "Skype_HTTP_Tunnel": 'http.user_agent contains "Skype"',
    "Skype_Detection": 'frame contains "skype"',

    # WhatsApp Calls
    "WhatsApp_Call_UDP": 'udp.port == 3478 || udp.port == 45395 || udp contains "whatsapp"',
    "WhatsApp_Call_TLS": 'tls.handshake.extensions_server_name contains "whatsapp.net" && frame.len > 600',

    # Facebook Messenger Calls
    "Messenger_Call_TLS": 'tls.handshake.extensions_server_name contains "messenger.com"',
    "Messenger_Call_Media": 'tls.handshake.extensions_server_name contains "cdn.fbsbx.com"',

    # Telegram Calls
    "Telegram_Call_TLS": 'tls.handshake.extensions_server_name contains "telegram.org" || tls.handshake.extensions_server_name contains "t.me"',

    # Google Meet / Duo
    "Google_Meet_Calls": 'tls.handshake.extensions_server_name contains "meet.google.com"',
    "Google_Duo_Calls": 'tls.handshake.extensions_server_name contains "duo.google.com"',

    # Zoom
    "Zoom_Signaling": 'tls.handshake.extensions_server_name contains "zoom.us"',
    "Zoom_UDP_Call": 'udp.port == 8801 || udp.port == 8802 || udp.port == 3478',
    "Zoom_TCP_Call": 'tcp.port == 8801 || tcp.port == 8802',

    # Microsoft Teams
    "Teams_Call_TLS": 'tls.handshake.extensions_server_name contains "teams.microsoft.com"',

    # Discord Calls
    "Discord_Call_TLS": 'tls.handshake.extensions_server_name contains "discord.com" || tls.handshake.extensions_server_name contains "discordapp.com"',

    # Signal Calls
    "Signal_Call_Traffic": 'tls.handshake.extensions_server_name contains "signal.org"',

    # Jitsi
    "Jitsi_Meet_Traffic": 'tls.handshake.extensions_server_name contains "meet.jit.si" || tls.handshake.extensions_server_name contains "8x8.vc"',

    # WebRTC General (used by many platforms)
    "WebRTC_UDP": 'udp.port == 3478 || udp.port == 5349',
    "WebRTC_STUN": 'stun',
    "WebRTC_TURN": 'turn',
    "WebRTC_ICE": 'frame contains "a=candidate"',
    "WebRTC_SDP": 'sdp && frame contains "a=rtcp"',
    
    # General VOIP App Signatures
    "Voice_Traffic_High_Length": 'udp.len > 300 && udp.len < 1400 && udp',
    "Encrypted_Call_TLS": 'tls.record.content_type == 23 && frame.len > 800',



# --- RTSP and Related Streaming Protocol Filters ---


    # RTSP (Real-Time Streaming Protocol)
    "RTSP_All": 'rtsp',
    "RTSP_Describe": 'rtsp.method == "DESCRIBE"',
    "RTSP_Announce": 'rtsp.method == "ANNOUNCE"',
    "RTSP_Options": 'rtsp.method == "OPTIONS"',
    "RTSP_Setup": 'rtsp.method == "SETUP"',
    "RTSP_Play": 'rtsp.method == "PLAY"',
    "RTSP_Pause": 'rtsp.method == "PAUSE"',
    "RTSP_Teardown": 'rtsp.method == "TEARDOWN"',
    "RTSP_Transport": 'rtsp.Transport',

    # RTP (Real-Time Transport Protocol) - often used by RTSP
    "RTP_All": 'rtp',
    "RTP_Payload": 'rtp.payload',
    "RTP_Video": 'rtp.marker == 1',  # Often used to indicate key frames
    "RTP_Audio": 'rtp.payload_type == 0 || rtp.payload_type == 8',  # G.711
    "RTP_H264": 'rtp.payload_type == 96 && rtp.ssrc',  # Dynamic payload (often H.264)
    "RTP_Payload_Dynamic": 'rtp.payload_type >= 96',
    
    # RTCP (Real-Time Control Protocol)
    "RTCP_All": 'rtcp',
    "RTCP_SR": 'rtcp.pkt_type == 200',  # Sender Report
    "RTCP_RR": 'rtcp.pkt_type == 201',  # Receiver Report
    "RTCP_SDES": 'rtcp.pkt_type == 202',  # Source Description
    "RTCP_BYE": 'rtcp.pkt_type == 203',

    # MPEG Transport Stream (used for media delivery)
    "MPEG_TS": 'mpegts',
    "MPEG_TS_UDP": 'udp && mpegts',
    "MPEG_TS_Over_TCP": 'tcp && mpegts',

    # HTTP Live Streaming (HLS)
    "HLS_M3U8_Request": 'http.request.uri contains ".m3u8"',
    "HLS_TS_Segment": 'http.request.uri contains ".ts"',
    "HLS_Audio_Segment": 'http.request.uri contains ".aac"',
    
    # DASH (Dynamic Adaptive Streaming over HTTP)
    "DASH_MPD": 'http.request.uri contains ".mpd"',
    "DASH_Segment": 'http.request.uri contains "seg" && http',

    # FLV and RTMP (Real-Time Messaging Protocol)
    "FLV_HTTP": 'http.content_type contains "video/x-flv"',
    "RTMP_Detection": 'tcp.port == 1935 || tcp contains "rtmp"',
    "RTMPT": 'http.request.uri contains "/fcs/ident2" || http.request.uri contains "/open/1"',  # RTMP tunneled over HTTP

    # WebRTC (used for streaming too)
    "WebRTC_RTP": 'rtp && udp && frame contains "webrtc"',
    "WebRTC_STUN": 'stun',
    "WebRTC_TURN": 'turn',
    "WebRTC_SDP": 'sdp && frame contains "a=rtcp"',
    
    # Multicast Streaming
    "Multicast_RTP": 'ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255 && udp && rtp',
    "Multicast_MPEGTS": 'ip.dst >= 224.0.0.0 && ip.dst <= 239.255.255.255 && udp && mpegts',

    # General Media Streaming Detection
    "Streaming_Large_UDP": 'udp.length > 1200 && udp',
    "Streaming_Continuous_Traffic": 'frame.len > 1000 && ip && (udp || tcp)',
    "Encrypted_Streaming_TLS": 'tls.record.content_type == 23 && frame.len > 800 && tls',
    


# --- Malware Detection Filters ---


    # Suspicious Executables
    "PE_Executable_Transfer": 'http.content_type contains "application/x-msdownload" || http.request.uri contains ".exe" || tcp contains "MZ"',
    "EXE_Over_HTTP": 'http.request.uri contains ".exe"',
    "EXE_Over_FTP": 'ftp.request.command == "RETR" && ftp.request.arg contains ".exe"',
    "Portable_Executable_Headers": 'tcp contains "MZ" || tcp contains "This program cannot be run in DOS mode"',

    # Common malware file types
    "EXE_DLL_SYS": 'http.request.uri matches "\\.(exe|dll|sys)$"',
    "JS_VBS_PS1_Macros": 'http.request.uri matches "\\.(js|vbs|ps1|doc|docm|xlsm|vbe|hta)$"',
    "Zip_RAR_Malware": 'http.request.uri matches "\\.(zip|rar)$"',
    "ISO_IMG_Mountable": 'http.request.uri matches "\\.(iso|img)$"',

    # Suspicious TLS Activity (C2, encrypted malware)
    "TLS_Unknown_SNI": 'tls.handshake.extensions_server_name == "" || tls.handshake.extensions_server_name contains "duckdns" || tls.handshake.extensions_server_name contains "dynv6"',
    "TLS_Anomalous_Ports": 'tls && !(tcp.port == 443)',
    "SelfSigned_TLS": 'x509sat.printableString contains "localhost" || x509sat.printableString contains "test"',

    # DNS Tunneling
    "DNS_Long_Query": 'dns.qry.name and strlen(dns.qry.name) > 50',
    "DNS_Suspicious_Domains": 'dns.qry.name contains "dyndns" || dns.qry.name contains "duckdns" || dns.qry.name contains "no-ip"',
    "DNS_Base64_Encoded": 'dns.qry.name matches "[A-Za-z0-9+/=]{20,}"',

    # C2 Communication Patterns
    "IRC_C2_Traffic": 'irc',
    "Tor_Obfs": 'tcp.port == 9001 || tcp.port == 9030 || tcp.port == 9150',
    "C2_Sleeping_Beacon": 'frame.time_delta > 60 && ip.dst == ip.src && frame.len < 200',

    # Ransomware Indicators
    "Ransom_Note_HTTP": 'http.response and http.content_type contains "text/html" and http.file_data contains "decrypt"',
    "Massive_File_Transfer": 'tcp && frame.len > 1000000',
    "Random_Domain_Contacts": 'dns.qry.name matches "[a-z0-9]{16,}"',

    # Powershell and Scripting Malware
    "Encoded_PS": 'tcp contains "powershell.exe" || tcp matches "JAB[0-9a-zA-Z]+"',
    "Base64_PS": 'http.request.uri contains "powershell" && http.request.uri contains "base64"',  

    # SMB Worm Propagation
    "SMB_Write_Exec": 'smb2.cmd == 0x05 && smb2.filename contains ".exe"',
    "SMB_Spread": 'smb2 && frame.len > 1000',

    # Malware using FTP
    "FTP_Malware_Drop": 'ftp.request.command == "STOR" && ftp.request.arg matches "\\.(exe|dll|bat|vbs|ps1)"',

    # Malicious Macros & Office Documents
    "Macro_Documents": 'http.request.uri matches "\\.(doc|docm|xls|xlsm|pptm)"',
    "OLE_Suspicious": 'tcp contains "D0CF11E0A1B11AE1"',  # Compound File Binary

    # Suspicious User-Agent (malware toolkits)
    "UserAgent_Meterpreter": 'http.user_agent contains "Meterpreter"',
    "UserAgent_PyHTTP": 'http.user_agent contains "Python-urllib"',
    "UserAgent_CobaltStrike": 'http.user_agent contains "Cobalt"',
    "Empty_UserAgent": 'http.user_agent == ""',

    # Beaconing
    "Consistent_Beacon_Traffic": 'frame.time_delta_displayed > 30 && frame.len < 300 && ip.dst == ip.src',
    
    # Exploit Kits / Exploit Behavior
    "Exploit_CVE_URLs": 'http.request.uri contains "cve"',
    "Shellcode_Like_Transfer": 'tcp contains "\\x90\\x90\\x90\\x90" || tcp contains "\\xcc\\xcc\\xcc"',
    "ETERNALBLUE_Signature": 'tcp.port == 445 && smb2 && frame.len > 1500',

    # Obfuscated Content
    "Base64_HTTP_Payload": 'http.file_data matches "[A-Za-z0-9+/=]{100,}"',
    "Binary_Over_HTTP": 'http && frame.len > 100000',

    # Malware Domains (IOC-style)
    "IOC_Known_Hosts": 'dns.qry.name contains "malware" || dns.qry.name contains "tor2web" || dns.qry.name contains "c2server" || dns.qry.name contains "blackhole"',



# --- Phishing Detection Filters ---


    # Suspicious HTTP Requests
    "Suspicious_HTTP_Login": 'http.request.uri contains "login" || http.request.uri contains "signin" || http.request.uri contains "verify"',
    "Fake_Branded_Logins": 'http.request.uri contains "paypal" || http.request.uri contains "apple" || http.request.uri contains "microsoft" || http.request.uri contains "amazon"',
    "Phishing_Login_Pages": 'http.request.uri contains "secure" && http.request.uri contains "account"',
    "HTTP_Password_Leak": 'http contains "password=" || http contains "pwd=" || http contains "pass="',

    # Unusual User-Agent Strings
    "Empty_UserAgent": 'http.user_agent == ""',
    "Phishing_UserAgent": 'http.user_agent contains "curl" || http.user_agent contains "python" || http.user_agent contains "winhttp"',

    # Suspicious URLs or Domains
    "Suspicious_Domain_Names": 'dns.qry.name contains "verify" || dns.qry.name contains "login" || dns.qry.name contains "secure"',
    "Lookalike_Domains": 'dns.qry.name matches "(paypa1|micros0ft|amazan|faceb00k|g00gle)"',
    "Free_Dynamic_DNS": 'dns.qry.name contains "duckdns" || dns.qry.name contains "no-ip" || dns.qry.name contains "dynv6"',

    # Credential Harvesting over HTTP
    "GET_With_Creds": 'http.request.method == "GET" && http.request.uri contains "password"',
    "POST_With_Creds": 'http.request.method == "POST" && http contains "username" && http contains "password"',

    # Base64 or Obfuscated Parameters
    "Base64_Encoded_Params": 'http.request.uri matches "[A-Za-z0-9+/=]{20,}"',
    "Obfuscated_Query_String": 'http.request.uri contains "%3D" || http.request.uri contains "%2F"',

    # Email-Based Phishing (SMTP/IMAP/POP)
    "Suspicious_Email_Keyword": 'smtp.req.parameter contains "reset your password" || smtp.req.parameter contains "urgent account update"',
    "Email_Exec_Attachment": 'smtp contains ".exe" || smtp contains ".scr" || smtp contains ".vbs" || smtp contains ".zip"',

    # Phishing Pages Over HTTPS (TLS SNI Analysis)
    "TLS_SNI_Phishing": 'tls.handshake.extensions_server_name contains "login" || tls.handshake.extensions_server_name contains "secure"',

    # DNS Over HTTPS (DoH) Potential Phishing Bypass
    "DoH_Traffic": 'dns && tls.handshake.extensions_server_name contains "mozilla" && dns.qry.name',

    # Hidden Iframe Phishing
    "Hidden_Iframe_Attack": 'http.file_data contains "<iframe" && http.file_data contains "display:none"',

    # Known Phishing Indicators
    "IOC_Phishing_Hosts": 'dns.qry.name contains "phish" || dns.qry.name contains "malicious" || dns.qry.name contains "phishingkit"',

}

# Output folder
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output_folder = f"packet_analysis_output_{timestamp}"
os.makedirs(output_folder, exist_ok=True)

# PCAP input
pcap_file = input("Enter the path to your .pcap or .pcapng file: ").strip()

# Function to run TShark filters and save results in CSV and HTML formats
def run_filter(name, expression):
    output_csv_file = os.path.join(output_folder, f"{name}.csv")
    output_html_file = os.path.join(output_folder, f"{name}.html")
    print(f"[*] Running filter: {name}")
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_file, '-Y', expression, '-T', 'fields', '-e', '_ws.col.No.', '-e', '_ws.col.Time', '-e', '_ws.col.Source', '-e', '_ws.col.Destination', '-e', '_ws.col.Protocol', '-e', '_ws.col.Info'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if result.stdout:
            # Save to CSV
            with open(output_csv_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["No.", "Time", "Source", "Destination", "Protocol", "Info"])
                for line in result.stdout.strip().split('\n'):
                    writer.writerow(line.split('\t'))
            print(f"[+] CSV Output saved to: {output_csv_file}")

            # Save to HTML
            with open(output_html_file, 'w') as htmlfile:
                htmlfile.write("<html><head><title>Packet Analysis Results</title></head><body><table border='1'>")
                htmlfile.write("<tr><th>No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th></tr>")
                for line in result.stdout.strip().split('\n'):
                    htmlfile.write("<tr>")
                    for field in line.split('\t'):
                        htmlfile.write(f"<td>{escape(field)}</td>")
                    htmlfile.write("</tr>")
                htmlfile.write("</table></body></html>")
            print(f"[+] HTML Output saved to: {output_html_file}\n")
        else:
            print(f"[-] No matches found for {name}.\n")
    except Exception as e:
        print(f"[!] Error running filter {name}: {e}\n")

# Run all filters
for label, filter_expr in filters.items():
    run_filter(label, filter_expr)

# Count filters
filter_count = len(filters)
print(f"[*] Total number of filters applied: {filter_count}")

print(f"[*] Analysis complete. Results saved to {output_folder}.")
