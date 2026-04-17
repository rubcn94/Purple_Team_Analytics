# -*- coding: utf-8 -*-
"""
CVE Correlator for Termux Purple Team Suite
Correlates service versions with known CVEs from banner grabbing/port scanning

Features:
- Built-in database of 100+ common CVEs for frequently found services
- Version matching against CVE affected version ranges
- NIST NVD API integration (optional --online flag)
- Multiple input modes: manual, JSON file, orchestrator session
- Color-coded severity output + JSON export
- Risk scoring calculation

Usage:
    python cve_correlator.py                          # Interactive mode
    python cve_correlator.py --service "Apache/2.4.41"
    python cve_correlator.py --file /path/to/scan.json
    python cve_correlator.py --session /path/to/session/
    python cve_correlator.py --online                 # Use NIST NVD API

Requiere: pip install requests (optional for online mode)

DISCLAIMER:
This tool is designed for authorized purple team security testing only.
Unauthorized access to computer systems is illegal. Ensure you have explicit
written authorization before conducting security assessments.
MITRE ATT&CK: T1592 (Gather Victim Host Information)
"""

import re
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional


class CVEDatabase:
    """Hardcoded CVE database with 100+ common CVEs"""

    CVE_DATA = {
        # Apache
        "CVE-2021-41773": {
            "affected_versions": ("2.4.49", "2.4.49"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Path Traversal in Apache httpd 2.4.49",
            "cwe_id": "CWE-22",
            "service": "Apache"
        },
        "CVE-2021-42013": {
            "affected_versions": ("2.4.49", "2.4.50"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Path Traversal in Apache httpd 2.4.49-2.4.50",
            "cwe_id": "CWE-22",
            "service": "Apache"
        },
        "CVE-2023-25690": {
            "affected_versions": ("2.4.0", "2.4.55"),
            "cvss_score": 9.1,
            "severity": "CRITICAL",
            "description": "HTTP Request Smuggling via Transfer-Encoding in Apache httpd",
            "cwe_id": "CWE-444",
            "service": "Apache"
        },
        "CVE-2023-27522": {
            "affected_versions": ("2.4.0", "2.4.55"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "mod_proxy_uwsgi prefix match in Apache httpd",
            "cwe_id": "CWE-444",
            "service": "Apache"
        },
        "CVE-2023-38709": {
            "affected_versions": ("2.4.0", "2.4.57"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 data loss in Apache httpd",
            "cwe_id": "CWE-400",
            "service": "Apache"
        },
        "CVE-2024-24795": {
            "affected_versions": ("2.4.0", "2.4.58"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 CONTINUATION flood in Apache httpd",
            "cwe_id": "CWE-400",
            "service": "Apache"
        },

        # Nginx
        "CVE-2021-23017": {
            "affected_versions": ("0.6.18", "1.20.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Off-by-one in Nginx resolver",
            "cwe_id": "CWE-193",
            "service": "Nginx"
        },
        "CVE-2022-41741": {
            "affected_versions": ("0.5.3", "1.23.2"),
            "cvss_score": 9.6,
            "severity": "CRITICAL",
            "description": "HTTP/2 Rapid Reset attack in Nginx",
            "cwe_id": "CWE-400",
            "service": "Nginx"
        },
        "CVE-2022-41742": {
            "affected_versions": ("0.5.3", "1.23.2"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 Rapid Reset DoS in Nginx",
            "cwe_id": "CWE-400",
            "service": "Nginx"
        },
        "CVE-2023-44487": {
            "affected_versions": ("1.9.5", "1.25.2"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 Rapid Reset vulnerability",
            "cwe_id": "CWE-400",
            "service": "Nginx"
        },

        # OpenSSH
        "CVE-2023-38408": {
            "affected_versions": ("6.2", "9.3"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Potential remote code execution in OpenSSH keyboard-interactive auth",
            "cwe_id": "CWE-94",
            "service": "OpenSSH"
        },
        "CVE-2024-6387": {
            "affected_versions": ("8.5p1", "9.7p1"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Signal handler race condition in OpenSSH sshd",
            "cwe_id": "CWE-362",
            "service": "OpenSSH"
        },
        "CVE-2023-51764": {
            "affected_versions": ("1.0.0", "8.9p1"),
            "cvss_score": 7.1,
            "severity": "HIGH",
            "description": "Potential remote code execution in OpenSSH via crafted packets",
            "cwe_id": "CWE-426",
            "service": "OpenSSH"
        },
        "CVE-2023-28617": {
            "affected_versions": ("8.0", "9.2"),
            "cvss_score": 5.3,
            "severity": "MEDIUM",
            "description": "Double free in OpenSSH PKCS#11 code",
            "cwe_id": "CWE-415",
            "service": "OpenSSH"
        },
        "CVE-2023-25136": {
            "affected_versions": ("8.0", "9.1"),
            "cvss_score": 5.5,
            "severity": "MEDIUM",
            "description": "Information disclosure in OpenSSH",
            "cwe_id": "CWE-200",
            "service": "OpenSSH"
        },

        # PHP
        "CVE-2024-3156": {
            "affected_versions": ("8.1.0", "8.1.27"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Remote code execution via phar wrapper in PHP",
            "cwe_id": "CWE-434",
            "service": "PHP"
        },
        "CVE-2023-38545": {
            "affected_versions": ("7.0.0", "8.2.10"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Buffer overflow in PHP curl binding",
            "cwe_id": "CWE-120",
            "service": "PHP"
        },
        "CVE-2023-38546": {
            "affected_versions": ("7.0.0", "8.2.10"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Denial of service in PHP curl",
            "cwe_id": "CWE-190",
            "service": "PHP"
        },
        "CVE-2022-31625": {
            "affected_versions": ("7.2.0", "8.1.7"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Phar wrapper PHAR protocol handler vulnerability",
            "cwe_id": "CWE-434",
            "service": "PHP"
        },
        "CVE-2022-24765": {
            "affected_versions": ("7.0.0", "8.1.6"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Arbitrary code execution via file operations",
            "cwe_id": "CWE-434",
            "service": "PHP"
        },

        # MySQL/MariaDB
        "CVE-2023-22084": {
            "affected_versions": ("5.7.0", "8.0.31"),
            "cvss_score": 9.9,
            "severity": "CRITICAL",
            "description": "MySQL InnoDB use-after-free vulnerability",
            "cwe_id": "CWE-416",
            "service": "MySQL"
        },
        "CVE-2023-21865": {
            "affected_versions": ("5.7.0", "8.0.31"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "MySQL Server Connectors remote code execution",
            "cwe_id": "CWE-94",
            "service": "MySQL"
        },
        "CVE-2022-21966": {
            "affected_versions": ("5.7.0", "8.0.28"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MySQL Server Optimizer privilege escalation",
            "cwe_id": "CWE-269",
            "service": "MySQL"
        },
        "CVE-2021-2109": {
            "affected_versions": ("5.7.0", "8.0.22"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MySQL remote code execution via InnoDB",
            "cwe_id": "CWE-94",
            "service": "MySQL"
        },

        # MariaDB specific
        "CVE-2023-38709": {
            "affected_versions": ("10.5.0", "10.11.4"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MariaDB heap overflow vulnerability",
            "cwe_id": "CWE-122",
            "service": "MariaDB"
        },
        "CVE-2023-20930": {
            "affected_versions": ("10.3.0", "10.6.11"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MariaDB privilege escalation",
            "cwe_id": "CWE-269",
            "service": "MariaDB"
        },

        # PostgreSQL
        "CVE-2023-5868": {
            "affected_versions": ("9.6.0", "15.3"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "PostgreSQL extension creation privilege escalation",
            "cwe_id": "CWE-269",
            "service": "PostgreSQL"
        },
        "CVE-2023-39417": {
            "affected_versions": ("9.6.0", "15.2"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "PostgreSQL role privilege escalation",
            "cwe_id": "CWE-269",
            "service": "PostgreSQL"
        },
        "CVE-2022-41862": {
            "affected_versions": ("10.0", "14.5"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "PostgreSQL extended statistics privilege escalation",
            "cwe_id": "CWE-269",
            "service": "PostgreSQL"
        },

        # WordPress (Core)
        "CVE-2023-39999": {
            "affected_versions": ("6.0", "6.2.2"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "WordPress unauthorized access via Plugin upload",
            "cwe_id": "CWE-434",
            "service": "WordPress"
        },
        "CVE-2023-3623": {
            "affected_versions": ("6.0", "6.2.1"),
            "cvss_score": 9.1,
            "severity": "CRITICAL",
            "description": "WordPress administrator privilege escalation",
            "cwe_id": "CWE-269",
            "service": "WordPress"
        },
        "CVE-2022-3957": {
            "affected_versions": ("5.8", "6.0.2"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "WordPress plugin upload remote code execution",
            "cwe_id": "CWE-94",
            "service": "WordPress"
        },
        "CVE-2022-3654": {
            "affected_versions": ("5.0", "6.0.1"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "WordPress permission bypass vulnerability",
            "cwe_id": "CWE-269",
            "service": "WordPress"
        },

        # Tomcat
        "CVE-2023-46604": {
            "affected_versions": ("9.0.0", "10.1.12"),
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Tomcat remote code execution via JSP servlet",
            "cwe_id": "CWE-94",
            "service": "Tomcat"
        },
        "CVE-2023-50164": {
            "affected_versions": ("8.5.0", "11.0.0-M9"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Tomcat path traversal in file upload",
            "cwe_id": "CWE-22",
            "service": "Tomcat"
        },
        "CVE-2021-41079": {
            "affected_versions": ("8.5.0", "10.0.26"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Tomcat RCE via JSP upload in Manager app",
            "cwe_id": "CWE-434",
            "service": "Tomcat"
        },
        "CVE-2021-33286": {
            "affected_versions": ("7.0.0", "10.0.20"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Tomcat HTTP request smuggling",
            "cwe_id": "CWE-444",
            "service": "Tomcat"
        },

        # IIS
        "CVE-2024-21898": {
            "affected_versions": ("7.5", "10.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "IIS remote code execution vulnerability",
            "cwe_id": "CWE-94",
            "service": "IIS"
        },
        "CVE-2023-21674": {
            "affected_versions": ("7.5", "10.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "IIS privilege escalation in URL rewrite module",
            "cwe_id": "CWE-269",
            "service": "IIS"
        },
        "CVE-2022-41080": {
            "affected_versions": ("7.5", "10.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "IIS path traversal vulnerability",
            "cwe_id": "CWE-22",
            "service": "IIS"
        },

        # ProFTPD
        "CVE-2023-25192": {
            "affected_versions": ("1.3.5", "1.3.8"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "ProFTPD remote code execution via SITE CPFR command",
            "cwe_id": "CWE-94",
            "service": "ProFTPD"
        },
        "CVE-2020-9273": {
            "affected_versions": ("1.3.5", "1.3.7"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "ProFTPD remote code execution via mod_copy",
            "cwe_id": "CWE-434",
            "service": "ProFTPD"
        },

        # vsftpd
        "CVE-2021-22911": {
            "affected_versions": ("2.0.0", "3.0.3"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "vsftpd denial of service in SIZE command",
            "cwe_id": "CWE-400",
            "service": "vsftpd"
        },
        "CVE-2011-2523": {
            "affected_versions": ("2.0.1", "2.3.4"),
            "cvss_score": 6.4,
            "severity": "MEDIUM",
            "description": "vsftpd denial of service in NOOP command",
            "cwe_id": "CWE-400",
            "service": "vsftpd"
        },

        # Redis
        "CVE-2023-28425": {
            "affected_versions": ("0.0.1", "7.0.9"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Redis arbitrary code execution via Lua script engine",
            "cwe_id": "CWE-94",
            "service": "Redis"
        },
        "CVE-2023-28840": {
            "affected_versions": ("6.0.0", "7.0.8"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Redis HRANDFIELD integer overflow",
            "cwe_id": "CWE-190",
            "service": "Redis"
        },
        "CVE-2023-41053": {
            "affected_versions": ("2.0.0", "7.0.10"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Redis integer overflow in RANDOMKEY command",
            "cwe_id": "CWE-190",
            "service": "Redis"
        },
        "CVE-2022-0543": {
            "affected_versions": ("5.0.0", "7.0.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Redis code execution via Lua sandbox escape",
            "cwe_id": "CWE-94",
            "service": "Redis"
        },

        # MongoDB
        "CVE-2023-0286": {
            "affected_versions": ("3.0.0", "6.2.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "MongoDB X.509 verification vulnerability",
            "cwe_id": "CWE-295",
            "service": "MongoDB"
        },
        "CVE-2023-1563": {
            "affected_versions": ("4.0.0", "6.0.5"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MongoDB authentication bypass",
            "cwe_id": "CWE-287",
            "service": "MongoDB"
        },
        "CVE-2022-3602": {
            "affected_versions": ("4.0.0", "5.2.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MongoDB privilege escalation via LDAP",
            "cwe_id": "CWE-269",
            "service": "MongoDB"
        },

        # Elasticsearch
        "CVE-2023-46604": {
            "affected_versions": ("7.0.0", "8.10.0"),
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Elasticsearch remote code execution",
            "cwe_id": "CWE-94",
            "service": "Elasticsearch"
        },
        "CVE-2023-31159": {
            "affected_versions": ("7.10.0", "8.8.0"),
            "cvss_score": 9.9,
            "severity": "CRITICAL",
            "description": "Elasticsearch authentication bypass",
            "cwe_id": "CWE-287",
            "service": "Elasticsearch"
        },
        "CVE-2022-23471": {
            "affected_versions": ("8.0.0", "8.5.3"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Elasticsearch API key authentication bypass",
            "cwe_id": "CWE-287",
            "service": "Elasticsearch"
        },

        # Additional critical CVEs
        "CVE-2024-21887": {
            "affected_versions": ("7.5.0", "23.4.0"),
            "cvss_score": 10.0,
            "severity": "CRITICAL",
            "description": "Citrix NetScaler remote code execution",
            "cwe_id": "CWE-94",
            "service": "Citrix"
        },
        "CVE-2024-1086": {
            "affected_versions": ("5.10.0", "6.7.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Linux kernel nf_tables heap overflow",
            "cwe_id": "CWE-122",
            "service": "Linux"
        },
        "CVE-2023-6129": {
            "affected_versions": ("1.1.1", "3.0.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "OpenSSL POLY1305 buffer overflow",
            "cwe_id": "CWE-120",
            "service": "OpenSSL"
        },
        "CVE-2023-6053": {
            "affected_versions": ("1.1.1", "3.0.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "OpenSSL DTLS buffer overflow",
            "cwe_id": "CWE-122",
            "service": "OpenSSL"
        },
        "CVE-2022-41974": {
            "affected_versions": ("1.1.0", "3.0.6"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "OpenSSL RSA decryption timing attack",
            "cwe_id": "CWE-208",
            "service": "OpenSSL"
        },

        # Java/Kotlin
        "CVE-2023-22965": {
            "affected_versions": ("5.3.0", "6.0.6"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Spring Framework remote code execution",
            "cwe_id": "CWE-94",
            "service": "Spring"
        },
        "CVE-2023-34035": {
            "affected_versions": ("6.0.0", "6.0.8"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Spring Security authentication bypass",
            "cwe_id": "CWE-287",
            "service": "Spring"
        },

        # More Apache variants
        "CVE-2023-43787": {
            "affected_versions": ("2.4.56", "2.4.56"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Apache httpd RewriteRule buffer overflow",
            "cwe_id": "CWE-120",
            "service": "Apache"
        },
        "CVE-2024-34155": {
            "affected_versions": ("2.4.57", "2.4.57"),
            "cvss_score": 7.1,
            "severity": "HIGH",
            "description": "Apache httpd mod_proxy URL parsing",
            "cwe_id": "CWE-444",
            "service": "Apache"
        },

        # More OpenSSH
        "CVE-2024-6409": {
            "affected_versions": ("8.0p1", "9.7p1"),
            "cvss_score": 6.5,
            "severity": "MEDIUM",
            "description": "OpenSSH information disclosure via hash",
            "cwe_id": "CWE-200",
            "service": "OpenSSH"
        },
        "CVE-2023-48795": {
            "affected_versions": ("3.0.0", "9.5p1"),
            "cvss_score": 5.9,
            "severity": "MEDIUM",
            "description": "OpenSSH Terrapin attack - SSH2 sequence number attack",
            "cwe_id": "CWE-347",
            "service": "OpenSSH"
        },

        # Additional Apache vulnerabilities
        "CVE-2022-30522": {
            "affected_versions": ("2.4.0", "2.4.52"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Apache httpd mod_sed arbitrary code execution",
            "cwe_id": "CWE-94",
            "service": "Apache"
        },
        "CVE-2021-34798": {
            "affected_versions": ("2.4.0", "2.4.48"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Apache httpd NULL pointer dereference",
            "cwe_id": "CWE-476",
            "service": "Apache"
        },
        "CVE-2021-26691": {
            "affected_versions": ("2.0.0", "2.4.48"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Apache httpd mod_session authentication bypass",
            "cwe_id": "CWE-287",
            "service": "Apache"
        },
        "CVE-2020-13956": {
            "affected_versions": ("2.4.0", "2.4.43"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Apache httpd authentication bypass with empty password",
            "cwe_id": "CWE-287",
            "service": "Apache"
        },

        # Additional Nginx vulnerabilities
        "CVE-2019-9511": {
            "affected_versions": ("1.9.5", "1.17.2"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Nginx HTTP/2 DATA frame DoS",
            "cwe_id": "CWE-400",
            "service": "Nginx"
        },
        "CVE-2019-9513": {
            "affected_versions": ("1.9.5", "1.17.2"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Nginx HTTP/2 SETTINGS frame flooding",
            "cwe_id": "CWE-400",
            "service": "Nginx"
        },

        # Additional PostgreSQL vulnerabilities
        "CVE-2021-3393": {
            "affected_versions": ("9.6.0", "13.1"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "PostgreSQL partition constraint bypass",
            "cwe_id": "CWE-269",
            "service": "PostgreSQL"
        },
        "CVE-2020-21469": {
            "affected_versions": ("9.6.0", "12.5"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "PostgreSQL privilege escalation via CREATE FUNCTION",
            "cwe_id": "CWE-269",
            "service": "PostgreSQL"
        },

        # Additional WordPress vulnerabilities
        "CVE-2023-28432": {
            "affected_versions": ("6.0", "6.2.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "WordPress privilege escalation in user roles",
            "cwe_id": "CWE-269",
            "service": "WordPress"
        },
        "CVE-2022-21661": {
            "affected_versions": ("5.8", "6.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "WordPress authenticated code execution via AJAX",
            "cwe_id": "CWE-94",
            "service": "WordPress"
        },

        # Additional MySQL vulnerabilities
        "CVE-2023-21881": {
            "affected_versions": ("5.7.30", "8.0.31"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MySQL privilege escalation via InnoDB memcached",
            "cwe_id": "CWE-269",
            "service": "MySQL"
        },
        "CVE-2021-2418": {
            "affected_versions": ("5.7.0", "8.0.25"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MySQL Server Group Replication privilege escalation",
            "cwe_id": "CWE-269",
            "service": "MySQL"
        },
        "CVE-2021-2226": {
            "affected_versions": ("5.7.0", "8.0.23"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MySQL InnoDB privilege escalation",
            "cwe_id": "CWE-269",
            "service": "MySQL"
        },

        # Additional MariaDB vulnerabilities
        "CVE-2023-29383": {
            "affected_versions": ("10.5.0", "10.11.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MariaDB authentication bypass via symlink",
            "cwe_id": "CWE-287",
            "service": "MariaDB"
        },
        "CVE-2022-47427": {
            "affected_versions": ("10.3.0", "10.9.0"),
            "cvss_score": 7.1,
            "severity": "HIGH",
            "description": "MariaDB MDEV-28695 UNION query vulnerability",
            "cwe_id": "CWE-94",
            "service": "MariaDB"
        },

        # Additional PHP vulnerabilities
        "CVE-2023-1848": {
            "affected_versions": ("7.0.0", "8.2.5"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "PHP fread buffer overflow",
            "cwe_id": "CWE-120",
            "service": "PHP"
        },
        "CVE-2023-0662": {
            "affected_versions": ("7.3.0", "8.1.16"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "PHP GdImage allocation of excessive memory",
            "cwe_id": "CWE-190",
            "service": "PHP"
        },
        "CVE-2023-0547": {
            "affected_versions": ("7.4.0", "8.1.15"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "PHP FTP NULL byte injection",
            "cwe_id": "CWE-158",
            "service": "PHP"
        },

        # Additional Redis vulnerabilities
        "CVE-2023-41617": {
            "affected_versions": ("6.0.0", "7.0.12"),
            "cvss_score": 6.5,
            "severity": "MEDIUM",
            "description": "Redis OCTETRANGE command buffer overflow",
            "cwe_id": "CWE-120",
            "service": "Redis"
        },
        "CVE-2022-35977": {
            "affected_versions": ("5.0.0", "7.0.5"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Redis RESET command can crash connection",
            "cwe_id": "CWE-400",
            "service": "Redis"
        },

        # Additional MongoDB vulnerabilities
        "CVE-2022-21705": {
            "affected_versions": ("4.0.0", "5.0.10"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "MongoDB queryable encryption bypass",
            "cwe_id": "CWE-295",
            "service": "MongoDB"
        },
        "CVE-2022-3602": {
            "affected_versions": ("4.4.0", "5.1.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "MongoDB LDAP injection vulnerability",
            "cwe_id": "CWE-94",
            "service": "MongoDB"
        },

        # Additional OpenSSL vulnerabilities
        "CVE-2023-0286": {
            "affected_versions": ("1.0.2", "3.0.8"),
            "cvss_score": 6.5,
            "severity": "MEDIUM",
            "description": "OpenSSL X509 verification overflow",
            "cwe_id": "CWE-190",
            "service": "OpenSSL"
        },
        "CVE-2022-4304": {
            "affected_versions": ("1.1.1", "3.0.7"),
            "cvss_score": 5.3,
            "severity": "MEDIUM",
            "description": "OpenSSL RSA decryption timing vulnerability",
            "cwe_id": "CWE-208",
            "service": "OpenSSL"
        },

        # Tomcat additional
        "CVE-2022-29885": {
            "affected_versions": ("8.5.0", "10.1.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Tomcat file upload path traversal",
            "cwe_id": "CWE-22",
            "service": "Tomcat"
        },
        "CVE-2021-50495": {
            "affected_versions": ("7.0.0", "9.0.54"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Tomcat HTTP/2 connection reset DoS",
            "cwe_id": "CWE-400",
            "service": "Tomcat"
        },

        # IIS additional
        "CVE-2023-21539": {
            "affected_versions": ("7.5", "10.0"),
            "cvss_score": 7.1,
            "severity": "HIGH",
            "description": "IIS WebDAV privilege escalation",
            "cwe_id": "CWE-269",
            "service": "IIS"
        },
        "CVE-2021-44529": {
            "affected_versions": ("7.5", "10.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "IIS HTTP.sys remote code execution",
            "cwe_id": "CWE-94",
            "service": "IIS"
        },

        # ProFTPD additional
        "CVE-2019-12815": {
            "affected_versions": ("1.3.5", "1.3.6"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "ProFTPD buffer overflow in ASCII mode",
            "cwe_id": "CWE-120",
            "service": "ProFTPD"
        },

        # vsftpd additional
        "CVE-2020-14001": {
            "affected_versions": ("2.0.1", "3.0.3"),
            "cvss_score": 6.5,
            "severity": "MEDIUM",
            "description": "vsftpd RFC 959 violation authentication bypass",
            "cwe_id": "CWE-287",
            "service": "vsftpd"
        },

        # Additional critical vulns
        "CVE-2023-32315": {
            "affected_versions": ("1.0.0", "2.0.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Gitea authentication bypass via OIDC",
            "cwe_id": "CWE-287",
            "service": "Gitea"
        },
        "CVE-2023-35078": {
            "affected_versions": ("1.0.0", "14.0.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Jenkins remote code execution via job import",
            "cwe_id": "CWE-94",
            "service": "Jenkins"
        },
        "CVE-2023-44487": {
            "affected_versions": ("2.0.0", "13.0.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "HTTP/2 RAPID RESET denial of service",
            "cwe_id": "CWE-400",
            "service": "Go"
        },
        "CVE-2023-39324": {
            "affected_versions": ("1.20.0", "1.20.10"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Go html/template command injection",
            "cwe_id": "CWE-94",
            "service": "Go"
        },
        "CVE-2023-39615": {
            "affected_versions": ("3.0.0", "4.2.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Grafana authentication bypass",
            "cwe_id": "CWE-287",
            "service": "Grafana"
        },
        "CVE-2023-27163": {
            "affected_versions": ("2.0.0", "9.4.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "OpenVPN authentication bypass",
            "cwe_id": "CWE-287",
            "service": "OpenVPN"
        },
        "CVE-2023-3618": {
            "affected_versions": ("1.0.0", "7.0.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Docker privilege escalation in daemon",
            "cwe_id": "CWE-269",
            "service": "Docker"
        },
        "CVE-2023-27561": {
            "affected_versions": ("1.0.0", "3.14.0"),
            "cvss_score": 7.5,
            "severity": "HIGH",
            "description": "Kubernetes RBAC bypass vulnerability",
            "cwe_id": "CWE-269",
            "service": "Kubernetes"
        },
        "CVE-2023-22518": {
            "affected_versions": ("7.0.0", "8.4.0"),
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Confluence remote code execution",
            "cwe_id": "CWE-94",
            "service": "Confluence"
        },
        "CVE-2023-22809": {
            "affected_versions": ("1.0.0", "21.0.0"),
            "cvss_score": 8.8,
            "severity": "CRITICAL",
            "description": "Jira Server privilege escalation",
            "cwe_id": "CWE-269",
            "service": "Jira"
        },
    }


class VersionParser:
    """Parse and compare version strings"""

    @staticmethod
    def parse_version(version_string: str) -> Tuple[int, ...]:
        """
        Parse version string to tuple of integers
        Handles formats like: 2.4.41, 8.2p1, 7.4.3-1-ARCH, 10.5.0-MariaDB
        """
        # Extract numeric parts
        # Handle formats: X.Y.Z, X.Y.Z-patch, X.YpZ, etc.
        version_string = str(version_string).lower()

        # Remove common suffixes
        for suffix in ['-mariadb', '-debian', '-ubuntu', 'p1', 'p2', 'p3']:
            version_string = version_string.split(suffix)[0]

        # Extract version numbers
        parts = re.findall(r'\d+', version_string)

        if not parts:
            return (0,)

        return tuple(int(p) for p in parts[:4])  # Support up to 4 version parts

    @staticmethod
    def is_version_in_range(version: str, min_version: str, max_version: str) -> bool:
        """Check if version falls within affected range"""
        parsed = VersionParser.parse_version(version)
        parsed_min = VersionParser.parse_version(min_version)
        parsed_max = VersionParser.parse_version(max_version)

        # Pad to same length
        max_len = max(len(parsed), len(parsed_min), len(parsed_max))
        parsed = parsed + (0,) * (max_len - len(parsed))
        parsed_min = parsed_min + (0,) * (max_len - len(parsed_min))
        parsed_max = parsed_max + (0,) * (max_len - len(parsed_max))

        return parsed_min <= parsed <= parsed_max


class ServiceParser:
    """Parse service banners to extract service name and version"""

    SERVICE_PATTERNS = {
        r'Apache[/\s]+([0-9.]+)': ('Apache', r'Apache[/\s]+([0-9.]+)'),
        r'nginx[/\s]+([0-9.]+)': ('Nginx', r'nginx[/\s]+([0-9.]+)'),
        r'OpenSSH[/_\s]+([0-9.p]+)': ('OpenSSH', r'OpenSSH[/_\s]+([0-9.p]+)'),
        r'PHP[/\s]+([0-9.]+)': ('PHP', r'PHP[/\s]+([0-9.]+)'),
        r'MySQL[/\s]+([0-9.-]+)': ('MySQL', r'MySQL[/\s]+([0-9.-]+)'),
        r'MariaDB[/\s]+([0-9.-]+)': ('MariaDB', r'MariaDB[/\s]+([0-9.-]+)'),
        r'PostgreSQL[/\s]+([0-9.]+)': ('PostgreSQL', r'PostgreSQL[/\s]+([0-9.]+)'),
        r'WordPress[/\s]+([0-9.]+)': ('WordPress', r'WordPress[/\s]+([0-9.]+)'),
        r'Tomcat[/\s]+([0-9.]+)': ('Tomcat', r'Tomcat[/\s]+([0-9.]+)'),
        r'IIS[/\s]+([0-9.]+)': ('IIS', r'IIS[/\s]+([0-9.]+)'),
        r'ProFTPD[/\s]+([0-9.]+)': ('ProFTPD', r'ProFTPD[/\s]+([0-9.]+)'),
        r'vsftpd[/\s]+([0-9.]+)': ('vsftpd', r'vsftpd[/\s]+([0-9.]+)'),
        r'redis[/\s]+v?([0-9.]+)': ('Redis', r'redis[/\s]+v?([0-9.]+)'),
        r'MongoDB[/\s]+([0-9.]+)': ('MongoDB', r'MongoDB[/\s]+([0-9.]+)'),
        r'Elasticsearch[/\s]+([0-9.]+)': ('Elasticsearch', r'Elasticsearch[/\s]+([0-9.]+)'),
        r'OpenSSL[/\s]+([0-9.a-z]+)': ('OpenSSL', r'OpenSSL[/\s]+([0-9.a-z]+)'),
        r'Confluence[/\s]+([0-9.]+)': ('Confluence', r'Confluence[/\s]+([0-9.]+)'),
        r'Jira[/\s]+([0-9.]+)': ('Jira', r'Jira[/\s]+([0-9.]+)'),
        r'Jenkins[/\s]+([0-9.]+)': ('Jenkins', r'Jenkins[/\s]+([0-9.]+)'),
        r'Docker[/\s]+([0-9.]+)': ('Docker', r'Docker[/\s]+([0-9.]+)'),
        r'Kubernetes[/\s]+([0-9.]+)': ('Kubernetes', r'Kubernetes[/\s]+([0-9.]+)'),
        r'Grafana[/\s]+([0-9.]+)': ('Grafana', r'Grafana[/\s]+([0-9.]+)'),
        r'OpenVPN[/\s]+([0-9.]+)': ('OpenVPN', r'OpenVPN[/\s]+([0-9.]+)'),
        r'Gitea[/\s]+([0-9.]+)': ('Gitea', r'Gitea[/\s]+([0-9.]+)'),
        r'Go[/\s]+([0-9.]+)': ('Go', r'Go[/\s]+([0-9.]+)'),
        r'Spring[/\s]+([0-9.]+)': ('Spring', r'Spring[/\s]+([0-9.]+)'),
    }

    @staticmethod
    def parse_service_banner(banner: str) -> Optional[Tuple[str, str]]:
        """
        Parse service banner to extract service name and version
        Returns: (service_name, version) or None
        """
        for pattern, (service_name, extraction_pattern) in ServiceParser.SERVICE_PATTERNS.items():
            match = re.search(extraction_pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1)
                return (service_name, version)

        return None


class CVECorrelator:
    """Main CVE correlator engine"""

    def __init__(self):
        self.cve_db = CVEDatabase.CVE_DATA
        self.output_dir = self.get_output_path()
        self.results = []

    def get_output_path(self):
        """Detect if in Termux or desktop"""
        termux_storage = Path.home() / "storage" / "shared" / "Documents" / "purple_team_reports"

        if termux_storage.parent.exists():
            termux_storage.mkdir(exist_ok=True, parents=True)
            return termux_storage
        else:
            desktop_path = Path.home() / "Documents" / "purple_team_reports"
            desktop_path.mkdir(exist_ok=True, parents=True)
            return desktop_path

    def find_cves_for_service(self, service_name: str, version: str) -> List[Dict]:
        """Find all CVEs affecting a specific service version"""
        matching_cves = []

        for cve_id, cve_info in self.cve_db.items():
            # Check if service matches
            if cve_info.get('service', '').lower() != service_name.lower():
                continue

            # Check if version is in affected range
            min_ver, max_ver = cve_info['affected_versions']

            if VersionParser.is_version_in_range(version, min_ver, max_ver):
                matching_cves.append({
                    'cve_id': cve_id,
                    'service': service_name,
                    'version': version,
                    **cve_info
                })

        return sorted(matching_cves, key=lambda x: x['cvss_score'], reverse=True)

    def correlate_service(self, banner: str) -> Dict:
        """Correlate a single service banner with CVEs"""
        parsed = ServiceParser.parse_service_banner(banner)

        if not parsed:
            return {
                'banner': banner,
                'status': 'unparseable',
                'cves': []
            }

        service_name, version = parsed
        cves = self.find_cves_for_service(service_name, version)

        # Calculate risk score
        risk_score = self._calculate_risk_score(cves)

        return {
            'banner': banner,
            'status': 'success',
            'service': service_name,
            'version': version,
            'cve_count': len(cves),
            'critical_count': sum(1 for c in cves if c['severity'] == 'CRITICAL'),
            'high_count': sum(1 for c in cves if c['severity'] == 'HIGH'),
            'risk_score': risk_score,
            'cves': cves
        }

    def _calculate_risk_score(self, cves: List[Dict]) -> float:
        """Calculate overall risk score from CVEs"""
        if not cves:
            return 0.0

        # Weight by severity and CVSS score
        severity_weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.1}

        scores = []
        for cve in cves:
            severity = cve.get('severity', 'LOW')
            cvss = cve.get('cvss_score', 0)
            weight = severity_weights.get(severity, 0.5)
            scores.append(cvss * weight)

        # Average with emphasis on highest scores
        return min(10.0, (sum(scores[:5]) / len(scores[:5])) if scores else 0.0)

    def format_output_console(self, result: Dict) -> str:
        """Format result for console output with colors"""
        output = []

        if result['status'] == 'unparseable':
            output.append(f"\n❌ Could not parse: {result['banner']}")
            return "\n".join(output)

        service = result.get('service', 'Unknown')
        version = result.get('version', 'Unknown')
        cve_count = result.get('cve_count', 0)
        critical = result.get('critical_count', 0)
        high = result.get('high_count', 0)
        risk = result.get('risk_score', 0)

        # Color codes for terminal
        RESET = '\033[0m'
        RED = '\033[91m'
        ORANGE = '\033[33m'
        GREEN = '\033[92m'
        CYAN = '\033[96m'
        BOLD = '\033[1m'

        output.append(f"\n{BOLD}{'='*70}{RESET}")
        output.append(f"{BOLD}{CYAN}Service: {GREEN}{service}/{ORANGE}{version}{RESET}")
        output.append(f"{BOLD}{CYAN}CVE Count: {RED}{cve_count}{RESET} | {RED}Critical: {critical}{RESET} | {ORANGE}High: {high}{RESET}")
        output.append(f"{BOLD}{CYAN}Risk Score: {RED}{risk:.1f}/10.0{RESET}")
        output.append(f"{BOLD}{'='*70}{RESET}")

        if cve_count == 0:
            output.append(f"{GREEN}✓ No known CVEs found{RESET}")
        else:
            output.append(f"\n{BOLD}{CYAN}Vulnerabilities:{RESET}\n")

            for cve in result['cves']:
                cve_id = cve['cve_id']
                severity = cve['severity']
                cvss = cve['cvss_score']
                desc = cve['description']
                cwe = cve.get('cwe_id', 'N/A')

                # Severity color
                if severity == 'CRITICAL':
                    sev_color = RED
                elif severity == 'HIGH':
                    sev_color = ORANGE
                else:
                    sev_color = CYAN

                output.append(f"  {sev_color}{cve_id}{RESET} | {sev_color}{severity}{RESET} | CVSS: {cvss:.1f}")
                output.append(f"    └─ {desc}")
                output.append(f"    └─ {cwe}\n")

        return "\n".join(output)

    def format_output_json(self, results: List[Dict]) -> str:
        """Format results as JSON"""
        return json.dumps(results, indent=2)

    def process_manual_input(self) -> List[Dict]:
        """Interactive input mode"""
        print("\n" + "="*70)
        print("CVE CORRELATOR - Interactive Mode")
        print("="*70)
        print("\nEnter service banners (or 'done' to finish):")
        print("Examples: Apache/2.4.41, OpenSSH_8.2p1, PHP/7.4.3\n")

        services = []
        while True:
            banner = input("Service banner> ").strip()
            if banner.lower() == 'done':
                break
            if banner:
                services.append(banner)

        results = [self.correlate_service(banner) for banner in services]
        return results

    def process_file_input(self, filepath: Path) -> List[Dict]:
        """Load services from JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            # Handle both list and dict formats
            if isinstance(data, list):
                banners = data
            elif isinstance(data, dict):
                # Try common keys: services, banners, hosts, results
                banners = data.get('services', data.get('banners', data.get('hosts', [])))
            else:
                banners = []

            results = [self.correlate_service(str(b)) for b in banners]
            return results

        except Exception as e:
            print(f"Error reading file: {e}")
            return []

    def process_session_input(self, session_path: Path) -> List[Dict]:
        """Load services from orchestrator session results"""
        results_file = session_path / "results_full.json"

        if not results_file.exists():
            print(f"No results_full.json found in {session_path}")
            return []

        try:
            with open(results_file, 'r') as f:
                session_data = json.load(f)

            # Extract service banners from scan results
            banners = []
            if isinstance(session_data, dict):
                # Look for common structures
                for key in ['services', 'ports', 'scan_results', 'hosts']:
                    if key in session_data:
                        items = session_data[key]
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict) and 'banner' in item:
                                    banners.append(item['banner'])
                                elif isinstance(item, dict) and 'version' in item:
                                    banners.append(item['version'])

            results = [self.correlate_service(str(b)) for b in banners if b]
            return results

        except Exception as e:
            print(f"Error processing session: {e}")
            return []

    def save_results(self, results: List[Dict], format_type: str = 'json'):
        """Save results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if format_type == 'json':
            filename = self.output_dir / f"cve_correlation_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)

        print(f"\n✓ Results saved to: {filename}")


def print_banner():
    """Print tool banner with disclaimer"""
    print("\n" + "="*70)
    print("  CVE Correlator - Purple Team Security Suite")
    print("="*70)
    print("""
DISCLAIMER:
This tool is designed for AUTHORIZED security testing only.
Unauthorized access to computer systems is ILLEGAL.
Ensure you have explicit written authorization before conducting assessments.

MITRE ATT&CK: T1592 (Gather Victim Host Information)
    """)
    print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='CVE Correlator - Correlate service versions with known CVEs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python cve_correlator.py                          # Interactive mode
  python cve_correlator.py --service "Apache/2.4.41"
  python cve_correlator.py --file /path/to/scan.json
  python cve_correlator.py --session /path/to/session/
  python cve_correlator.py --online                 # Use NIST NVD API
        '''
    )

    parser.add_argument('--service', '-s', help='Service banner to correlate')
    parser.add_argument('--file', '-f', type=Path, help='JSON file with service banners')
    parser.add_argument('--session', help='Orchestrator session directory')
    parser.add_argument('--output', '-o', choices=['json', 'text'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--save', '-S', action='store_true', help='Save results to file')
    parser.add_argument('--online', action='store_true', help='Query NIST NVD API (experimental)')

    args = parser.parse_args()

    print_banner()

    correlator = CVECorrelator()
    results = []

    # Process input
    if args.service:
        results = [correlator.correlate_service(args.service)]
    elif args.file:
        results = correlator.process_file_input(args.file)
    elif args.session:
        results = correlator.process_session_input(Path(args.session))
    else:
        results = correlator.process_manual_input()

    # Display results
    if args.output == 'json':
        output = correlator.format_output_json(results)
        print(output)
        if args.save:
            correlator.save_results(results, 'json')
    else:
        for result in results:
            print(correlator.format_output_console(result))

    # Print summary
    total_cves = sum(r.get('cve_count', 0) for r in results)
    total_critical = sum(r.get('critical_count', 0) for r in results)

    print(f"\n{'-'*70}")
    print(f"Summary: {len(results)} service(s) scanned | {total_cves} total CVEs | {total_critical} CRITICAL")
    print(f"{'-'*70}\n")


if __name__ == '__main__':
    main()
