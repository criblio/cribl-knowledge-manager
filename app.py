#!/usr/bin/env python3
"""
Cribl Knowledge Manager - Backend Server
Version: 4.0.0
Date: December 2025

This Flask application serves as a backend proxy for the Cribl Cloud API,
enabling users to manage Knowledge items across Cribl Cloud deployments
(Stream, Edge, and Search).

Knowledge Items Supported:
- Lookups
- Event Breaker Rulesets
- Parsers
- Variables
- Regexes
- Grok Patterns
- Schemas
- Parquet Schemas
- Database Connections
- HMAC Functions
- AppScope Configs
- Guard Rules

Architecture:
- Flask web server serving both the API and static HTML frontend
- Direct proxy to Cribl Cloud API with authentication handling
- Server-Sent Events (SSE) for streaming pack scan progress
- Temporary file handling for transfers

Security Features:
- CORS restricted to localhost origins
- Input validation for all user-supplied parameters
- Security headers (X-Frame-Options, CSP, etc.)
- Path traversal protection for filenames

API Endpoints:
- /api/auth/login, /logout, /status - Authentication management
- /api/worker-groups - List worker groups/fleets
- /api/lookups - List and manage lookup files
- /api/packs - List and scan packs for lookups
- /api/transfer - Transfer lookups between groups
- /api/commit, /api/deploy - Version control operations
"""

# =============================================================================
# CONFIGURATION
# =============================================================================

# Set to True to enable verbose debug logging to console
# When False, only essential startup/error messages are printed
DEBUG_MODE = False

# Commit message prefix to identify commits made by Knowledge Manager
# Used to track undeployed commits made by this tool
COMMIT_PREFIX = "[KnowledgeManager]"

# =============================================================================
# IMPORTS - Standard Library
# =============================================================================
import sys
import subprocess
import importlib.util
import socket
import webbrowser
import threading
import time

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================
# Check and install dependencies
def check_install_package(package_name, import_name=None):
    """Check if a package is installed, if not ask to install it"""
    if import_name is None:
        import_name = package_name
    
    if importlib.util.find_spec(import_name) is None:
        print(f"\n[WARN] Required package '{package_name}' is not installed.")
        response = input(f"Would you like to install '{package_name}' now? (y/n): ").strip().lower()
        
        if response == 'y':
            print(f"[INSTALL] Installing {package_name}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
                print(f"[ERROR] {package_name} installed successfully!")
                return True
            except subprocess.CalledProcessError:
                print(f"[ERROR] Failed to install {package_name}. Please install manually:")
                print(f"   pip install {package_name}")
                return False
        else:
            print(f"[ERROR] {package_name} is required to run this application.")
            print(f"   Install with: pip install {package_name}")
            return False
    return True

# Check all required packages
required_packages = [
    ('Flask', 'flask'),
    ('Flask-CORS', 'flask_cors'),
    ('requests', 'requests'),
    ('APScheduler', 'apscheduler')
]

print("[INFO] Checking dependencies...")
all_installed = True
for package_name, import_name in required_packages:
    if not check_install_package(package_name, import_name):
        all_installed = False

if not all_installed:
    print("\n[ERROR] Missing required dependencies. Please install them and try again.")
    sys.exit(1)

print("[OK] All dependencies are installed!\n")

# =============================================================================
# IMPORTS - Third Party (after dependency check)
# =============================================================================
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
import requests
import os
import json
from pathlib import Path
import configparser
import gzip
import tarfile
import io
import tempfile
from datetime import datetime
import re
import logging
import sqlite3
import hashlib
import csv
from io import StringIO
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger
import atexit

# =============================================================================
# LOGGING UTILITIES
# =============================================================================

# Suppress Flask's default request logging (GET /api/... 200 -)
# Only show errors, not every HTTP request
werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.setLevel(logging.ERROR)

# Debug logging helper - only prints if DEBUG_MODE is True
def debug_log(message):
    """Print debug message only if DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        print(message)

# =============================================================================
# FLASK APPLICATION SETUP
# =============================================================================

app = Flask(__name__)

# SECURITY: Configure CORS to only allow localhost origins
# This prevents Cross-Site Request Forgery (CSRF) attacks
CORS(app, 
     origins=[
         'http://localhost:42002',
         'http://127.0.0.1:42002',
         'http://localhost:*',  # Allow any localhost port for development
         'http://127.0.0.1:*'
     ],
     supports_credentials=True,
     allow_headers=['Content-Type', 'Authorization'])

# SECURITY: Input validation functions
def validate_filename(filename):
    """
    Validate filename to prevent path traversal attacks
    Only allows: letters, numbers, underscores, hyphens, periods
    """
    if not filename:
        raise ValueError("Filename cannot be empty")
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename or '\0' in filename:
        raise ValueError("Invalid filename: path traversal detected")
    
    # Only allow safe characters
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise ValueError("Invalid filename: only alphanumeric, underscore, hyphen, and period allowed")
    
    # Check length
    if len(filename) > 255:
        raise ValueError("Filename too long (max 255 characters)")
    
    return filename

def validate_worker_group(group_name):
    """
    Validate worker group name
    Only allows: letters, numbers, underscores, hyphens
    """
    if not group_name:
        raise ValueError("Worker group name cannot be empty")
    
    # Check for path traversal or special characters
    if '..' in group_name or '/' in group_name or '\\' in group_name or '\0' in group_name:
        raise ValueError("Invalid worker group name")
    
    # Allow alphanumeric, underscore, hyphen, and period (for default_search, etc.)
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', group_name):
        raise ValueError("Invalid worker group name: only alphanumeric, underscore, hyphen allowed")
    
    if len(group_name) > 100:
        raise ValueError("Worker group name too long (max 100 characters)")
    
    return group_name

def validate_api_type(api_type):
    """
    Validate API type against allowed values
    """
    allowed_types = ['stream', 'search', 'edge']
    if api_type not in allowed_types:
        raise ValueError(f"Invalid API type: must be one of {allowed_types}")
    return api_type

def sanitize_url_for_logging(url):
    """
    Remove sensitive data from URLs before logging
    """
    if not url:
        return url
    # Remove token parameters
    url = re.sub(r'([?&]token=)[^&]+', r'\1***', url)
    # Remove Authorization headers from logs
    url = re.sub(r'(Bearer\s+)[a-zA-Z0-9\-_\.]+', r'\1***', url)
    return url

# =============================================================================
# GLOBAL APPLICATION STATE
# =============================================================================

# Global config storage - holds authentication state and session data
# This is stored in memory and cleared on server restart
app_config = {
    'authenticated': False,
    'token': None,
    'token_expiry': None,
    'client_id': None,
    'client_secret': None,
    'organization_id': None,
    'base_url': None,  # Store the base URL for API calls
    'is_direct_tenant': False  # Flag for direct tenant URLs
}

# =============================================================================
# MARKETPLACE - Threat Intelligence Feed System
# =============================================================================

# Database path for feed configurations
MARKETPLACE_DB_PATH = Path('marketplace.db')

# Global scheduler instance
scheduler = BackgroundScheduler()

# Available feed providers with their configurations
FEED_PROVIDERS = {
    # ========================
    # FREE - No API Key Required
    # ========================
    'spamhaus_drop': {
        'name': 'Spamhaus DROP',
        'description': 'Dont Route Or Peer - list of netblocks to drop (includes EDROP)',
        'url': 'https://www.spamhaus.org/drop/drop.txt',
        'auth_type': 'none',
        'format': 'spamhaus_txt',
        'category': 'ip_blocklist',
        'default_filename': 'spamhaus_drop.csv',
        'update_frequency': 'daily'
    },
    'feodo_tracker': {
        'name': 'Feodo Tracker',
        'description': 'Botnet C2 IP blocklist from abuse.ch',
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'botnet_c2',
        'default_filename': 'feodo_tracker.csv',
        'update_frequency': 'hourly'
    },
    'urlhaus': {
        'name': 'URLhaus',
        'description': 'Malware URLs from abuse.ch',
        'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'malware_urls',
        'default_filename': 'urlhaus.csv',
        'update_frequency': 'hourly'
    },
    'sslbl_ip': {
        'name': 'SSL Blacklist IPs',
        'description': 'Botnet C2 IPs identified by SSL certificates from abuse.ch',
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'botnet_c2',
        'default_filename': 'sslbl_ips.csv',
        'update_frequency': 'daily'
    },
    'threatfox_iocs': {
        'name': 'ThreatFox IOCs',
        'description': 'Recent malware IOCs from abuse.ch ThreatFox',
        'url': 'https://threatfox.abuse.ch/export/csv/recent/',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'threat_intel',
        'default_filename': 'threatfox_iocs.csv',
        'update_frequency': 'hourly'
    },
    'malware_bazaar_recent': {
        'name': 'Malware Bazaar Recent',
        'description': 'Recent malware hashes from abuse.ch',
        'url': 'https://bazaar.abuse.ch/export/csv/recent/',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'malware_hashes',
        'default_filename': 'malware_bazaar.csv',
        'update_frequency': 'hourly'
    },
    'emerging_threats_compromised': {
        'name': 'Emerging Threats Compromised IPs',
        'description': 'Known compromised hosts from Proofpoint/ET',
        'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'et_compromised.csv',
        'update_frequency': 'daily'
    },
    'emerging_threats_tor': {
        'name': 'Emerging Threats Tor Nodes',
        'description': 'Tor exit nodes from Proofpoint/ET',
        'url': 'https://rules.emergingthreats.net/blockrules/emerging-tor.rules',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'anonymizer',
        'default_filename': 'et_tor.csv',
        'update_frequency': 'daily'
    },
    'tor_exit_nodes': {
        'name': 'Tor Exit Nodes (Official)',
        'description': 'Official Tor Project exit node list',
        'url': 'https://check.torproject.org/torbulkexitlist',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'anonymizer',
        'default_filename': 'tor_exit_nodes.csv',
        'update_frequency': 'hourly'
    },
    'blocklist_de': {
        'name': 'Blocklist.de All Attacks',
        'description': 'IPs that attacked services in the last 48 hours',
        'url': 'https://lists.blocklist.de/lists/all.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'blocklist_de.csv',
        'update_frequency': 'daily'
    },
    'blocklist_de_ssh': {
        'name': 'Blocklist.de SSH Attacks',
        'description': 'IPs attacking SSH services',
        'url': 'https://lists.blocklist.de/lists/ssh.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'blocklist_de_ssh.csv',
        'update_frequency': 'daily'
    },
    'blocklist_de_bruteforce': {
        'name': 'Blocklist.de Brute Force',
        'description': 'IPs conducting brute force attacks',
        'url': 'https://lists.blocklist.de/lists/bruteforcelogin.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'blocklist_de_bruteforce.csv',
        'update_frequency': 'daily'
    },
    'cinsscore': {
        'name': 'CI Army Bad IPs',
        'description': 'Bad reputation IPs from CI Army',
        'url': 'https://cinsscore.com/list/ci-badguys.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'cinsscore.csv',
        'update_frequency': 'daily'
    },
    'dshield_top20': {
        'name': 'DShield Top 20 Attackers',
        'description': 'Top attacking IPs from SANS DShield',
        'url': 'https://www.dshield.org/block.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'dshield_top20.csv',
        'update_frequency': 'daily'
    },
    'firehol_level1': {
        'name': 'FireHOL Level 1',
        'description': 'Basic IP blocklist with minimal false positives',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'firehol_level1.csv',
        'update_frequency': 'daily'
    },
    'openphish': {
        'name': 'OpenPhish Community',
        'description': 'Phishing URLs (community feed)',
        'url': 'https://openphish.com/feed.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'phishing',
        'default_filename': 'openphish.csv',
        'update_frequency': 'hourly'
    },
    'phishtank': {
        'name': 'PhishTank',
        'description': 'Verified phishing URLs (JSON feed)',
        'url': 'http://data.phishtank.com/data/online-valid.json',
        'auth_type': 'none',
        'format': 'json',
        'category': 'phishing',
        'default_filename': 'phishtank.csv',
        'update_frequency': 'hourly'
    },
    'nist_nvd_cve': {
        'name': 'NIST NVD Recent CVEs',
        'description': 'Recent CVE data from NIST National Vulnerability Database',
        'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000',
        'auth_type': 'none',
        'format': 'json',
        'category': 'vulnerabilities',
        'default_filename': 'nist_nvd_cves.csv',
        'update_frequency': 'daily'
    },
    'botvrij_filenames': {
        'name': 'Botvrij Malicious Filenames',
        'description': 'Known malicious filenames from Botvrij.eu',
        'url': 'https://www.botvrij.eu/data/ioclist.filename',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_iocs',
        'default_filename': 'botvrij_filenames.csv',
        'update_frequency': 'daily'
    },
    'botvrij_urls': {
        'name': 'Botvrij Malicious URLs',
        'description': 'Known malicious URLs from Botvrij.eu',
        'url': 'https://www.botvrij.eu/data/ioclist.url',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_urls',
        'default_filename': 'botvrij_urls.csv',
        'update_frequency': 'daily'
    },
    'botvrij_domains': {
        'name': 'Botvrij Malicious Domains',
        'description': 'Known malicious domains from Botvrij.eu',
        'url': 'https://www.botvrij.eu/data/ioclist.domain',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'botvrij_domains.csv',
        'update_frequency': 'daily'
    },
    'digitalside_urls': {
        'name': 'DigitalSide Malicious URLs',
        'description': 'Malicious URLs from DigitalSide Threat Intel',
        'url': 'https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_urls',
        'default_filename': 'digitalside_urls.csv',
        'update_frequency': 'daily'
    },
    'digitalside_ips': {
        'name': 'DigitalSide Malicious IPs',
        'description': 'Malicious IPs from DigitalSide Threat Intel',
        'url': 'https://osint.digitalside.it/Threat-Intel/lists/latestips.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'digitalside_ips.csv',
        'update_frequency': 'daily'
    },
    'digitalside_domains': {
        'name': 'DigitalSide Malicious Domains',
        'description': 'Malicious domains from DigitalSide Threat Intel',
        'url': 'https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'digitalside_domains.csv',
        'update_frequency': 'daily'
    },
    'ipsum_threat': {
        'name': 'IPsum Threat IPs',
        'description': 'Daily aggregated threat IPs (level 3+)',
        'url': 'https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'ipsum_threat.csv',
        'update_frequency': 'daily'
    },
    'binarydefense_banlist': {
        'name': 'Binary Defense IP Banlist',
        'description': 'IPs observed attacking honeypots',
        'url': 'https://www.binarydefense.com/banlist.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'binarydefense.csv',
        'update_frequency': 'daily'
    },
    'stamparm_maltrail': {
        'name': 'Maltrail Blacklist',
        'description': 'Malicious traffic IPs from Maltrail project',
        'url': 'https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/mass_scanner.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'maltrail_scanners.csv',
        'update_frequency': 'daily'
    },
    'mirai_tracker': {
        'name': 'Mirai Tracker',
        'description': 'Active Mirai botnet C2 servers',
        'url': 'https://mirai.security.gives/data/ip_list.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'botnet_c2',
        'default_filename': 'mirai_c2.csv',
        'update_frequency': 'hourly'
    },
    # ========================
    # DOMAIN RANKINGS & ALLOWLISTS
    # ========================
    'majestic_million': {
        'name': 'Majestic Million',
        'description': 'Top 1 million domains ranked by referring subnets',
        'url': 'https://downloads.majestic.com/majestic_million.csv',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'domain_ranking',
        'default_filename': 'majestic_million.csv',
        'update_frequency': 'daily'
    },
    'tranco_list': {
        'name': 'Tranco Top Sites',
        'description': 'Research-grade top sites list combining multiple rankings',
        'url': 'https://tranco-list.eu/top-1m.csv.zip',
        'auth_type': 'none',
        'format': 'zip_csv',
        'category': 'domain_ranking',
        'default_filename': 'tranco_top1m.csv',
        'update_frequency': 'daily'
    },
    'umbrella_top1m': {
        'name': 'Cisco Umbrella Top 1M',
        'description': 'Umbrella Popularity List - top 1 million DNS domains',
        'url': 'http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip',
        'auth_type': 'none',
        'format': 'zip_csv',
        'category': 'domain_ranking',
        'default_filename': 'umbrella_top1m.csv',
        'update_frequency': 'daily'
    },
    # ========================
    # ADDITIONAL IP BLOCKLISTS
    # ========================
    'feodotracker_ips': {
        'name': 'Feodo Tracker Botnet IPs',
        'description': 'Feodo/Dridex/Emotet botnet C2 IPs from abuse.ch',
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'botnet_c2',
        'default_filename': 'feodotracker_ips.csv',
        'update_frequency': 'hourly'
    },
    'sslbl_ips': {
        'name': 'SSL Blacklist IPs',
        'description': 'IPs associated with malicious SSL certificates',
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'sslbl_ips.csv',
        'update_frequency': 'hourly'
    },
    'threatfox_ips': {
        'name': 'ThreatFox IOCs',
        'description': 'Indicators of compromise from ThreatFox/abuse.ch',
        'url': 'https://threatfox.abuse.ch/export/json/recent/',
        'auth_type': 'none',
        'format': 'json',
        'category': 'threat_intel',
        'default_filename': 'threatfox_iocs.csv',
        'update_frequency': 'hourly'
    },
    'urlhaus_ips': {
        'name': 'URLhaus Malware URLs',
        'description': 'Malware distribution URLs from URLhaus/abuse.ch',
        'url': 'https://urlhaus.abuse.ch/downloads/text_online/',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_urls',
        'default_filename': 'urlhaus_urls.csv',
        'update_frequency': 'hourly'
    },
    'spamhaus_drop': {
        'name': 'Spamhaus DROP',
        'description': "Don't Route Or Peer - hijacked/leased spam/malware networks",
        'url': 'https://www.spamhaus.org/drop/drop.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'spamhaus_drop.csv',
        'update_frequency': 'daily'
    },
    'spamhaus_edrop': {
        'name': 'Spamhaus EDROP',
        'description': 'Extended DROP - additional hijacked netblocks',
        'url': 'https://www.spamhaus.org/drop/edrop.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'spamhaus_edrop.csv',
        'update_frequency': 'daily'
    },
    'greensnow_blocklist': {
        'name': 'GreenSnow Blocklist',
        'description': 'IPs detected probing/attacking systems',
        'url': 'https://blocklist.greensnow.co/greensnow.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'greensnow.csv',
        'update_frequency': 'hourly'
    },
    'darklist_de': {
        'name': 'Darklist.de Blocklist',
        'description': 'SSH bruteforce attack IPs',
        'url': 'https://www.darklist.de/raw.php',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'darklist_de.csv',
        'update_frequency': 'hourly'
    },
    'emergingthreats_compromised': {
        'name': 'ET Compromised IPs',
        'description': 'Compromised IPs from Emerging Threats',
        'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'et_compromised.csv',
        'update_frequency': 'daily'
    },
    'talos_ip_blacklist': {
        'name': 'Cisco Talos IP Blacklist',
        'description': 'Known malicious IPs from Talos Intelligence',
        'url': 'https://talosintelligence.com/documents/ip-blacklist',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'talos_blacklist.csv',
        'update_frequency': 'daily'
    },
    'firehol_level2': {
        'name': 'FireHOL Level 2',
        'description': 'Moderate risk IP blocklist with some false positives',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'firehol_level2.csv',
        'update_frequency': 'daily'
    },
    'firehol_level3': {
        'name': 'FireHOL Level 3',
        'description': 'Higher risk IPs - more aggressive blocking',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ip_blocklist',
        'default_filename': 'firehol_level3.csv',
        'update_frequency': 'daily'
    },
    # ========================
    # RANSOMWARE & MALWARE
    # ========================
    'ransomware_tracker': {
        'name': 'Ransomware Tracker URLs',
        'description': 'Known ransomware payment/distribution URLs',
        'url': 'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'ransomware',
        'default_filename': 'ransomware_urls.csv',
        'update_frequency': 'hourly'
    },
    'malwaredomains_immortal': {
        'name': 'DNS-BH Malware Domains',
        'description': 'Domains serving malware from Malware Domain List',
        'url': 'http://mirror1.malwaredomains.com/files/immortal_domains.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'malware_immortal.csv',
        'update_frequency': 'daily'
    },
    'bazaar_recent': {
        'name': 'MalwareBazaar Recent Samples',
        'description': 'Recent malware samples from MalwareBazaar/abuse.ch',
        'url': 'https://bazaar.abuse.ch/export/txt/recent/',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_iocs',
        'default_filename': 'malware_bazaar.csv',
        'update_frequency': 'hourly'
    },
    # ========================
    # DOMAIN BLOCKLISTS
    # ========================
    'malwaredomainlist': {
        'name': 'Malware Domain List',
        'description': 'Domains hosting/distributing malware',
        'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'malware_domain_list.csv',
        'update_frequency': 'daily'
    },
    'urlvoid_domains': {
        'name': 'URLVoid Suspicious Domains',
        'description': 'Suspicious domains from URLVoid analysis',
        'url': 'http://www.urlvoid.com/export-hosts/',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'urlvoid_domains.csv',
        'update_frequency': 'daily'
    },
    'disconnect_malware': {
        'name': 'Disconnect Malware Domains',
        'description': 'Malware domains from Disconnect tracking protection',
        'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'disconnect_malware.csv',
        'update_frequency': 'daily'
    },
    # ========================
    # CRYPTOMINING & AD/TRACKING
    # ========================
    'cryptominer_domains': {
        'name': 'Cryptominer Domains',
        'description': 'Domains hosting browser cryptominers',
        'url': 'https://raw.githubusercontent.com/nickspaargaren/pihole-google/master/categories/cryptomining.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'cryptomining',
        'default_filename': 'cryptominer_domains.csv',
        'update_frequency': 'weekly'
    },
    'adaway_hosts': {
        'name': 'AdAway Hosts',
        'description': 'Ad server domains for blocking',
        'url': 'https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'advertising',
        'default_filename': 'adaway_hosts.csv',
        'update_frequency': 'weekly'
    },
    'easylist_privacy': {
        'name': 'EasyPrivacy Tracking Domains',
        'description': 'Privacy/tracking domains from EasyList',
        'url': 'https://raw.githubusercontent.com/nickspaargaren/pihole-google/master/categories/tracking.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'tracking',
        'default_filename': 'easyprivacy_tracking.csv',
        'update_frequency': 'weekly'
    },
    # ========================
    # VPN/PROXY/ANONYMIZERS
    # ========================
    'dan_tor_nodes': {
        'name': 'Dan.me.uk Tor Nodes',
        'description': 'All Tor network nodes (not just exits)',
        'url': 'https://www.dan.me.uk/torlist/?full',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'anonymizer',
        'default_filename': 'dan_tor_nodes.csv',
        'update_frequency': 'hourly'
    },
    'proxy_list': {
        'name': 'Free Proxy List',
        'description': 'Known public proxy server IPs',
        'url': 'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'proxy',
        'default_filename': 'proxy_list.csv',
        'update_frequency': 'hourly'
    },
    # ========================
    # DATACENTER/CLOUD IPS
    # ========================
    'aws_ip_ranges': {
        'name': 'AWS IP Ranges',
        'description': 'Official Amazon Web Services IP ranges',
        'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
        'auth_type': 'none',
        'format': 'json',
        'category': 'cloud_provider',
        'default_filename': 'aws_ip_ranges.csv',
        'update_frequency': 'daily'
    },
    'azure_ip_ranges': {
        'name': 'Azure IP Ranges',
        'description': 'Microsoft Azure datacenter IP ranges',
        'url': 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20231127.json',
        'auth_type': 'none',
        'format': 'json',
        'category': 'cloud_provider',
        'default_filename': 'azure_ip_ranges.csv',
        'update_frequency': 'weekly'
    },
    'google_cloud_ips': {
        'name': 'Google Cloud IP Ranges',
        'description': 'Google Cloud Platform IP ranges',
        'url': 'https://www.gstatic.com/ipranges/cloud.json',
        'auth_type': 'none',
        'format': 'json',
        'category': 'cloud_provider',
        'default_filename': 'gcp_ip_ranges.csv',
        'update_frequency': 'daily'
    },
    'cloudflare_ips': {
        'name': 'Cloudflare IP Ranges',
        'description': 'Cloudflare CDN/proxy IP ranges',
        'url': 'https://www.cloudflare.com/ips-v4',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'cdn',
        'default_filename': 'cloudflare_ips.csv',
        'update_frequency': 'weekly'
    },
    'fastly_ips': {
        'name': 'Fastly IP Ranges',
        'description': 'Fastly CDN IP ranges',
        'url': 'https://api.fastly.com/public-ip-list',
        'auth_type': 'none',
        'format': 'json',
        'category': 'cdn',
        'default_filename': 'fastly_ips.csv',
        'update_frequency': 'weekly'
    },
    # ========================
    # COUNTRY/ASN DATA
    # ========================
    'asn_database': {
        'name': 'IPtoASN Database',
        'description': 'IP to ASN mapping database',
        'url': 'https://iptoasn.com/data/ip2asn-v4.tsv.gz',
        'auth_type': 'none',
        'format': 'gzip_tsv',
        'category': 'network_intel',
        'default_filename': 'ip2asn.csv',
        'update_frequency': 'weekly'
    },
    # ========================
    # ADDITIONAL THREAT FEEDS
    # ========================
    'c2_intel_feed': {
        'name': 'C2 IntelFeed',
        'description': 'Command and Control server indicators',
        'url': 'https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s.csv',
        'auth_type': 'none',
        'format': 'csv',
        'category': 'botnet_c2',
        'default_filename': 'c2_intel.csv',
        'update_frequency': 'daily'
    },
    'vxvault_urls': {
        'name': 'VXVault URLs',
        'description': 'Malware distribution URLs from VXVault',
        'url': 'http://vxvault.net/URL_List.php',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_urls',
        'default_filename': 'vxvault_urls.csv',
        'update_frequency': 'daily'
    },
    'cybercrime_tracker': {
        'name': 'Cybercrime Tracker',
        'description': 'Active C2 panels (Zeus, SpyEye, etc)',
        'url': 'https://cybercrime-tracker.net/all.php',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'botnet_c2',
        'default_filename': 'cybercrime_c2.csv',
        'update_frequency': 'daily'
    },
    'threatcrowd_domains': {
        'name': 'ThreatCrowd Domains',
        'description': 'Malicious domain intelligence',
        'url': 'https://www.threatcrowd.org/feeds/domains.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'malware_domains',
        'default_filename': 'threatcrowd_domains.csv',
        'update_frequency': 'daily'
    },
    'iana_tlds': {
        'name': 'IANA TLD List',
        'description': 'Official list of all Top-Level Domains',
        'url': 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'reference',
        'default_filename': 'iana_tlds.csv',
        'update_frequency': 'weekly'
    },
    'public_suffix_list': {
        'name': 'Public Suffix List',
        'description': 'Domain suffixes where cookies should not be set',
        'url': 'https://publicsuffix.org/list/public_suffix_list.dat',
        'auth_type': 'none',
        'format': 'txt_lines',
        'category': 'reference',
        'default_filename': 'public_suffix.csv',
        'update_frequency': 'weekly'
    },
    # ========================
    # REQUIRES API KEY
    # ========================
    'alienvault_otx': {
        'name': 'AlienVault OTX',
        'description': 'Open Threat Exchange indicators (requires free API key)',
        'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        'auth_type': 'api_key_header',
        'auth_header': 'X-OTX-API-KEY',
        'format': 'json',
        'category': 'threat_intel',
        'default_filename': 'alienvault_otx.csv',
        'update_frequency': 'daily'
    },
    'abuseipdb': {
        'name': 'AbuseIPDB Blacklist',
        'description': 'IP addresses reported for abuse (requires API key)',
        'url': 'https://api.abuseipdb.com/api/v2/blacklist',
        'auth_type': 'api_key_header',
        'auth_header': 'Key',
        'format': 'json',
        'category': 'ip_blocklist',
        'default_filename': 'abuseipdb.csv',
        'update_frequency': 'daily',
        'extra_params': {'confidenceMinimum': '90'}
    },
    'maxmind_geolite2_country': {
        'name': 'MaxMind GeoLite2 Country',
        'description': 'GeoIP country database (requires free license key)',
        'url': 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download',
        'auth_type': 'basic_auth',
        'format': 'zip_csv',
        'category': 'geolocation',
        'default_filename': 'geolite2_country.csv',
        'update_frequency': 'weekly'
    },
    'maxmind_geolite2_city': {
        'name': 'MaxMind GeoLite2 City',
        'description': 'GeoIP city database (requires free license key)',
        'url': 'https://download.maxmind.com/geoip/databases/GeoLite2-City-CSV/download',
        'auth_type': 'basic_auth',
        'format': 'zip_csv',
        'category': 'geolocation',
        'default_filename': 'geolite2_city.csv',
        'update_frequency': 'weekly'
    },
    'maxmind_geolite2_asn': {
        'name': 'MaxMind GeoLite2 ASN',
        'description': 'GeoIP ASN database (requires free license key)',
        'url': 'https://download.maxmind.com/geoip/databases/GeoLite2-ASN-CSV/download',
        'auth_type': 'basic_auth',
        'format': 'zip_csv',
        'category': 'geolocation',
        'default_filename': 'geolite2_asn.csv',
        'update_frequency': 'weekly'
    },
    'greynoise_community': {
        'name': 'GreyNoise Community',
        'description': 'Internet scanner and noise IPs (requires API key)',
        'url': 'https://api.greynoise.io/v3/community/{ip}',
        'auth_type': 'api_key_header',
        'auth_header': 'key',
        'format': 'json',
        'category': 'ip_context',
        'default_filename': 'greynoise.csv',
        'update_frequency': 'daily',
        'note': 'Query individual IPs only'
    },
    'ipinfo_country': {
        'name': 'IPinfo Country ASN',
        'description': 'Free IP to country/ASN database from IPinfo.io (requires free account)',
        'url': 'https://ipinfo.io/data/free/country_asn.csv.gz',
        'auth_type': 'api_key_header',
        'auth_header': 'Authorization',
        'auth_prefix': 'Bearer ',
        'format': 'gzip_csv',
        'category': 'geolocation',
        'default_filename': 'ipinfo_country.csv',
        'update_frequency': 'daily',
        'signup_url': 'https://ipinfo.io/signup'
    },
    'ipinfodb_city': {
        'name': 'IP2Location LITE City',
        'description': 'Free IP geolocation database - no API key required',
        'url': 'https://download.ip2location.com/lite/IP2LOCATION-LITE-DB11.CSV.ZIP',
        'auth_type': 'none',
        'format': 'zip_csv',
        'category': 'geolocation',
        'default_filename': 'ip2location_city.csv',
        'update_frequency': 'monthly',
        'note': 'Free IP2Location LITE database - no registration required'
    },
    'nist_nvd_nginx': {
        'name': 'NIST NVD - Nginx CVEs',
        'description': 'NIST National Vulnerability Database CVEs for Nginx',
        'url': 'https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*',
        'auth_type': 'none',
        'format': 'nvd_json',
        'category': 'vulnerability',
        'default_filename': 'nvd_nginx_cves.csv',
        'update_frequency': 'daily'
    }
}

# Default feeds to pre-configure (disabled, not scheduled)
# schedule_cron format: "minute hour day_of_month month day_of_week"
# Example: "0 6 * * *" = daily at 6:00 AM, "0 6 * * 1,3,5" = Mon/Wed/Fri at 6:00 AM
# This list is auto-generated from FEED_PROVIDERS for all free (no auth required) feeds
# Only verified working free feeds (no auth required)
# Non-working feeds have been removed but remain in FEED_PROVIDERS for manual addition via "Add Feed" button
DEFAULT_FEEDS = [
    # === IP Blocklists (Verified Working) ===
    {'provider_id': 'spamhaus_drop', 'name': 'Spamhaus DROP', 'lookup_filename': 'spamhaus_drop.csv', 'schedule_cron': '0 2 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'blocklist_de', 'name': 'Blocklist.de All Attacks', 'lookup_filename': 'blocklist_de.csv', 'schedule_cron': '0 3 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'blocklist_de_ssh', 'name': 'Blocklist.de SSH Attacks', 'lookup_filename': 'blocklist_de_ssh.csv', 'schedule_cron': '0 3 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'blocklist_de_bruteforce', 'name': 'Blocklist.de Brute Force', 'lookup_filename': 'blocklist_de_bruteforce.csv', 'schedule_cron': '0 3 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'firehol_level1', 'name': 'FireHOL Level 1', 'lookup_filename': 'firehol_level1.csv', 'schedule_cron': '0 4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'firehol_level2', 'name': 'FireHOL Level 2', 'lookup_filename': 'firehol_level2.csv', 'schedule_cron': '0 4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'firehol_level3', 'name': 'FireHOL Level 3', 'lookup_filename': 'firehol_level3.csv', 'schedule_cron': '0 4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'emerging_threats_compromised', 'name': 'ET Compromised IPs', 'lookup_filename': 'et_compromised.csv', 'schedule_cron': '0 5 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'emergingthreats_compromised', 'name': 'Emerging Threats Compromised', 'lookup_filename': 'et_compromised2.csv', 'schedule_cron': '0 5 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'cinsscore', 'name': 'CI Army Bad IPs', 'lookup_filename': 'cinsscore.csv', 'schedule_cron': '0 6 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'dshield_top20', 'name': 'DShield Top 20 Attackers', 'lookup_filename': 'dshield_top20.csv', 'schedule_cron': '0 6 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'binarydefense_banlist', 'name': 'Binary Defense IP Banlist', 'lookup_filename': 'binarydefense.csv', 'schedule_cron': '0 7 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'ipsum_threat', 'name': 'IPsum Threat IPs', 'lookup_filename': 'ipsum_threat.csv', 'schedule_cron': '0 7 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'stamparm_maltrail', 'name': 'Maltrail Blacklist', 'lookup_filename': 'maltrail_scanners.csv', 'schedule_cron': '0 8 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'greensnow_blocklist', 'name': 'GreenSnow Blocklist', 'lookup_filename': 'greensnow.csv', 'schedule_cron': '0 8 * * *', 'enabled': False, 'auto_deploy': False},
    # === Botnet C2 (Verified Working) ===
    {'provider_id': 'feodo_tracker', 'name': 'Feodo Tracker', 'lookup_filename': 'feodo_tracker.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'feodotracker_ips', 'name': 'Feodo Tracker Botnet IPs', 'lookup_filename': 'feodotracker_ips.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'c2_intel_feed', 'name': 'C2 IntelFeed', 'lookup_filename': 'c2_intel.csv', 'schedule_cron': '0 12 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'cybercrime_tracker', 'name': 'Cybercrime Tracker', 'lookup_filename': 'cybercrime_c2.csv', 'schedule_cron': '0 12 * * *', 'enabled': False, 'auto_deploy': False},
    # === Threat Intel (Verified Working) ===
    {'provider_id': 'threatfox_iocs', 'name': 'ThreatFox IOCs', 'lookup_filename': 'threatfox_iocs.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    # === Malware URLs (Verified Working) ===
    {'provider_id': 'urlhaus', 'name': 'URLhaus Malware URLs', 'lookup_filename': 'urlhaus.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'urlhaus_ips', 'name': 'URLhaus Online URLs', 'lookup_filename': 'urlhaus_urls.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'vxvault_urls', 'name': 'VXVault URLs', 'lookup_filename': 'vxvault_urls.csv', 'schedule_cron': '0 13 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'botvrij_urls', 'name': 'Botvrij Malicious URLs', 'lookup_filename': 'botvrij_urls.csv', 'schedule_cron': '0 14 * * *', 'enabled': False, 'auto_deploy': False},
    # === Phishing (Verified Working) ===
    {'provider_id': 'openphish', 'name': 'OpenPhish Community', 'lookup_filename': 'openphish.csv', 'schedule_cron': '0 */6 * * *', 'enabled': False, 'auto_deploy': False},
    # === Malware Hashes/IOCs (Verified Working) ===
    {'provider_id': 'malware_bazaar_recent', 'name': 'Malware Bazaar Recent', 'lookup_filename': 'malware_bazaar.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'botvrij_filenames', 'name': 'Botvrij Malicious Filenames', 'lookup_filename': 'botvrij_filenames.csv', 'schedule_cron': '0 15 * * *', 'enabled': False, 'auto_deploy': False},
    # === Malware Domains (Verified Working) ===
    {'provider_id': 'botvrij_domains', 'name': 'Botvrij Malicious Domains', 'lookup_filename': 'botvrij_domains.csv', 'schedule_cron': '0 15 * * *', 'enabled': False, 'auto_deploy': False},
    # === Anonymizers/Tor/Proxy (Verified Working) ===
    {'provider_id': 'tor_exit_nodes', 'name': 'Tor Exit Nodes (Official)', 'lookup_filename': 'tor_exit_nodes.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'emerging_threats_tor', 'name': 'ET Tor Nodes', 'lookup_filename': 'et_tor.csv', 'schedule_cron': '0 18 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'proxy_list', 'name': 'Free Proxy List', 'lookup_filename': 'proxy_list.csv', 'schedule_cron': '0 */4 * * *', 'enabled': False, 'auto_deploy': False},
    # === Domain Rankings/Allowlists (Verified Working) ===
    {'provider_id': 'majestic_million', 'name': 'Majestic Million', 'lookup_filename': 'majestic_million.csv', 'schedule_cron': '0 1 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'tranco_list', 'name': 'Tranco Top Sites', 'lookup_filename': 'tranco_top1m.csv', 'schedule_cron': '0 1 * * *', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'umbrella_top1m', 'name': 'Cisco Umbrella Top 1M', 'lookup_filename': 'umbrella_top1m.csv', 'schedule_cron': '0 1 * * *', 'enabled': False, 'auto_deploy': False},
    # === Cloud Provider IPs (Verified Working) ===
    {'provider_id': 'cloudflare_ips', 'name': 'Cloudflare IP Ranges', 'lookup_filename': 'cloudflare_ips.csv', 'schedule_cron': '0 3 * * 0', 'enabled': False, 'auto_deploy': False},
    # === Reference Data (Verified Working) ===
    {'provider_id': 'iana_tlds', 'name': 'IANA TLD List', 'lookup_filename': 'iana_tlds.csv', 'schedule_cron': '0 5 * * 0', 'enabled': False, 'auto_deploy': False},
    {'provider_id': 'public_suffix_list', 'name': 'Public Suffix List', 'lookup_filename': 'public_suffix.csv', 'schedule_cron': '0 5 * * 0', 'enabled': False, 'auto_deploy': False},
    # === Ad/Tracking (Verified Working) ===
    {'provider_id': 'adaway_hosts', 'name': 'AdAway Hosts', 'lookup_filename': 'adaway_hosts.csv', 'schedule_cron': '0 7 * * 0', 'enabled': False, 'auto_deploy': False},
    # NOTE: Non-working feeds and API-key-required feeds remain in FEED_PROVIDERS and can be added via "Add Feed" button
]

def init_marketplace_db():
    """Initialize the SQLite database for Marketplace feed configurations."""
    conn = sqlite3.connect(MARKETPLACE_DB_PATH)
    cursor = conn.cursor()

    # Create feeds table with schedule_cron (full cron expression: minute hour day_of_month month day_of_week)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS feeds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_id TEXT NOT NULL,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 0,
            lookup_filename TEXT NOT NULL,
            schedule_cron TEXT DEFAULT '0 6 * * *',
            target_api_type TEXT DEFAULT 'stream',
            target_worker_groups TEXT DEFAULT 'default',
            auto_deploy INTEGER DEFAULT 0,
            auth_config TEXT,
            last_sync TEXT,
            last_sync_status TEXT,
            last_sync_message TEXT,
            content_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create sync history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sync_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            feed_id INTEGER NOT NULL,
            sync_time TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL,
            message TEXT,
            records_count INTEGER,
            content_hash TEXT,
            preview_data TEXT,
            FOREIGN KEY (feed_id) REFERENCES feeds(id)
        )
    ''')

    # Add preview_data column to sync_history if it doesn't exist
    cursor.execute("PRAGMA table_info(sync_history)")
    sync_columns = [col[1] for col in cursor.fetchall()]
    if 'preview_data' not in sync_columns:
        cursor.execute("ALTER TABLE sync_history ADD COLUMN preview_data TEXT")

    # Check if we need to migrate old schema (schedule_time -> schedule_cron)
    cursor.execute("PRAGMA table_info(feeds)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'schedule_time' in columns and 'schedule_cron' not in columns:
        # Add new column and migrate data
        cursor.execute("ALTER TABLE feeds ADD COLUMN schedule_cron TEXT DEFAULT '0 6 * * *'")
        # Convert old HH:MM time format to cron (daily at that time)
        cursor.execute("SELECT id, schedule_time FROM feeds WHERE schedule_time IS NOT NULL")
        for row in cursor.fetchall():
            feed_id, schedule_time = row
            if schedule_time and ':' in schedule_time:
                parts = schedule_time.split(':')
                hour = int(parts[0])
                minute = int(parts[1]) if len(parts) > 1 else 0
                cron_expr = f"{minute} {hour} * * *"
                cursor.execute("UPDATE feeds SET schedule_cron = ? WHERE id = ?", (cron_expr, feed_id))
        debug_log("[MARKETPLACE] Migrated schedule schema from time to cron-based")

    # Insert default feeds if table is empty
    cursor.execute("SELECT COUNT(*) FROM feeds")
    count = cursor.fetchone()[0]
    if count == 0:
        debug_log("[MARKETPLACE] Inserting default feed configurations...")
        for feed in DEFAULT_FEEDS:
            cursor.execute('''
                INSERT INTO feeds (provider_id, name, lookup_filename, schedule_cron, enabled, auto_deploy, target_worker_groups)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                feed['provider_id'],
                feed['name'],
                feed['lookup_filename'],
                feed['schedule_cron'],
                1 if feed.get('enabled', False) else 0,
                1 if feed.get('auto_deploy', False) else 0,
                ''  # Empty - user must configure target worker groups
            ))
        debug_log(f"[MARKETPLACE] Inserted {len(DEFAULT_FEEDS)} default feeds")

    conn.commit()
    conn.close()
    debug_log("[MARKETPLACE] Database initialized")

def get_db_connection():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(MARKETPLACE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def feed_row_to_dict(row):
    """Convert a sqlite3.Row to a dictionary."""
    if row is None:
        return None
    return dict(row)

# =============================================================================
# MARKETPLACE - Feed Download and Parsing Functions
# =============================================================================

def download_feed_content(provider_id, auth_config=None):
    """
    Download content from a feed provider.

    Args:
        provider_id: The provider ID from FEED_PROVIDERS
        auth_config: Optional dict with authentication credentials

    Returns:
        tuple: (content_bytes, error_message)
    """
    provider = FEED_PROVIDERS.get(provider_id)
    if not provider:
        return None, f"Unknown provider: {provider_id}"

    url = provider['url']
    headers = {}
    auth = None
    params = provider.get('extra_params', {})

    # Handle authentication
    auth_type = provider.get('auth_type', 'none')
    if auth_type == 'api_key_header' and auth_config:
        header_name = provider.get('auth_header', 'Authorization')
        api_key = auth_config.get('api_key', '')
        if api_key:
            headers[header_name] = api_key
    elif auth_type == 'basic_auth' and auth_config:
        username = auth_config.get('account_id', auth_config.get('username', ''))
        password = auth_config.get('license_key', auth_config.get('password', ''))
        if username and password:
            auth = (username, password)

    # Add Accept header for JSON APIs
    if provider.get('format') == 'json':
        headers['Accept'] = 'application/json'

    try:
        response = requests.get(url, headers=headers, auth=auth, params=params, timeout=60)
        response.raise_for_status()
        return response.content, None
    except requests.exceptions.RequestException as e:
        return None, str(e)

def parse_feed_to_csv(provider_id, content):
    """
    Parse feed content and convert to CSV format suitable for Cribl lookups.

    Args:
        provider_id: The provider ID from FEED_PROVIDERS
        content: Raw content bytes from download

    Returns:
        tuple: (csv_content_string, record_count, error_message)
    """
    provider = FEED_PROVIDERS.get(provider_id)
    if not provider:
        return None, 0, f"Unknown provider: {provider_id}"

    format_type = provider.get('format', 'csv')

    try:
        if format_type == 'json':
            return parse_json_feed(provider_id, content)
        elif format_type == 'csv':
            return parse_csv_feed(provider_id, content)
        elif format_type == 'txt_lines':
            return parse_txt_lines_feed(provider_id, content)
        elif format_type == 'zip_csv':
            return parse_zip_csv_feed(provider_id, content)
        elif format_type == 'spamhaus_txt':
            return parse_spamhaus_txt(provider_id, content)
        elif format_type == 'nvd_json':
            return parse_nvd_json(provider_id, content)
        else:
            return None, 0, f"Unsupported format: {format_type}"
    except Exception as e:
        return None, 0, f"Parse error: {str(e)}"

def parse_json_feed(provider_id, content):
    """Parse JSON format feeds."""
    data = json.loads(content.decode('utf-8'))
    output = StringIO()
    writer = None
    count = 0

    if provider_id == 'spamhaus_drop' or provider_id == 'spamhaus_edrop':
        # Spamhaus DROP JSON format
        writer = csv.DictWriter(output, fieldnames=['cidr', 'sbl_id', 'rir', 'country'])
        writer.writeheader()
        for entry in data:
            writer.writerow({
                'cidr': entry.get('cidr', ''),
                'sbl_id': entry.get('sbl', ''),
                'rir': entry.get('rir', ''),
                'country': entry.get('country', '')
            })
            count += 1

    elif provider_id == 'abuseipdb':
        # AbuseIPDB blacklist format
        writer = csv.DictWriter(output, fieldnames=['ip', 'country_code', 'abuse_confidence_score', 'last_reported_at'])
        writer.writeheader()
        for entry in data.get('data', []):
            writer.writerow({
                'ip': entry.get('ipAddress', ''),
                'country_code': entry.get('countryCode', ''),
                'abuse_confidence_score': entry.get('abuseConfidenceScore', ''),
                'last_reported_at': entry.get('lastReportedAt', '')
            })
            count += 1

    elif provider_id == 'alienvault_otx':
        # AlienVault OTX pulses - extract indicators
        writer = csv.DictWriter(output, fieldnames=['indicator', 'type', 'pulse_name', 'created'])
        writer.writeheader()
        for pulse in data.get('results', []):
            pulse_name = pulse.get('name', '')
            for indicator in pulse.get('indicators', []):
                writer.writerow({
                    'indicator': indicator.get('indicator', ''),
                    'type': indicator.get('type', ''),
                    'pulse_name': pulse_name,
                    'created': indicator.get('created', '')
                })
                count += 1

    else:
        # Generic JSON array handling
        if isinstance(data, list):
            if data and isinstance(data[0], dict):
                writer = csv.DictWriter(output, fieldnames=data[0].keys())
                writer.writeheader()
                for row in data:
                    writer.writerow(row)
                    count += 1

    return output.getvalue(), count, None

def parse_spamhaus_txt(provider_id, content):
    """Parse Spamhaus DROP/EDROP text format (CIDR ; SBL_ID)."""
    text = content.decode('utf-8', errors='replace')
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=['cidr', 'sbl_id', 'source'])
    writer.writeheader()
    count = 0

    provider = FEED_PROVIDERS.get(provider_id, {})
    source_name = provider.get('name', provider_id)

    for line in text.split('\n'):
        line = line.strip()
        # Skip empty lines and comments (start with ;)
        if line and not line.startswith(';'):
            # Format: CIDR ; SBL_ID
            parts = line.split(';', 1)
            cidr = parts[0].strip()
            sbl_id = parts[1].strip() if len(parts) > 1 else ''
            if cidr:
                writer.writerow({
                    'cidr': cidr,
                    'sbl_id': sbl_id,
                    'source': source_name
                })
                count += 1

    return output.getvalue(), count, None

def parse_nvd_json(provider_id, content):
    """Parse NIST NVD JSON format (CVE vulnerability data)."""
    data = json.loads(content.decode('utf-8'))
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'cve_id', 'published', 'last_modified', 'severity', 'cvss_score',
        'cvss_version', 'vuln_status', 'description', 'cpe_match'
    ])
    writer.writeheader()
    count = 0

    # NVD API 2.0 returns vulnerabilities array
    vulnerabilities = data.get('vulnerabilities', [])

    for vuln_wrapper in vulnerabilities:
        cve = vuln_wrapper.get('cve', {})
        cve_id = cve.get('id', '')
        published = cve.get('published', '')
        last_modified = cve.get('lastModified', '')
        vuln_status = cve.get('vulnStatus', '')

        # Get description (English)
        description = ''
        for desc in cve.get('descriptions', []):
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # Get CVSS score - try v3.1 first, then v3.0, then v2
        severity = ''
        cvss_score = ''
        cvss_version = ''

        metrics = cve.get('metrics', {})
        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0].get('cvssData', {})
            cvss_score = str(cvss_data.get('baseScore', ''))
            severity = cvss_data.get('baseSeverity', '')
            cvss_version = '3.1'
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0].get('cvssData', {})
            cvss_score = str(cvss_data.get('baseScore', ''))
            severity = cvss_data.get('baseSeverity', '')
            cvss_version = '3.0'
        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
            metric = metrics['cvssMetricV2'][0]
            cvss_data = metric.get('cvssData', {})
            cvss_score = str(cvss_data.get('baseScore', ''))
            severity = metric.get('baseSeverity', '')
            cvss_version = '2.0'

        # Get CPE match string (affected products)
        cpe_matches = []
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    if match.get('vulnerable'):
                        cpe_matches.append(match.get('criteria', ''))
        cpe_match = '; '.join(cpe_matches[:5])  # Limit to first 5

        writer.writerow({
            'cve_id': cve_id,
            'published': published,
            'last_modified': last_modified,
            'severity': severity,
            'cvss_score': cvss_score,
            'cvss_version': cvss_version,
            'vuln_status': vuln_status,
            'description': description[:500] if description else '',  # Truncate long descriptions
            'cpe_match': cpe_match
        })
        count += 1

    return output.getvalue(), count, None

def parse_csv_feed(provider_id, content):
    """Parse CSV format feeds."""
    text = content.decode('utf-8', errors='replace')
    output = StringIO()
    count = 0

    if provider_id == 'feodo_tracker':
        # Feodo Tracker CSV has comment lines starting with #
        # Format: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        writer = csv.DictWriter(output, fieldnames=['first_seen', 'dst_ip', 'dst_port', 'c2_status', 'last_online', 'malware'])
        writer.writeheader()
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('"first_seen'):
                # Parse CSV line properly (handles quoted fields)
                reader = csv.reader(StringIO(line))
                for parts in reader:
                    if len(parts) >= 6:
                        writer.writerow({
                            'first_seen': parts[0],
                            'dst_ip': parts[1],
                            'dst_port': parts[2],
                            'c2_status': parts[3],
                            'last_online': parts[4],
                            'malware': parts[5]
                        })
                        count += 1

    elif provider_id == 'urlhaus':
        # URLhaus CSV has specific format with # comments
        writer = csv.DictWriter(output, fieldnames=['id', 'dateadded', 'url', 'url_status', 'threat', 'tags', 'urlhaus_link', 'reporter'])
        writer.writeheader()
        for line in text.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Parse CSV line properly
                reader = csv.reader(StringIO(line))
                for parts in reader:
                    if len(parts) >= 8:
                        writer.writerow({
                            'id': parts[0],
                            'dateadded': parts[1],
                            'url': parts[2],
                            'url_status': parts[3],
                            'threat': parts[4],
                            'tags': parts[5],
                            'urlhaus_link': parts[6],
                            'reporter': parts[7]
                        })
                        count += 1

    else:
        # Generic CSV passthrough with header
        reader = csv.reader(StringIO(text))
        headers = next(reader, None)
        if headers:
            writer = csv.writer(output)
            writer.writerow(headers)
            for row in reader:
                writer.writerow(row)
                count += 1

    return output.getvalue(), count, None

def parse_txt_lines_feed(provider_id, content):
    """Parse text file with one entry per line (IPs, domains, etc.)."""
    text = content.decode('utf-8', errors='replace')
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=['indicator', 'source', 'added_date'])
    writer.writeheader()
    count = 0

    provider = FEED_PROVIDERS.get(provider_id, {})
    source_name = provider.get('name', provider_id)
    added_date = datetime.utcnow().strftime('%Y-%m-%d')

    for line in text.split('\n'):
        line = line.strip()
        # Skip empty lines and comments
        if line and not line.startswith('#') and not line.startswith(';'):
            writer.writerow({
                'indicator': line,
                'source': source_name,
                'added_date': added_date
            })
            count += 1

    return output.getvalue(), count, None

def parse_zip_csv_feed(provider_id, content):
    """Parse ZIP files containing CSV (like MaxMind databases)."""
    import zipfile

    output = StringIO()
    count = 0

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            # Find the main CSV file
            csv_files = [f for f in zf.namelist() if f.endswith('.csv') and 'Blocks' in f]
            if not csv_files:
                csv_files = [f for f in zf.namelist() if f.endswith('.csv')]

            if csv_files:
                # Use the first (or largest) CSV
                csv_file = csv_files[0]
                with zf.open(csv_file) as f:
                    text = f.read().decode('utf-8', errors='replace')
                    reader = csv.reader(StringIO(text))
                    headers = next(reader, None)
                    if headers:
                        writer = csv.writer(output)
                        writer.writerow(headers)
                        for row in reader:
                            writer.writerow(row)
                            count += 1
    except Exception as e:
        return None, 0, f"ZIP extraction error: {str(e)}"

    return output.getvalue(), count, None

def generate_csv_preview(csv_content, max_rows=100):
    """
    Generate a preview of CSV content for display in the UI.

    Args:
        csv_content: CSV content as a string
        max_rows: Maximum number of data rows to include (default 100)

    Returns:
        dict with 'headers', 'rows', and 'total_count'
    """
    try:
        lines = csv_content.strip().split('\n')
        if not lines:
            return {'headers': [], 'rows': [], 'total_count': 0}

        reader = csv.reader(io.StringIO(csv_content))
        headers = next(reader, [])

        rows = []
        total_count = 0
        for row in reader:
            total_count += 1
            if len(rows) < max_rows:
                rows.append(row)

        return {
            'headers': headers,
            'rows': rows,
            'total_count': total_count
        }
    except Exception as e:
        debug_log(f"[MARKETPLACE] CSV preview generation error: {str(e)}")
        return {'headers': [], 'rows': [], 'total_count': 0, 'error': str(e)}

# =============================================================================
# MARKETPLACE - Sync Execution
# =============================================================================

def execute_feed_sync(feed_id, manual=False):
    """
    Execute a feed sync operation.

    Args:
        feed_id: The feed ID from the database
        manual: Whether this is a manual sync (vs scheduled)
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Get feed configuration
        cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
        feed = feed_row_to_dict(cursor.fetchone())

        if not feed:
            debug_log(f"[MARKETPLACE] Feed {feed_id} not found")
            return False, "Feed not found", None

        if not feed['enabled'] and not manual:
            debug_log(f"[MARKETPLACE] Feed {feed_id} is disabled, skipping")
            return False, "Feed is disabled", None

        provider_id = feed['provider_id']
        auth_config = json.loads(feed['auth_config']) if feed['auth_config'] else None

        debug_log(f"[MARKETPLACE] Syncing feed {feed_id}: {feed['name']} ({provider_id})")

        # Download feed content
        content, error = download_feed_content(provider_id, auth_config)
        if error:
            update_feed_status(feed_id, 'error', f"Download failed: {error}")
            return False, error, None

        # Calculate content hash to detect changes
        content_hash = hashlib.md5(content).hexdigest()

        # Check if content has changed
        if feed['content_hash'] == content_hash and not manual:
            update_feed_status(feed_id, 'unchanged', "Content unchanged since last sync")
            debug_log(f"[MARKETPLACE] Feed {feed_id} content unchanged")
            return True, "Content unchanged", None

        # Parse to CSV
        csv_content, record_count, parse_error = parse_feed_to_csv(provider_id, content)
        if parse_error:
            update_feed_status(feed_id, 'error', f"Parse failed: {parse_error}")
            return False, parse_error, None

        # Generate preview data (first 100 rows as JSON)
        preview_data = generate_csv_preview(csv_content, max_rows=100)
        preview_json = json.dumps(preview_data)

        # Store in sync history
        cursor.execute('''
            INSERT INTO sync_history (feed_id, status, message, records_count, content_hash, preview_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (feed_id, 'success', f"Downloaded {record_count} records", record_count, content_hash, preview_json))

        # Update feed status
        cursor.execute('''
            UPDATE feeds SET
                last_sync = CURRENT_TIMESTAMP,
                last_sync_status = 'success',
                last_sync_message = ?,
                content_hash = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (f"Downloaded {record_count} records", content_hash, feed_id))

        conn.commit()

        # Track transfer result for response
        transfer_result = None
        transfer_message = None

        # If authenticated with Cribl, transfer the lookup to target worker groups
        if app_config['authenticated'] and feed['target_worker_groups']:
            # Handle target_worker_groups as either JSON array or plain string
            target_groups_raw = feed['target_worker_groups']
            try:
                target_groups = json.loads(target_groups_raw) if target_groups_raw else []
            except json.JSONDecodeError:
                # If not valid JSON, treat as plain string (single group name)
                target_groups = [target_groups_raw] if target_groups_raw else []

            # Filter out empty values only (don't filter 'default' as it's a valid Cribl group name)
            target_groups = [g for g in target_groups if g]

            if target_groups:
                debug_log(f"[MARKETPLACE] Transferring lookup to groups: {target_groups}")
                transfer_result = transfer_feed_to_cribl(
                    feed,
                    csv_content,
                    target_groups,
                    auto_deploy=feed['auto_deploy']
                )
                if transfer_result['success']:
                    successful = [t['group'] for t in transfer_result['transfers'] if t.get('status') == 'success']
                    if successful:
                        transfer_message = f"Transferred to: {', '.join(successful)}"
                        if feed['auto_deploy']:
                            transfer_message += " (deployed)"
                        debug_log(f"[MARKETPLACE] {transfer_message}")
                else:
                    transfer_message = f"Transfer failed: {transfer_result['error']}"
                    debug_log(f"[MARKETPLACE] {transfer_message}")
            else:
                transfer_message = "No target worker groups configured (edit feed to set destination)"
                debug_log(f"[MARKETPLACE] {transfer_message}")
        elif not app_config['authenticated']:
            transfer_message = "Not authenticated with Cribl - login to enable transfer"
            debug_log(f"[MARKETPLACE] {transfer_message}")
        else:
            transfer_message = "No target worker groups configured"
            debug_log(f"[MARKETPLACE] {transfer_message}")

        # Build final message with transfer status
        final_message = f"Synced {record_count} records"
        if transfer_message:
            final_message += f". {transfer_message}"

        debug_log(f"[MARKETPLACE] Feed {feed_id} sync complete: {final_message}")
        return True, final_message, preview_data

    except Exception as e:
        debug_log(f"[MARKETPLACE] Feed {feed_id} sync error: {str(e)}")
        update_feed_status(feed_id, 'error', str(e))
        return False, str(e), None
    finally:
        conn.close()

def update_feed_status(feed_id, status, message):
    """Update feed sync status in database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE feeds SET
            last_sync = CURRENT_TIMESTAMP,
            last_sync_status = ?,
            last_sync_message = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (status, message, feed_id))
    conn.commit()
    conn.close()

def transfer_feed_to_cribl(feed, csv_content, target_groups, auto_deploy=False):
    """
    Transfer feed lookup to Cribl worker groups.
    Uses the same API pattern as the working transfer_lookup function.

    Args:
        feed: Feed configuration dict
        csv_content: CSV content string
        target_groups: List of worker group names
        auto_deploy: Whether to auto-deploy after transfer
    """
    results = {'success': True, 'transfers': [], 'error': None}

    api_type = feed.get('target_api_type', 'stream')
    filename = feed['lookup_filename']
    token = app_config['token']

    for group in target_groups:
        try:
            debug_log(f"[MARKETPLACE] Transferring {filename} to {group} ({api_type})")

            # Step 1: Upload CSV to temp file
            upload_url = build_api_url(api_type, group, path='/system/lookups', query=f'filename={filename}')
            debug_log(f"[MARKETPLACE] Upload URL: {upload_url}")

            upload_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/csv"
            }

            response = requests.put(
                upload_url,
                headers=upload_headers,
                data=csv_content.encode('utf-8'),
                timeout=60
            )

            if response.status_code not in [200, 201]:
                debug_log(f"[MARKETPLACE] Upload failed: {response.status_code} - {response.text}")
                results['transfers'].append({'group': group, 'status': 'error', 'code': response.status_code})
                results['success'] = False
                results['error'] = f"Upload failed: {response.status_code}"
                continue

            temp_file_response = response.json()
            temp_file_name = temp_file_response.get('filename')
            debug_log(f"[MARKETPLACE] Uploaded to temp file: {temp_file_name}")

            # Step 2: Create/update lookup definition
            lookup_url = build_api_url(api_type, group, path='/system/lookups')
            lookup_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            payload = {
                "id": filename,
                "fileInfo": {"filename": temp_file_name}
            }

            # Try POST first (create new)
            lookup_response = requests.post(lookup_url, headers=lookup_headers, json=payload, timeout=30)

            if lookup_response.status_code == 409 or (lookup_response.status_code == 500 and 'already exists' in lookup_response.text.lower()):
                # Lookup exists, update it with PATCH
                debug_log(f"[MARKETPLACE] Lookup exists, updating...")
                patch_url = f"{lookup_url}/{filename}"
                lookup_response = requests.patch(patch_url, headers=lookup_headers, json=payload, timeout=30)

            if lookup_response.status_code not in [200, 201]:
                debug_log(f"[MARKETPLACE] Lookup create/update failed: {lookup_response.status_code} - {lookup_response.text}")
                results['transfers'].append({'group': group, 'status': 'error', 'code': lookup_response.status_code})
                results['success'] = False
                results['error'] = f"Lookup definition failed: {lookup_response.status_code}"
                continue

            debug_log(f"[MARKETPLACE] Lookup definition created/updated")

            # Step 3: Commit changes
            commit_url = build_api_url(api_type, group, path='/version/commit')
            commit_response = requests.post(
                commit_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"message": f"[Marketplace] Updated {filename} from {feed['name']}"},
                timeout=30
            )

            if commit_response.status_code == 200:
                debug_log(f"[MARKETPLACE] Committed changes to {group}")
            else:
                debug_log(f"[MARKETPLACE] Commit warning: {commit_response.status_code}")

            # Step 4: Deploy if auto_deploy is enabled
            if auto_deploy:
                deploy_url = build_api_url(api_type, group, path=f'/master/groups/{group}/deploy')
                deploy_response = requests.patch(
                    deploy_url,
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=30
                )
                if deploy_response.status_code == 200:
                    debug_log(f"[MARKETPLACE] Deployed to {group}")
                else:
                    debug_log(f"[MARKETPLACE] Deploy failed: {deploy_response.status_code}")

            results['transfers'].append({'group': group, 'status': 'success'})

        except Exception as e:
            results['transfers'].append({'group': group, 'status': 'error', 'error': str(e)})
            results['success'] = False
            results['error'] = str(e)

    return results

def schedule_feed_job(feed_id, schedule_cron):
    """
    Schedule a feed sync job using a cron expression.

    Args:
        feed_id: Feed ID from database
        schedule_cron: Cron expression (minute hour day_of_month month day_of_week)
                       e.g., "0 6 * * *" = daily at 6:00 AM
                       e.g., "0 6 * * 1,3,5" = Mon/Wed/Fri at 6:00 AM
    """
    job_id = f"feed_{feed_id}"

    # Remove existing job if any
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    # Parse cron expression (minute hour day_of_month month day_of_week)
    try:
        parts = schedule_cron.split()
        if len(parts) >= 5:
            minute = parts[0]
            hour = parts[1]
            day = parts[2]
            month = parts[3]
            day_of_week = parts[4]
        else:
            # Default to daily at 6:00 AM if invalid
            minute, hour, day, month, day_of_week = '0', '6', '*', '*', '*'
    except (ValueError, AttributeError):
        minute, hour, day, month, day_of_week = '0', '6', '*', '*', '*'

    scheduler.add_job(
        execute_feed_sync,
        CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week),
        id=job_id,
        args=[feed_id],
        replace_existing=True
    )

    debug_log(f"[MARKETPLACE] Scheduled job for feed {feed_id}: cron={schedule_cron}")

def load_scheduled_jobs():
    """Load and schedule all enabled feeds from database."""
    if not MARKETPLACE_DB_PATH.exists():
        return

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, schedule_cron FROM feeds WHERE enabled = 1')
    feeds = cursor.fetchall()
    conn.close()

    for feed in feeds:
        schedule_feed_job(feed['id'], feed['schedule_cron'] or '0 6 * * *')

    debug_log(f"[MARKETPLACE] Loaded {len(feeds)} scheduled feeds")

# SECURITY: Add security headers to all responses
@app.after_request
def add_security_headers(response):
    """Add security headers to prevent various attacks"""
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # Prevent MIME sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enable XSS protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Content Security Policy (restrictive)
    response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; img-src 'self' data:; connect-src 'self' http://localhost:* http://127.0.0.1:* https://*.cribl.cloud;"
    # Referrer policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# =============================================================================
# STATIC FILE ROUTES
# =============================================================================

@app.route('/')
def index():
    """Serve the main application page (React frontend)."""
    return send_file('index.html')

@app.route('/cribl-logo.svg')
def serve_logo():
    """Serve the Cribl logo SVG file."""
    return send_file('cribl-logo.svg', mimetype='image/svg+xml')

# =============================================================================
# CONFIGURATION AND AUTHENTICATION HELPERS
# =============================================================================

def load_config_from_env():
    """
    Load credentials from environment variables.

    Environment variables (more secure than config file):
        CRIBL_CLIENT_ID - OAuth client ID
        CRIBL_CLIENT_SECRET - OAuth client secret
        CRIBL_ORG_ID - Organization ID (tenant name or URL)

    Returns:
        dict: Configuration with client_id, client_secret, organization_id
        None: If environment variables are not set
    """
    client_id = os.environ.get('CRIBL_CLIENT_ID', '')
    client_secret = os.environ.get('CRIBL_CLIENT_SECRET', '')
    org_id = os.environ.get('CRIBL_ORG_ID', '')

    if client_id and client_secret and org_id:
        return {
            'client_id': client_id,
            'client_secret': client_secret,
            'organization_id': org_id
        }
    return None

def secure_config_file():
    """
    Set restrictive file permissions on config.ini (owner read/write only).
    This helps protect credentials from other users on shared systems.
    """
    config_path = Path('config.ini')
    if config_path.exists():
        try:
            # Set permissions to 600 (owner read/write only)
            os.chmod(config_path, 0o600)
            return True
        except (OSError, PermissionError):
            # May fail on Windows or if file is owned by another user
            return False
    return False

def load_config_file():
    """
    Load credentials from environment variables or config.ini file.

    Priority order:
    1. Environment variables (CRIBL_CLIENT_ID, CRIBL_CLIENT_SECRET, CRIBL_ORG_ID)
    2. config.ini file

    Environment variables are preferred as they:
    - Don't persist secrets to disk
    - Work with secret managers and CI/CD systems
    - Can't be accidentally committed to git

    Returns:
        tuple: (config_dict, source_string) where source is 'env' or 'file'
        (None, None): If no configuration found
    """
    # First, try environment variables (more secure)
    env_config = load_config_from_env()
    if env_config:
        return env_config, 'env'

    # Fall back to config.ini file
    config_path = Path('config.ini')
    if config_path.exists():
        # Secure the file permissions
        secure_config_file()

        config = configparser.ConfigParser()
        config.read(config_path)
        if 'cribl' in config:
            return {
                'client_id': config['cribl'].get('client_id', ''),
                'client_secret': config['cribl'].get('client_secret', ''),
                'organization_id': config['cribl'].get('organization_id', '')
            }, 'file'
    return None, None

def get_bearer_token(client_id, client_secret):
    """
    Obtain OAuth bearer token from Cribl Cloud authentication service.

    Args:
        client_id: OAuth client ID from Cribl Cloud API credentials
        client_secret: OAuth client secret from Cribl Cloud API credentials

    Returns:
        str: Bearer token for API authentication

    Raises:
        Exception: If authentication fails
    """
    url = "https://login.cribl.cloud/oauth/token"
    headers = {"Content-Type": "application/json"}
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "audience": "https://api.cribl.cloud"
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        raise Exception(f"Failed to obtain bearer token: {str(e)}")

def get_api_base_url(api_type, organization_id):
    """
    Get the appropriate API base URL based on API type.

    Note: This function returns the centralized app.cribl.cloud URL format,
    but for direct tenant URLs, use get_base_url() instead.
    """
    if api_type == 'search':
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"
    elif api_type == 'stream':
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"
    elif api_type == 'edge':
        return f"https://app.cribl.cloud/organizations/{organization_id}/edge/api/v1"
    else:
        return f"https://app.cribl.cloud/organizations/{organization_id}/workspaces/main/app/api/v1"

# =============================================================================
# DIAGNOSTIC AND TESTING ENDPOINTS
# =============================================================================

@app.route('/api/test-connection', methods=['GET'])
def test_connection():
    """
    Test connectivity to Cribl Cloud services.

    Tests DNS resolution, HTTPS connectivity, and OAuth endpoint availability.
    Useful for troubleshooting connection issues.
    """
    results = {}
    
    # Get the actual base URL if we have one from login
    base_url = get_base_url()  # Use helper function
    test_hostname = base_url.replace('https://', '').replace('http://', '').split('/')[0]
    
    # Test DNS resolution
    try:
        import socket
        socket.gethostbyname(test_hostname)
        results['dns'] = f'✓ DNS resolution successful for {test_hostname}'
    except Exception as e:
        results['dns'] = f'[ERROR] DNS resolution failed for {test_hostname}: {str(e)}'
    
    # Test HTTPS connection
    try:
        response = requests.get(base_url, timeout=5)
        results['https'] = f'✓ HTTPS connection successful (status: {response.status_code})'
    except requests.exceptions.Timeout:
        results['https'] = f'[ERROR] Connection timeout to {base_url} - firewall or network issue?'
    except requests.exceptions.ConnectionError as e:
        results['https'] = f'[ERROR] Connection error to {base_url}: {str(e)}'
    except Exception as e:
        results['https'] = f'[ERROR] HTTPS connection failed to {base_url}: {str(e)}'
    
    # Test OAuth endpoint
    try:
        response = requests.get('https://login.cribl.cloud', timeout=5)
        results['oauth'] = f'✓ OAuth endpoint reachable (status: {response.status_code})'
    except Exception as e:
        results['oauth'] = f'[ERROR] OAuth endpoint unreachable: {str(e)}'
    
    return jsonify(results)

@app.route('/api/discover-api-paths', methods=['GET'])
def discover_api_paths():
    """
    Try to discover the correct API paths for the deployment.

    Tests multiple URL patterns to find working API endpoints.
    Useful when API paths vary between deployment types.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    base_url = get_base_url()  # Use helper function
    org_id = app_config['organization_id']
    token = app_config['token']
    api_type = request.args.get('api_type', 'stream')
    
    headers = {"Authorization": f"Bearer {token}"}
    results = {}
    
    debug_log(f"\n[DISCOVER] Discovering API paths for {api_type}")
    debug_log(f"   Base URL: {base_url}")
    debug_log(f"   Org ID: {org_id}")
    
    # Test both direct tenant URLs and centralized URLs
    test_urls = []
    
    if api_type == 'search':
        test_urls = [
            # Most likely correct path based on user's working curl
            f"{base_url}/api/v1/master/groups",
            # Standard Cribl Cloud API patterns
            f"{base_url}/api/v1/m",
            f"{base_url}/api/v1/m/default_search",
            # With workspaces
            f"{base_url}/workspaces/main/app/api/v1/m",
            f"{base_url}/search/workspaces/main/app/api/v1/m",
            f"{base_url}/workspaces/search/api/v1/m",
            # Search-specific paths
            f"{base_url}/search/api/v1/m",
            f"{base_url}/api/m",
            # Centralized attempts (likely to fail based on your network)
            f"https://app.cribl.cloud/organizations/{org_id}/workspaces/main/app/api/v1/m",
            f"https://app.cribl.cloud/organizations/{org_id}/search/api/v1/m",
        ]
    elif api_type == 'edge':
        test_urls = [
            # Correct path based on user's working curl
            f"{base_url}/api/v1/products/edge/groups",
            # Other possible paths
            f"{base_url}/api/v1/edge/fleets",
            f"{base_url}/api/v1/fleets",
            f"{base_url}/api/v1/f",
            # With workspaces
            f"{base_url}/workspaces/main/app/api/v1/edge/fleets",
            f"{base_url}/edge/workspaces/main/api/v1/fleets",
            f"{base_url}/edge/api/v1/fleets",
            # Centralized attempts
            f"https://app.cribl.cloud/organizations/{org_id}/api/v1/products/edge/groups",
            f"https://app.cribl.cloud/organizations/{org_id}/edge/api/v1/fleets",
        ]
    else:  # stream
        test_urls = [
            # Most likely correct path based on user's working curl
            f"{base_url}/api/v1/master/groups",
            # Standard Cribl Cloud API patterns
            f"{base_url}/api/v1/m",
            f"{base_url}/api/v1/groups",
            # With workspaces  
            f"{base_url}/workspaces/main/app/api/v1/m",
            f"{base_url}/stream/workspaces/main/app/api/v1/m",
            f"{base_url}/workspaces/stream/api/v1/m",
            # Stream-specific paths
            f"{base_url}/stream/api/v1/m",
            f"{base_url}/api/m",
            # Centralized attempts
            f"https://app.cribl.cloud/organizations/{org_id}/workspaces/main/app/api/v1/m",
            f"https://app.cribl.cloud/organizations/{org_id}/api/v1/m",
        ]
    
    for url in test_urls:
        try:
            debug_log(f"   Testing: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            content_type = response.headers.get('Content-Type', '')
            
            is_json = 'application/json' in content_type
            is_success = response.status_code == 200
            
            debug_log(f"   {'[OK]' if (is_json and is_success) else '[WARN]'} Status: {response.status_code}, Content-Type: {content_type}")
            
            result_data = {
                'status': response.status_code,
                'content_type': content_type,
                'is_json': is_json,
                'works': is_json and is_success
            }
            
            if is_json and is_success:
                try:
                    data = response.json()
                    result_data['preview'] = json.dumps(data, indent=2)[:300]
                    result_data['data_type'] = type(data).__name__
                    if isinstance(data, dict):
                        result_data['keys'] = list(data.keys())[:10]
                    elif isinstance(data, list):
                        result_data['count'] = len(data)
                        result_data['first_item'] = data[0] if data else None
                except:
                    pass
                
                # Found a working path - return immediately
                results[url] = result_data
                debug_log(f"   [OK] Found working path! Stopping search.")
                return jsonify(results)
            
            results[url] = result_data
            
        except Exception as e:
            debug_log(f"   [ERROR] Error: {str(e)}")
            results[url] = {
                'works': False,
                'error': str(e)
            }

    return jsonify(results)

@app.route('/api/discover-pack-lookups', methods=['GET'])
def discover_pack_lookups():
    """Discover the correct API path for pack lookups"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group', 'default')
    pack_id = request.args.get('pack_id')
    api_type = request.args.get('api_type', 'stream')

    base_url = get_base_url()
    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}
    results = {}

    debug_log(f"\n[DISCOVER-PACK] Finding pack lookup path for {pack_id} in {worker_group}")

    # First, get the pack detail to see what fields it returns
    pack_detail_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}')
    try:
        debug_log(f"   Getting pack detail: {pack_detail_url}")
        response = requests.get(pack_detail_url, headers=headers, timeout=10)
        if response.status_code == 200:
            pack_data = response.json()
            results['pack_detail_url'] = pack_detail_url
            results['pack_keys'] = list(pack_data.keys()) if isinstance(pack_data, dict) else str(type(pack_data))
            results['pack_data_preview'] = json.dumps(pack_data, indent=2)[:2000]
    except Exception as e:
        results['pack_detail_error'] = str(e)

    # Try various pack lookup endpoint patterns
    test_patterns = [
        f"/packs/{pack_id}/lookups",
        f"/packs/{pack_id}/knowledge/lookups",
        f"/lib/{pack_id}/lookups",
        f"/lib/{pack_id}/knowledge/lookups",
        f"/p/{pack_id}/lookups",
        f"/p/{pack_id}/knowledge/lookups",
    ]

    for pattern in test_patterns:
        url = build_api_url(api_type, worker_group, path=pattern)
        try:
            debug_log(f"   Testing: {url}")
            response = requests.get(url, headers=headers, timeout=10)
            content_type = response.headers.get('Content-Type', '')
            result = {
                'status': response.status_code,
                'content_type': content_type
            }
            if response.status_code == 200 and 'application/json' in content_type:
                data = response.json()
                result['data_preview'] = json.dumps(data, indent=2)[:500]
                result['works'] = True
            else:
                result['works'] = False
            results[url] = result
        except Exception as e:
            results[url] = {'error': str(e), 'works': False}

    return jsonify(results)

# =============================================================================
# AUTHENTICATION ENDPOINTS
# =============================================================================

@app.route('/api/config', methods=['GET'])
def get_config():
    """Check if config file exists and return non-sensitive config data."""
    config, source = load_config_file()
    if config and all(config.values()):
        return jsonify({
            'hasConfig': True,
            'configSource': source,  # 'env' or 'file'
            'config': {
                'organization_id': config['organization_id']
            }
        })
    return jsonify({'hasConfig': False})

@app.route('/api/session-info', methods=['GET'])
def get_session_info():
    """
    Get current session info including token and base URL.

    Returns the bearer token and base URL needed for the frontend
    to construct curl commands for debugging purposes.
    """
    if not app_config['authenticated']:
        debug_log("   [ERROR] Session info request - not authenticated")
        return jsonify({'error': 'Not authenticated'}), 401
    
    base_url = app_config.get('base_url', '')
    token = app_config.get('token', '')
    org_id = app_config.get('organization_id', '')
    
    debug_log(f"\n[DEBUG] Session info request:")
    debug_log(f"   Base URL: {base_url}")
    debug_log(f"   Token present: {bool(token)}")
    debug_log(f"   Token length: {len(token) if token else 0}")
    debug_log(f"   Org ID: {org_id}")
    
    response_data = {
        'base_url': base_url,
        'token': token,
        'organization_id': org_id
    }
    
    return jsonify(response_data)


def extract_org_id_and_base_url(org_input):
    """
    Extract organization ID and determine base URL from user input.

    Supports multiple input formats:
    - Direct tenant URL: main-org-name.cribl.cloud
    - Full URL: https://main-org-name.cribl.cloud/
    - Centralized URL: https://app.cribl.cloud/organizations/org-id/...
    - Just the org ID: org-name

    Returns:
        tuple: (org_id, base_url, is_direct_tenant)
    """
    if not org_input:
        return None, None, False
    
    # Remove any whitespace
    org_input = org_input.strip()
    
    # Check if it's a direct tenant URL (e.g., main-amazing-varahamihira.cribl.cloud)
    is_direct_tenant = False
    base_url = None
    org_id = None
    
    # If it's a URL, extract the org ID and base URL
    if 'http://' in org_input or 'https://' in org_input or '.cribl.cloud' in org_input:
        # Remove protocol
        clean_url = org_input.replace('https://', '').replace('http://', '')
        
        # Handle app.cribl.cloud URLs with /organizations/ path
        if 'app.cribl.cloud/organizations/' in clean_url:
            parts = clean_url.split('/organizations/')
            if len(parts) > 1:
                org_id = parts[1].split('/')[0]
                base_url = 'https://app.cribl.cloud'
                is_direct_tenant = False
        # Handle direct tenant URLs (e.g., main-amazing-varahamihira.cribl.cloud)
        elif '.cribl.cloud' in clean_url and 'app.cribl.cloud' not in clean_url:
            # Extract subdomain as org_id
            subdomain = clean_url.split('.cribl.cloud')[0]
            # Remove any path
            subdomain = subdomain.split('/')[0]
            org_id = subdomain
            base_url = f'https://{subdomain}.cribl.cloud'
            is_direct_tenant = True
        # Handle app.cribl.cloud without /organizations/ path
        elif 'app.cribl.cloud' in clean_url:
            base_url = 'https://app.cribl.cloud'
            # Try to extract from other parts of URL
            org_id = clean_url.split('/')[1] if '/' in clean_url else None
            is_direct_tenant = False
    else:
        # Just an org ID was provided - assume it's a direct tenant subdomain
        # For Cribl Cloud, the format is: https://{workspace}-{org}.cribl.cloud
        org_id = org_input
        base_url = f'https://{org_input}.cribl.cloud'
        is_direct_tenant = True
    
    return org_id, base_url, is_direct_tenant

def get_base_url():
    """
    Get base URL with proper fallback to organization_id.

    Returns the correct base URL for API calls. If base_url is not set in app_config,
    it constructs it from organization_id. Handles malformed URLs and cleans up
    any double-protocol issues.

    This is the primary function for obtaining the base URL throughout the app.

    Returns:
        str: Base URL like 'https://main-org-name.cribl.cloud'
    """
    base_url = app_config.get('base_url')

    # Validate base_url - if it contains double protocol or malformed .cribl.cloud, reconstruct it
    if base_url and ('https://https://' in base_url or '.cribl.cloud/.cribl.cloud' in base_url or 'https://' in base_url[8:]):
        base_url = None  # Force reconstruction

    if not base_url and app_config.get('organization_id'):
        # Construct from organization_id if not already set
        org_id = app_config['organization_id']

        # Clean up organization_id - remove protocol and trailing slashes
        org_id = org_id.strip()
        if org_id.startswith('https://'):
            org_id = org_id[8:]
        elif org_id.startswith('http://'):
            org_id = org_id[7:]
        org_id = org_id.rstrip('/')

        # If it already ends with .cribl.cloud, use as-is; otherwise add it
        if org_id.endswith('.cribl.cloud'):
            base_url = f'https://{org_id}'
        else:
            base_url = f'https://{org_id}.cribl.cloud'

        # Update the stored value with the corrected one
        app_config['base_url'] = base_url

    # Final fallback with proper cleaning
    if not base_url and app_config.get('organization_id'):
        org_id = app_config.get('organization_id', 'unknown')
        org_id = org_id.strip()
        if org_id.startswith('https://'):
            org_id = org_id[8:]
        elif org_id.startswith('http://'):
            org_id = org_id[7:]
        org_id = org_id.rstrip('/')

        if org_id.endswith('.cribl.cloud'):
            base_url = f'https://{org_id}'
        else:
            base_url = f'https://{org_id}.cribl.cloud'

    return base_url

# =============================================================================
# API URL CONSTRUCTION
# =============================================================================

def build_api_url(api_type, worker_group=None, path='', query=''):
    """
    Build API URL based on tenant type and API type.

    Based on Cribl API documentation:
    - Cribl.Cloud: https://{workspace}-{org}.cribl.cloud/api/v1/m/{group}/...
    - On-prem: https://{hostname}:{port}/api/v1/m/{group}/...

    Note: Both Stream worker groups AND Edge fleets use /m/{group} for resource access
    (lookups, pipelines, etc). The /f/ prefix was found to be incorrect.

    Args:
        api_type: 'stream', 'edge', or 'search'
        worker_group: Worker group or fleet name (optional)
        path: Additional path to append (e.g., '/system/lookups')
        query: Query string without leading '?' (optional)

    Returns:
        str: Complete API URL
    """
    base_url = get_base_url()  # Use helper function
    is_direct_tenant = app_config.get('is_direct_tenant', False)
    organization_id = app_config.get('organization_id')

    # All API types (stream, edge, search) use /m/{group} for resource access
    base_path = f"{base_url}/api/v1"
    if worker_group:
        base_path += f"/m/{worker_group}"

    url = base_path + path
    if query:
        url += f"?{query}"

    return url

@app.route('/api/auth/login', methods=['POST'])
def login():
    """
    Authenticate with Cribl Cloud.

    Accepts client_id, client_secret, and organization_id in request body.
    Falls back to config.ini if credentials not provided in request.
    Stores authentication state in app_config for subsequent requests.
    """
    data = request.json
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    organization_id = data.get('organization_id')
    
    # Try config file/env vars first if credentials not provided
    if not client_id or not client_secret:
        config, _ = load_config_file()
        if config:
            client_id = config['client_id']
            client_secret = config['client_secret']
            organization_id = organization_id or config['organization_id']
    
    # Extract org ID and determine base URL from URL if needed
    org_id, base_url, is_direct_tenant = extract_org_id_and_base_url(organization_id)
    
    debug_log(f"\n[DEBUG] Login attempt:")
    debug_log(f"   Input: {organization_id}")
    debug_log(f"   Extracted: Org ID: {org_id}")
    debug_log(f"   Base URL: {base_url}")
    debug_log(f"   Direct Tenant: {is_direct_tenant}")
    
    if not all([client_id, client_secret, org_id]):
        return jsonify({'error': 'Missing credentials'}), 400
    
    try:
        token = get_bearer_token(client_id, client_secret)
        app_config['authenticated'] = True
        app_config['token'] = token
        app_config['client_id'] = client_id
        app_config['client_secret'] = client_secret
        app_config['organization_id'] = org_id
        app_config['base_url'] = base_url
        app_config['is_direct_tenant'] = is_direct_tenant
        
        debug_log(f"   [OK] Authentication successful!")
        debug_log(f"   Token stored (length: {len(token)})")
        
        return jsonify({
            'success': True,
            'organization_id': org_id,
            'base_url': base_url,
            'is_direct_tenant': is_direct_tenant,
            'extracted_from_input': organization_id
        })
    except Exception as e:
        debug_log(f"   [OK] Authentication failed: {str(e)}")
        return jsonify({'error': str(e)}), 401

@app.route('/api/test-curl', methods=['POST'])
def test_curl():
    """
    Test API endpoint connectivity.

    Tests multiple API endpoints to verify connectivity:
    - List worker groups
    - List lookups (if worker group provided)
    - Version endpoint

    Used by the frontend's "Test API" feature.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    api_type = data.get('api_type', 'stream')
    worker_group = data.get('worker_group')
    
    debug_log(f"\n[TEST] Testing API connectivity for {api_type}")
    if worker_group:
        debug_log(f"   Worker Group: {worker_group}")
    
    try:
        # Validate API type
        validate_api_type(api_type)
        
        token = app_config['token']
        base_url = get_base_url()
        
        debug_log(f"   Base URL: {base_url}")
        
        results = []
        
        # Test 1: List worker groups
        try:
            if api_type == 'edge':
                test_url = f"{base_url}/api/v1/products/edge/groups"
            else:
                test_url = f"{base_url}/api/v1/master/groups"
            
            debug_log(f"   Testing: {test_url}")
            response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
            results.append({
                'endpoint': 'List Groups',
                'url': test_url,
                'status': response.status_code,
                'success': response.status_code == 200,
                'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code}"
            })
        except Exception as e:
            results.append({
                'endpoint': 'List Groups',
                'url': test_url,
                'status': 0,
                'success': False,
                'message': str(e)
            })
        
        # Test 2: List lookups (if worker group provided)
        if worker_group:
            try:
                validate_worker_group(worker_group)
                
                if api_type == 'edge':
                    test_url = f"{base_url}/api/v1/f/{worker_group}/system/lookups"
                else:
                    test_url = f"{base_url}/api/v1/m/{worker_group}/system/lookups"
                
                debug_log(f"   Testing: {test_url}")
                response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                results.append({
                    'endpoint': 'List Lookups',
                    'url': test_url,
                    'status': response.status_code,
                    'success': response.status_code == 200,
                    'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code}"
                })
            except Exception as e:
                results.append({
                    'endpoint': 'List Lookups',
                    'url': test_url,
                    'status': 0,
                    'success': False,
                    'message': str(e)
                })
        
        # Test 3: Version endpoint (if worker group provided)
        if worker_group:
            try:
                if api_type == 'edge':
                    test_url = f"{base_url}/api/v1/f/{worker_group}/version"
                else:
                    test_url = f"{base_url}/api/v1/m/{worker_group}/version"
                
                debug_log(f"   Testing: {test_url}")
                response = requests.get(test_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                results.append({
                    'endpoint': 'Version',
                    'url': test_url,
                    'status': response.status_code,
                    'success': response.status_code in [200, 404],  # 404 is OK for version
                    'message': 'OK' if response.status_code == 200 else f"HTTP {response.status_code} (may not be supported)"
                })
            except Exception as e:
                results.append({
                    'endpoint': 'Version',
                    'url': test_url,
                    'status': 0,
                    'success': False,
                    'message': str(e)
                })
        
        debug_log(f"   [OK] Test completed - {len([r for r in results if r['success']])}/{len(results)} passed")
        
        return jsonify({
            'success': True,
            'results': results,
            'base_url': base_url
        })
        
    except Exception as e:
        debug_log(f"   [ERROR] Test failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def logout():
    """Clear session data and reset authentication state."""
    app_config['authenticated'] = False
    app_config['token'] = None
    app_config['client_id'] = None
    app_config['client_secret'] = None
    app_config['organization_id'] = None
    app_config['base_url'] = None
    app_config['is_direct_tenant'] = False
    debug_log("[INFO] User logged out - session cleared")
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    """Check authentication status. Returns whether user is authenticated."""
    return jsonify({
        'authenticated': app_config['authenticated'],
        'organization_id': app_config.get('organization_id')
    })

# =============================================================================
# WORKER GROUP / FLEET ENDPOINTS
# =============================================================================

@app.route('/api/worker-groups', methods=['GET'])
def get_worker_groups():
    """
    Get list of worker groups (Stream) or fleets (Edge).

    Query params:
    - api_type: 'stream', 'edge', or 'search'

    Returns list of groups with id and name properties.
    For Search, returns default_search as the only group.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    organization_id = app_config['organization_id']
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    is_direct_tenant = app_config.get('is_direct_tenant', False)
    
    debug_log(f"\n[DEBUG] Fetching worker groups for {api_type} API...")
    debug_log(f"   Organization ID: {organization_id}")
    debug_log(f"   Base URL: {base_url}")
    debug_log(f"   Direct Tenant: {is_direct_tenant}")
    
    try:
        # Build correct URL for listing groups per Cribl API docs
        if is_direct_tenant or '.cribl.cloud' in base_url:
            # Cribl.Cloud format
            if api_type == 'edge':
                url = f"{base_url}/api/v1/products/edge/groups"
            else:  # stream or search
                url = f"{base_url}/api/v1/master/groups"
        else:
            # On-prem format
            if api_type == 'edge':
                url = f"{base_url}/api/v1/products/edge/groups"
            else:  # stream or search
                url = f"{base_url}/api/v1/master/groups"
        
        debug_log(f"   URL: {url}")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.get(url, headers=headers, timeout=10)
        debug_log(f"   Response Status: {response.status_code}")
        debug_log(f"   Content-Type: {response.headers.get('Content-Type', 'unknown')}")
        
        # Check if we got HTML instead of JSON
        if 'text/html' in response.headers.get('Content-Type', ''):
            debug_log(f"   [ERROR] Received HTML instead of JSON - wrong endpoint!")
            debug_log(f"   Response preview: {response.text[:200]}")
            # Return defaults with a helpful message
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
            return jsonify({
                'groups': groups,
                'warning': f'API endpoint returned HTML. Using defaults. URL: {url}'
            })
        
        response.raise_for_status()
        
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            debug_log(f"   [ERROR] JSON decode error: {str(e)}")
            debug_log(f"   Response text: {response.text[:500]}")
            raise
        
        debug_log(f"   Response Data: {json.dumps(data, indent=2)[:500]}...")
        
        # Extract group names based on API type and response structure
        groups = []
        
        if api_type == 'edge':
            # Edge /api/v1/products/edge/groups returns array of group objects
            if isinstance(data, list):
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('name', item.get('id', item)) if isinstance(item, dict) else item} 
                         for item in data]
            elif 'items' in data:
                items = data.get('items', [])
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item, 
                          'name': item.get('name', item.get('id', item)) if isinstance(item, dict) else item} 
                         for item in items]
        elif api_type == 'search':
            # Search uses default_search - auto-selected in UI
            groups = [{'id': 'default_search', 'name': 'default_search'}]
        else:  # stream
            # Stream /api/v1/master/groups returns array of objects with id property
            # Filter to only include stream worker groups, not edge fleets or search
            def is_stream_group(item):
                if not isinstance(item, dict):
                    return True
                item_id = item.get('id', '')
                # Exclude items that are clearly fleets or search
                if 'fleet' in item_id.lower():
                    return False
                if item_id == 'default_search':
                    return False
                # Check product field if available
                product = item.get('product', '')
                if product and product != 'stream':
                    return False
                # Check isFleet flag
                if item.get('isFleet', False):
                    return False
                return True

            if isinstance(data, list):
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item,
                          'name': item.get('id', item) if isinstance(item, dict) else item}
                         for item in data
                         if is_stream_group(item)]
            elif 'items' in data:
                items = data.get('items', [])
                groups = [{'id': item.get('id', item) if isinstance(item, dict) else item,
                          'name': item.get('id', item) if isinstance(item, dict) else item}
                         for item in items
                         if is_stream_group(item)]
            else:
                groups = []
        
        # If no groups found, provide defaults
        if not groups:
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
        
        return jsonify({'groups': groups})
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP error: {e.response.status_code}"
        debug_log(f"   [ERROR] HTTP Error {e.response.status_code}")
        debug_log(f"   Response: {e.response.text[:500]}")
        if e.response.status_code == 404:
            # If endpoint not found, return defaults
            if api_type == 'search':
                groups = [
                    {'id': 'default_search', 'name': 'default_search'},
                    {'id': 'default', 'name': 'default'}
                ]
            else:
                groups = [{'id': 'default', 'name': 'default'}]
            debug_log(f"   [OK] Using default groups: {[g['id'] for g in groups]}")
            return jsonify({'groups': groups})
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        debug_log(f"   [ERROR] Exception: {str(e)}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# LOOKUP FILE ENDPOINTS
# =============================================================================

@app.route('/api/lookups', methods=['GET'])
def get_lookups():
    """
    Get list of system lookup files in a worker group.

    Query params:
    - worker_group: Required. The worker group/fleet to query.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'

    Note: For Stream/Edge, pack lookups are not included here. Use the
    /api/packs endpoint to list packs, then /api/packs/<pack_id>/lookups
    to get lookups from specific packs.

    For Search, pack lookups appear in /system/lookups with pack prefix.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}
    lookups = []

    # Get system lookups - single API call for fast response
    # Note: Pack lookups are only available in Search (they appear with pack prefix in /system/lookups)
    # For Stream/Edge, use /api/packs and /api/packs/<pack_id>/lookups separately
    url = build_api_url(api_type, worker_group, path='/system/lookups')

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()

        for item in data.get('items', []):
            mode = item.get('mode', 'memory')
            is_memory = mode != 'disk'
            item_id = item.get('id', '')

            # Detect pack lookups by pattern (works for Search where pack lookups have prefix)
            pack_name = None
            detected_pack, _ = parse_pack_lookup(item_id)
            if detected_pack:
                pack_name = detected_pack

            lookup = {
                'id': item_id,
                'size': item.get('size', 0),
                'inMemory': is_memory,
                'pack': pack_name
            }
            lookups.append(lookup)
    except Exception as e:
        debug_log(f"[WARNING] Failed to get system lookups: {str(e)}")

    return jsonify({'lookups': lookups})


def fetch_pack_lookups_internal(worker_group, api_type, token):
    """Internal function to fetch pack lookups for Stream/Edge.

    Uses the direct API: /api/v1/m/{group}/p/{pack}/system/lookups

    For Search, this function is not needed - pack lookups appear in /system/lookups.

    Returns a list of lookup dicts.
    """
    # Search doesn't need this - pack lookups already appear in /system/lookups with prefix
    if api_type == 'search':
        return []

    headers = {"Authorization": f"Bearer {token}"}
    pack_lookups = []

    debug_log(f"\n[PACK-LOOKUPS] Discovering pack lookups in {worker_group} ({api_type})")

    # Step 1: List all packs in the worker group
    packs_url = build_api_url(api_type, worker_group, path='/packs')
    debug_log(f"   [INFO] Listing packs: {packs_url}")

    packs_response = requests.get(packs_url, headers=headers, timeout=15)
    if packs_response.status_code != 200:
        debug_log(f"   [WARNING] Failed to list packs: HTTP {packs_response.status_code}")
        return []

    packs_data = packs_response.json()
    packs = packs_data.get('items', [])
    debug_log(f"   [OK] Found {len(packs)} pack(s)")

    if not packs:
        return []

    # Step 2: For each pack, get lookups via direct API
    for pack in packs:
        pack_id = pack.get('id')
        if not pack_id:
            continue

        debug_log(f"   [PACK] Processing pack: {pack_id}")

        # Direct API: /api/v1/m/{group}/p/{pack_id}/system/lookups
        lookups_url = build_api_url(api_type, worker_group, path=f'/p/{pack_id}/system/lookups')
        debug_log(f"      [API] {lookups_url}")

        try:
            response = requests.get(lookups_url, headers=headers, timeout=30)
            if response.status_code != 200:
                debug_log(f"      [WARNING] Failed to get lookups for pack {pack_id}: HTTP {response.status_code}")
                continue

            data = response.json()
            items = data.get('items', [])
            debug_log(f"      [OK] Found {len(items)} lookup(s)")

            for item in items:
                filename = item.get('id', item.get('filename', ''))
                if not filename:
                    continue
                size = item.get('size', item.get('fileInfo', {}).get('size', 0))
                in_memory = item.get('inMemory', True)
                pack_lookups.append({
                    'id': f"{pack_id}.{filename}",
                    'filename': filename,
                    'size': size,
                    'inMemory': in_memory,
                    'pack': pack_id
                })

        except requests.exceptions.Timeout:
            debug_log(f"      [WARNING] Timeout fetching lookups for pack {pack_id}")
            continue
        except Exception as e:
            debug_log(f"      [WARNING] Error fetching lookups for pack {pack_id}: {str(e)}")
            continue

    debug_log(f"   [DONE] Total pack lookups found: {len(pack_lookups)}")
    return pack_lookups


# =============================================================================
# KNOWLEDGE ITEM ENDPOINTS
# =============================================================================

# Knowledge type configurations - maps type ID to API path
KNOWLEDGE_TYPE_PATHS = {
    'breakers': '/lib/breakers',
    'datatypes': '/lib/breakers',  # Search uses same endpoint as breakers, just different UI name
    'parsers': '/lib/parsers',
    'variables': '/lib/vars',
    'macros': '/lib/vars',  # Search macros use same endpoint as variables
    'regexes': '/lib/regex',  # Note: singular, not plural
    'grok': '/lib/grok',
    'schemas': '/lib/schemas',
    'parquet-schemas': '/lib/parquet-schemas',
    'database-connections': '/lib/database-connections',
    'hmac': '/lib/hmac-functions',
    'appscope': '/lib/appscope-configs',  # AppScope configs (with hyphen)
    'guard': '/lib/sds-rules',  # Guard rules (SDS = Sensitive Data Shield)
}

@app.route('/api/knowledge/<knowledge_type>', methods=['GET'])
def get_knowledge_items(knowledge_type):
    """
    Get list of knowledge items by type.

    Path params:
    - knowledge_type: One of breakers, parsers, variables, regexes, grok,
                      schemas, parquet-schemas, database-connections, hmac,
                      appscope, guard

    Query params:
    - worker_group: Required. The worker group/fleet to query.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    if knowledge_type not in KNOWLEDGE_TYPE_PATHS:
        return jsonify({'error': f'Unknown knowledge type: {knowledge_type}'}), 400

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    try:
        validate_api_type(api_type)
        validate_worker_group(worker_group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    api_path = KNOWLEDGE_TYPE_PATHS[knowledge_type]
    url = build_api_url(api_type, worker_group, path=api_path)

    debug_log(f"\n[API] GET {sanitize_url_for_logging(url)}")

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Extract items from response
        items = []
        if isinstance(data, dict) and 'items' in data:
            items = data['items']
        elif isinstance(data, list):
            items = data

        return jsonify({
            'items': items,
            'count': len(items),
            'knowledge_type': knowledge_type
        })
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', str(e))
            except:
                pass
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg, 'items': []}), e.response.status_code if e.response else 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e), 'items': []}), 500


@app.route('/api/knowledge/<knowledge_type>/<item_id>', methods=['GET'])
def get_knowledge_item(knowledge_type, item_id):
    """
    Get a specific knowledge item by ID.

    Path params:
    - knowledge_type: The type of knowledge item
    - item_id: The ID of the item to retrieve

    Query params:
    - worker_group: Required. The worker group/fleet to query.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    if knowledge_type not in KNOWLEDGE_TYPE_PATHS:
        return jsonify({'error': f'Unknown knowledge type: {knowledge_type}'}), 400

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    try:
        validate_api_type(api_type)
        validate_worker_group(worker_group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    api_path = f"{KNOWLEDGE_TYPE_PATHS[knowledge_type]}/{item_id}"
    url = build_api_url(api_type, worker_group, path=api_path)

    debug_log(f"\n[API] GET {sanitize_url_for_logging(url)}")

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()

        # Some Cribl APIs return wrapped responses with count/items even for single items
        # Unwrap if necessary to get the actual item data
        item = data
        if isinstance(data, dict) and 'items' in data and 'count' in data:
            # Response is wrapped with count/items - extract the actual item
            items = data.get('items', [])
            if len(items) >= 1:
                item = items[0]
            # If empty, keep original data

        return jsonify({
            'item': item,
            'knowledge_type': knowledge_type,
            'item_id': item_id
        })
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', str(e))
            except:
                pass
        return jsonify({'error': error_msg}), e.response.status_code if e.response else 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/knowledge/<knowledge_type>', methods=['POST'])
def create_knowledge_item(knowledge_type):
    """
    Create a new knowledge item.

    Path params:
    - knowledge_type: The type of knowledge item

    Query params:
    - worker_group: Required. The worker group/fleet.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'

    Body: JSON object with the item data (must include 'id' field)
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    if knowledge_type not in KNOWLEDGE_TYPE_PATHS:
        return jsonify({'error': f'Unknown knowledge type: {knowledge_type}'}), 400

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    try:
        validate_api_type(api_type)
        validate_worker_group(worker_group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    if 'id' not in data:
        return jsonify({'error': 'Item must have an id field'}), 400

    token = app_config['token']
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    api_path = KNOWLEDGE_TYPE_PATHS[knowledge_type]
    url = build_api_url(api_type, worker_group, path=api_path)

    debug_log(f"\n[API] POST {sanitize_url_for_logging(url)}")
    debug_log(f"   [BODY] {json.dumps(data)[:500]}...")

    try:
        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        result = response.json()

        return jsonify({
            'success': True,
            'item': result,
            'knowledge_type': knowledge_type,
            'item_id': data.get('id')
        })
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', str(e))
            except:
                pass
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), e.response.status_code if e.response else 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/knowledge/<knowledge_type>/<item_id>', methods=['PATCH', 'PUT'])
def update_knowledge_item(knowledge_type, item_id):
    """
    Update a specific knowledge item.

    Path params:
    - knowledge_type: The type of knowledge item
    - item_id: The ID of the item to update

    Query params:
    - worker_group: Required. The worker group/fleet.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'

    Body: JSON object with the updated item data
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    if knowledge_type not in KNOWLEDGE_TYPE_PATHS:
        return jsonify({'error': f'Unknown knowledge type: {knowledge_type}'}), 400

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    try:
        validate_api_type(api_type)
        validate_worker_group(worker_group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    token = app_config['token']
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    api_path = f"{KNOWLEDGE_TYPE_PATHS[knowledge_type]}/{item_id}"
    url = build_api_url(api_type, worker_group, path=api_path)

    debug_log(f"\n[API] PATCH {sanitize_url_for_logging(url)}")
    debug_log(f"   [BODY] {json.dumps(data)[:500]}...")

    try:
        response = requests.patch(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        result = response.json()

        return jsonify({
            'success': True,
            'item': result,
            'knowledge_type': knowledge_type,
            'item_id': item_id
        })
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', str(e))
            except:
                pass
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), e.response.status_code if e.response else 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/knowledge/<knowledge_type>/<item_id>', methods=['DELETE'])
def delete_knowledge_item(knowledge_type, item_id):
    """
    Delete a specific knowledge item.

    Path params:
    - knowledge_type: The type of knowledge item
    - item_id: The ID of the item to delete

    Query params:
    - worker_group: Required. The worker group/fleet.
    - api_type: 'stream', 'edge', or 'search'. Default: 'stream'
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    if knowledge_type not in KNOWLEDGE_TYPE_PATHS:
        return jsonify({'error': f'Unknown knowledge type: {knowledge_type}'}), 400

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    try:
        validate_api_type(api_type)
        validate_worker_group(worker_group)
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    api_path = f"{KNOWLEDGE_TYPE_PATHS[knowledge_type]}/{item_id}"
    url = build_api_url(api_type, worker_group, path=api_path)

    debug_log(f"\n[API] DELETE {sanitize_url_for_logging(url)}")

    try:
        response = requests.delete(url, headers=headers, timeout=30)
        response.raise_for_status()

        return jsonify({
            'success': True,
            'message': f'Successfully deleted {knowledge_type} {item_id}',
            'knowledge_type': knowledge_type,
            'item_id': item_id
        })
    except requests.exceptions.HTTPError as e:
        error_msg = str(e)
        if e.response is not None:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('message', str(e))
            except:
                pass
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), e.response.status_code if e.response else 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# PACK LOOKUP ENDPOINTS
# =============================================================================

@app.route('/api/packs', methods=['GET'])
def list_packs():
    """
    List packs that contain lookup files in a worker group.

    For Stream/Edge, checks each pack for lookups by exporting and parsing
    the .crbl file. Only returns packs that have at least one lookup file.

    This is a synchronous endpoint - for progress updates, use /api/packs/scan.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    debug_log(f"\n[PACKS] Listing packs with lookups in {worker_group} ({api_type})")

    packs_url = build_api_url(api_type, worker_group, path='/packs')
    debug_log(f"   [INFO] URL: {packs_url}")

    try:
        response = requests.get(packs_url, headers=headers, timeout=15)
        if response.status_code != 200:
            debug_log(f"   [WARNING] Failed to list packs: HTTP {response.status_code}")
            return jsonify({'packs': [], 'error': f'HTTP {response.status_code}'})

        data = response.json()
        packs = data.get('items', [])
        debug_log(f"   [INFO] Found {len(packs)} total pack(s), checking for lookups...")

        # For Stream/Edge, check each pack for lookups by exporting .crbl
        # The /p/{pack_id}/system/lookups API can return false positives
        pack_list = []
        for pack in packs:
            pack_id = pack.get('id')
            if not pack_id:
                continue

            # Check if pack has lookups by exporting and checking for lookup files
            export_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}/export', query='mode=merge')
            try:
                export_response = requests.get(export_url, headers=headers, timeout=30, stream=True)
                if export_response.status_code == 200:
                    crbl_content = export_response.content
                    lookup_count = count_lookups_in_crbl(crbl_content)
                    if lookup_count > 0:
                        pack_list.append({
                            'id': pack_id,
                            'displayName': pack.get('displayName', pack_id),
                            'version': pack.get('version', ''),
                            'description': pack.get('description', ''),
                            'lookupCount': lookup_count
                        })
                        debug_log(f"      [OK] {pack_id}: {lookup_count} lookup(s)")
                    else:
                        debug_log(f"      [SKIP] {pack_id}: no lookups")
                else:
                    debug_log(f"      [SKIP] {pack_id}: HTTP {export_response.status_code}")
            except Exception as e:
                debug_log(f"      [SKIP] {pack_id}: {str(e)}")

        debug_log(f"   [OK] Found {len(pack_list)} pack(s) containing lookups")
        return jsonify({'packs': pack_list})

    except Exception as e:
        debug_log(f"   [ERROR] Failed to list packs: {str(e)}")
        return jsonify({'packs': [], 'error': str(e)})


@app.route('/api/packs/scan', methods=['GET'])
def scan_packs_stream():
    """Stream pack scanning progress via Server-Sent Events.

    Returns progress updates as SSE events while scanning each pack for lookups.
    Events:
    - progress: { current, total, currentPack } - Progress update
    - pack: { id, displayName, version, description, lookupCount } - Pack with lookups found
    - complete: { totalPacks } - Scanning complete
    - error: { message } - Error occurred
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    def generate():
        token = app_config['token']
        headers = {"Authorization": f"Bearer {token}"}

        debug_log(f"\n[PACKS] Streaming pack scan for {worker_group} ({api_type})")

        packs_url = build_api_url(api_type, worker_group, path='/packs')
        debug_log(f"   [INFO] URL: {packs_url}")

        try:
            response = requests.get(packs_url, headers=headers, timeout=15)
            if response.status_code != 200:
                yield f"data: {json.dumps({'type': 'error', 'message': f'HTTP {response.status_code}'})}\n\n"
                return

            data = response.json()
            packs = data.get('items', [])
            total = len(packs)
            debug_log(f"   [INFO] Found {total} total pack(s), scanning for lookups...")

            # Send initial progress
            yield f"data: {json.dumps({'type': 'progress', 'current': 0, 'total': total, 'currentPack': ''})}\n\n"

            packs_with_lookups = 0
            for i, pack in enumerate(packs):
                pack_id = pack.get('id')
                if not pack_id:
                    continue

                # Send progress update
                yield f"data: {json.dumps({'type': 'progress', 'current': i + 1, 'total': total, 'currentPack': pack_id})}\n\n"

                # Check if pack has lookups by exporting and checking for lookup files
                # The /p/{pack_id}/system/lookups API can return false positives
                # so we use the .crbl export method which is more accurate
                export_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}/export', query='mode=merge')
                debug_log(f"      [DEBUG] Checking pack {pack_id}: {export_url}")
                try:
                    export_response = requests.get(export_url, headers=headers, timeout=30, stream=True)
                    if export_response.status_code == 200:
                        crbl_content = export_response.content
                        # Quick check for lookups in the tarball
                        lookup_count = count_lookups_in_crbl(crbl_content)
                        debug_log(f"      [DEBUG] {pack_id}: {lookup_count} lookup file(s) in .crbl")
                        if lookup_count > 0:
                            pack_info = {
                                'type': 'pack',
                                'id': pack_id,
                                'displayName': pack.get('displayName', pack_id),
                                'version': pack.get('version', ''),
                                'description': pack.get('description', ''),
                                'lookupCount': lookup_count
                            }
                            yield f"data: {json.dumps(pack_info)}\n\n"
                            packs_with_lookups += 1
                            debug_log(f"      [OK] {pack_id}: {lookup_count} lookup(s)")
                        else:
                            debug_log(f"      [SKIP] {pack_id}: no lookups")
                    else:
                        debug_log(f"      [SKIP] {pack_id}: HTTP {lookup_response.status_code}")
                except Exception as e:
                    debug_log(f"      [SKIP] {pack_id}: {str(e)}")

            # Send completion event
            yield f"data: {json.dumps({'type': 'complete', 'totalPacks': packs_with_lookups})}\n\n"
            debug_log(f"   [OK] Found {packs_with_lookups} pack(s) containing lookups")

        except Exception as e:
            debug_log(f"   [ERROR] Failed to scan packs: {str(e)}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no'
    })


@app.route('/api/packs/<pack_id>/lookups', methods=['GET'])
def get_single_pack_lookups(pack_id):
    """Get lookup files from a single pack by exporting and parsing its .crbl file.

    This allows the frontend to load pack lookups one at a time with progress indication.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    if api_type == 'search':
        return jsonify({'lookups': [], 'message': 'Search API already includes pack lookups in /system/lookups'})

    token = app_config['token']
    headers = {"Authorization": f"Bearer {token}"}

    debug_log(f"\n[PACK-EXPORT] Exporting pack '{pack_id}' from {worker_group} ({api_type})")

    # Export the pack as .crbl file
    export_url = build_api_url(api_type, worker_group, path=f'/packs/{pack_id}/export', query='mode=merge')
    debug_log(f"   [EXPORT] {export_url}")

    try:
        export_response = requests.get(export_url, headers=headers, timeout=60, stream=True)
        if export_response.status_code != 200:
            debug_log(f"   [WARNING] Failed to export pack {pack_id}: HTTP {export_response.status_code}")
            return jsonify({'lookups': [], 'error': f'Failed to export pack: HTTP {export_response.status_code}'})

        # The .crbl file is a gzipped tarball
        crbl_content = export_response.content
        debug_log(f"   [OK] Downloaded {len(crbl_content)} bytes")

        # Extract lookup files from the tarball
        lookups_found = extract_lookups_from_crbl(crbl_content, pack_id)
        debug_log(f"   [OK] Found {len(lookups_found)} lookup(s) in pack")

        pack_lookups = []
        for lookup in lookups_found:
            # Determine if lookup is memory-based from mode in lookups.yml
            mode = lookup.get('mode', 'memory').lower()
            is_memory = mode != 'disk'
            pack_lookups.append({
                'id': f"{pack_id}.{lookup['filename']}",  # Use pack prefix format
                'filename': lookup['filename'],
                'size': lookup.get('size', 0),
                'inMemory': is_memory,
                'pack': pack_id,
                'packPath': lookup.get('path', '')
            })

        return jsonify({'lookups': pack_lookups, 'packId': pack_id})

    except requests.exceptions.Timeout:
        debug_log(f"   [WARNING] Timeout exporting pack {pack_id}")
        return jsonify({'lookups': [], 'error': 'Timeout exporting pack'})
    except Exception as e:
        debug_log(f"   [ERROR] Error processing pack {pack_id}: {str(e)}")
        return jsonify({'lookups': [], 'error': str(e)})


@app.route('/api/pack-lookups', methods=['GET'])
def get_pack_lookups():
    """Get lookup files from ALL packs in Stream/Edge by exporting and parsing .crbl files.

    This endpoint exports all packs at once. For selective loading with progress,
    use /api/packs to list packs, then /api/packs/<pack_id>/lookups for each.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    # This is only needed for Stream/Edge - Search already shows pack lookups in /system/lookups
    if api_type == 'search':
        return jsonify({'lookups': [], 'message': 'Search API already includes pack lookups in /system/lookups'})

    token = app_config['token']

    try:
        pack_lookups = fetch_pack_lookups_internal(worker_group, api_type, token)
        return jsonify({'lookups': pack_lookups})
    except Exception as e:
        debug_log(f"   [ERROR] Failed to get pack lookups: {str(e)}")
        return jsonify({'lookups': [], 'error': str(e)})


def count_lookups_in_crbl(crbl_content):
    """Quickly count lookup files in a .crbl (gzipped tarball) file.

    This is a fast check to determine if a pack contains any lookups,
    without extracting all the details.

    Returns: int count of lookup files found
    """
    count = 0

    def count_in_tar(tar):
        nonlocal count
        for member in tar.getmembers():
            path_parts = member.name.split('/')
            if member.isfile() and 'lookups' in path_parts:
                filename = path_parts[-1]
                if filename.endswith(('.csv', '.csv.gz', '.mmdb', '.json', '.gz')):
                    count += 1

    try:
        with io.BytesIO(crbl_content) as crbl_io:
            with tarfile.open(fileobj=crbl_io, mode='r:gz') as tar:
                count_in_tar(tar)
    except tarfile.TarError:
        try:
            with io.BytesIO(crbl_content) as crbl_io:
                with gzip.GzipFile(fileobj=crbl_io) as gz:
                    decompressed = gz.read()
                    with io.BytesIO(decompressed) as tar_io:
                        with tarfile.open(fileobj=tar_io, mode='r:') as tar:
                            count_in_tar(tar)
        except Exception:
            pass
    except Exception:
        pass

    return count


def extract_lookups_from_crbl(crbl_content, pack_id):
    """Extract lookup file information from a .crbl (gzipped tarball) file.

    Pack structure typically contains lookups in:
    - lookups/ directory (for lookup files)
    - default/lookups/ or local/lookups/ directories

    Also reads lookups.yml to determine mode (memory/disk) for each lookup.

    Returns list of dicts with 'filename', 'size', 'path', 'mode' keys.
    """
    lookups = []
    lookup_configs = {}  # filename -> mode mapping from lookups.yml

    def parse_lookups_yml(content):
        """Parse lookups.yml to extract mode settings for each lookup."""
        configs = {}
        try:
            # Simple YAML-like parsing for lookups.yml
            # Format is typically:
            # filename.csv:
            #   mode: memory
            # or
            # filename.csv:
            #   mode: disk
            lines = content.decode('utf-8', errors='ignore').split('\n')
            current_file = None
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # Check for filename entry (ends with : and no leading spaces means top-level)
                if not line.startswith(' ') and not line.startswith('\t') and stripped.endswith(':'):
                    current_file = stripped[:-1]  # Remove trailing colon
                elif current_file and 'mode:' in stripped.lower():
                    mode_value = stripped.split(':', 1)[1].strip().lower()
                    configs[current_file] = mode_value
                    debug_log(f"            [CONFIG] {current_file}: mode={mode_value}")
        except Exception as e:
            debug_log(f"         [WARNING] Failed to parse lookups.yml: {e}")
        return configs

    def process_tar(tar):
        nonlocal lookup_configs
        # First pass: find and parse lookups.yml
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('lookups.yml'):
                try:
                    f = tar.extractfile(member)
                    if f:
                        lookup_configs = parse_lookups_yml(f.read())
                        debug_log(f"         [CONFIG] Found lookups.yml with {len(lookup_configs)} entries")
                except Exception as e:
                    debug_log(f"         [WARNING] Could not read lookups.yml: {e}")

        # Second pass: find lookup files
        for member in tar.getmembers():
            path_parts = member.name.split('/')
            if member.isfile() and 'lookups' in path_parts:
                filename = path_parts[-1]
                if filename.endswith(('.csv', '.csv.gz', '.mmdb', '.json', '.gz')):
                    # Check if we have mode info from lookups.yml
                    mode = lookup_configs.get(filename, 'memory')  # Default to memory if not specified
                    lookups.append({
                        'filename': filename,
                        'size': member.size,
                        'path': member.name,
                        'mode': mode
                    })
                    debug_log(f"         [LOOKUP] {member.name} ({member.size} bytes, mode={mode})")

    try:
        # .crbl files are gzipped tarballs
        with io.BytesIO(crbl_content) as crbl_io:
            with tarfile.open(fileobj=crbl_io, mode='r:gz') as tar:
                process_tar(tar)

    except tarfile.TarError as e:
        debug_log(f"      [WARNING] Failed to parse crbl as tarball: {str(e)}")
        # Try as plain gzip
        try:
            with io.BytesIO(crbl_content) as crbl_io:
                with gzip.GzipFile(fileobj=crbl_io) as gz:
                    decompressed = gz.read()
                    with io.BytesIO(decompressed) as tar_io:
                        with tarfile.open(fileobj=tar_io, mode='r:') as tar:
                            process_tar(tar)
        except Exception as e2:
            debug_log(f"      [WARNING] Failed alternate extraction: {str(e2)}")
    except Exception as e:
        debug_log(f"      [WARNING] Error extracting lookups: {str(e)}")

    return lookups


def extract_lookup_content_from_crbl(crbl_content, lookup_filename):
    """Extract the actual content of a specific lookup file from a .crbl (gzipped tarball).

    Args:
        crbl_content: The raw bytes of the .crbl file
        lookup_filename: The name of the lookup file to extract (e.g., 'asa_drops.csv')

    Returns:
        The file content as bytes, or None if not found.
    """
    def find_in_tar(tar):
        for member in tar.getmembers():
            path_parts = member.name.split('/')
            if member.isfile() and 'lookups' in path_parts:
                filename = path_parts[-1]
                if filename == lookup_filename:
                    debug_log(f"      [EXTRACT] Found {member.name}")
                    f = tar.extractfile(member)
                    if f:
                        return f.read()
        return None

    try:
        # .crbl files are gzipped tarballs
        with io.BytesIO(crbl_content) as crbl_io:
            with tarfile.open(fileobj=crbl_io, mode='r:gz') as tar:
                content = find_in_tar(tar)
                if content:
                    return content
    except tarfile.TarError as e:
        debug_log(f"      [WARNING] Failed to parse crbl as tarball: {str(e)}")
        # Try as plain gzip then tar
        try:
            import gzip
            with io.BytesIO(crbl_content) as gz_io:
                with gzip.GzipFile(fileobj=gz_io, mode='rb') as gz:
                    decompressed = gz.read()
                    with io.BytesIO(decompressed) as tar_io:
                        with tarfile.open(fileobj=tar_io, mode='r:') as tar:
                            content = find_in_tar(tar)
                            if content:
                                return content
        except Exception as e2:
            debug_log(f"      [WARNING] Failed alternate extraction: {str(e2)}")
    except Exception as e:
        debug_log(f"      [WARNING] Error extracting lookup content: {str(e)}")

    return None


def parse_pack_lookup(lookup_filename, pack_hint=None):
    """Parse a lookup filename to determine if it's a pack lookup.
    Returns (pack_name, actual_filename) if pack lookup, or (None, lookup_filename) if system lookup.
    Pack lookups have format: pack_name.filename.ext (e.g., cribl-search.operators.csv)

    Args:
        lookup_filename: The full lookup filename (may include pack prefix)
        pack_hint: Optional pack name if already known (from frontend)
    """
    # If pack hint is provided, use it directly
    if pack_hint:
        # The filename should start with pack_hint followed by a dot
        prefix = f"{pack_hint}."
        if lookup_filename.startswith(prefix):
            actual_filename = lookup_filename[len(prefix):]
            return pack_hint, actual_filename
        return pack_hint, lookup_filename

    parts = lookup_filename.split('.')
    # Need at least 3 parts: pack_name, filename, extension
    if len(parts) >= 3:
        potential_pack = parts[0]
        # Pack name detection - must meet stricter criteria:
        # 1. Contains hyphen (e.g., cribl-search, cribl-cisco-asa-cleanup) - most common pattern
        # 2. Known vendor prefixes that are commonly used as pack prefixes
        # 3. Underscore alone is NOT enough (e.g., pkg_vuln.csv.gz is not a pack)
        #    - Only treat as pack if it also starts with a known vendor prefix
        known_pack_prefixes = ['cribl', 'okta', 'aws', 'azure', 'gcp', 'splunk', 'crowdstrike', 'palo', 'cisco']

        is_pack_name = (
            # Hyphenated names are almost always packs (e.g., cribl-search, my-custom-pack)
            '-' in potential_pack or
            # Known vendor name as the full pack name
            potential_pack in known_pack_prefixes or
            # Underscore names only if they start with a known vendor prefix
            # e.g., okta_improbable is a pack, but pkg_vuln is not
            ('_' in potential_pack and any(potential_pack.startswith(prefix + '_') for prefix in known_pack_prefixes))
        )
        if is_pack_name:
            pack_name = parts[0]
            actual_filename = '.'.join(parts[1:])
            return pack_name, actual_filename
    return None, lookup_filename

@app.route('/api/lookups/<worker_group>/<lookup_filename>/content', methods=['GET'])
def get_lookup_content(worker_group, lookup_filename):
    """Get the raw content of a lookup file (system or pack)"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']

    debug_log(f"\n[FETCH] Getting content for {lookup_filename} from {worker_group} ({api_type})")

    # Check if this is a pack lookup
    pack_name, actual_filename = parse_pack_lookup(lookup_filename)

    try:
        headers = {"Authorization": f"Bearer {token}"}

        if pack_name and api_type in ['stream', 'edge']:
            # Pack lookup - use /system/lookups/ with prefixed name (pack.filename format)
            # The API expects the full prefixed name like "cribl-cisco-asa-cleanup.asa_parsing.csv"
            download_url = build_api_url(api_type, worker_group,
                                         path=f'/system/lookups/{lookup_filename}/content',
                                         query='raw=1')
            debug_log(f"   [PACK] Pack: {pack_name}, File: {actual_filename} (using prefixed name: {lookup_filename})")
        else:
            # System lookup
            download_url = build_api_url(api_type, worker_group,
                                         path=f'/system/lookups/{lookup_filename}/content',
                                         query='raw=1')

        debug_log(f"   Download URL: {download_url}")

        response = requests.get(download_url, headers=headers, timeout=30)
        response.raise_for_status()

        # Return the raw content as text
        return response.text, 200, {'Content-Type': 'text/plain'}

    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/lookups/<worker_group>/<lookup_id>', methods=['GET'])
def get_lookup_details(worker_group, lookup_id):
    """Get lookup details including inMemory flag (system or pack)"""
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']

    debug_log(f"\n[FETCH] Getting details for {lookup_id} from {worker_group} ({api_type})")

    # Check if this is a pack lookup
    pack_name, actual_filename = parse_pack_lookup(lookup_id)

    try:
        headers = {"Authorization": f"Bearer {token}"}

        if pack_name and api_type in ['stream', 'edge']:
            # Pack lookup - use /system/lookups/ with prefixed name
            lookup_url = build_api_url(api_type, worker_group,
                                       path=f'/system/lookups/{lookup_id}')
            debug_log(f"   [PACK] Pack: {pack_name}, File: {actual_filename} (using prefixed name: {lookup_id})")
        else:
            # System lookup
            lookup_url = build_api_url(api_type, worker_group,
                                       path=f'/system/lookups/{lookup_id}')

        debug_log(f"   Lookup URL: {lookup_url}")

        response = requests.get(lookup_url, headers=headers, timeout=10)
        response.raise_for_status()

        lookup_data = response.json()
        return jsonify({'success': True, 'lookup': lookup_data}), 200

    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# TRANSFER AND VERSION CONTROL ENDPOINTS
# =============================================================================

@app.route('/api/transfer', methods=['POST'])
def transfer_lookup():
    """
    Transfer a lookup file from source to destination worker group.

    This is the main endpoint for copying lookup files between worker groups.
    It handles:
    - Downloading content from source (or using edited content if provided)
    - Uploading to destination
    - Creating/updating the lookup definition
    - Automatic commit of the transferred file
    - Type conversion (disk/memory) including delete+recreate if needed

    Request body:
    - source_group: Source worker group name
    - target_group: Destination worker group name
    - lookup_filename: Name of the lookup file
    - source_api_type: 'stream', 'edge', or 'search'
    - target_api_type: 'stream', 'edge', or 'search'
    - content: Optional - edited content to use instead of downloading
    - target_filename: Optional - rename the file on transfer
    - lookup_type: 'file' (disk) or 'memory'

    Returns:
    - success: Boolean indicating transfer success
    - committed: Whether auto-commit succeeded
    - requiresDeploy: Whether deploy is needed (for Stream/Edge)
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    source_group = data.get('source_group')
    target_group = data.get('target_group')
    lookup_filename = data.get('lookup_filename')
    source_api_type = data.get('source_api_type', 'stream')
    target_api_type = data.get('target_api_type', 'stream')
    edited_content = data.get('content')  # Optional edited content
    target_filename_override = data.get('target_filename')  # Optional renamed file
    lookup_type = data.get('lookup_type', 'file')  # 'file' or 'memory'
    
    if not all([source_group, target_group, lookup_filename]):
        return jsonify({'error': 'Missing required parameters'}), 400
    
    # SECURITY: Validate all inputs
    try:
        source_group = validate_worker_group(source_group)
        target_group = validate_worker_group(target_group)
        lookup_filename = validate_filename(lookup_filename)
        source_api_type = validate_api_type(source_api_type)
        target_api_type = validate_api_type(target_api_type)
        if target_filename_override:
            target_filename_override = validate_filename(target_filename_override)
        if lookup_type not in ['file', 'memory']:
            return jsonify({'error': 'Invalid lookup_type: must be file or memory'}), 400
    except ValueError as e:
        debug_log(f"   [SECURITY] Input validation failed: {str(e)}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    
    debug_log(f"\n[TRANSFER] Lookup type: {lookup_type}-based")
    
    # Strip pack prefix for Cribl Pack lookups
    # Format: pack-name.lookup-name.csv -> lookup-name.csv
    def strip_pack_prefix(filename):
        """Remove pack prefix from filename if it has more than one period"""
        parts = filename.split('.')
        # If more than 2 parts (e.g., pack.name.csv has 3), it's from a pack
        if len(parts) > 2:
            # Remove the first part (pack name) and rejoin
            return '.'.join(parts[1:])
        return filename
    
    # Use target filename override if provided, otherwise strip pack prefix
    target_filename = target_filename_override if target_filename_override else strip_pack_prefix(lookup_filename)
    
    debug_log(f"\n[TRANSFER] Transfer lookup:")
    debug_log(f"   Source: {lookup_filename}")
    if target_filename != lookup_filename:
        debug_log(f"   Target: {target_filename} (renamed/stripped)" if target_filename_override else f"   Target: {target_filename} (stripped pack prefix)")
    else:
        debug_log(f"   Target: {target_filename}")
    if edited_content:
        debug_log(f"   [INFO] Using edited content ({len(edited_content)} chars)")
    
    organization_id = app_config['organization_id']
    token = app_config['token']
    
    try:
        # Check if we have edited content or need to download
        if edited_content:
            # Use the edited content directly
            debug_log(f"   [STEP 1] Using provided edited content...")
            content = edited_content.encode('utf-8')
            debug_log(f"   [OK] Using {len(content)} bytes of edited content")
        else:
            # Step 1: Download from source
            debug_log(f"   [STEP 1] Downloading from source...")

            # Check if this is a pack lookup
            pack_name, actual_filename = parse_pack_lookup(lookup_filename)

            if pack_name and source_api_type in ['stream', 'edge']:
                # Pack lookup - use /system/lookups/ with prefixed name (pack.filename format)
                # The API expects the full prefixed name like "cribl-cisco-asa-cleanup.asa_parsing.csv"
                download_url = build_api_url(source_api_type, source_group,
                                             path=f'/system/lookups/{lookup_filename}/content',
                                             query='raw=1')
                debug_log(f"   [PACK] Downloading from pack: {pack_name}, file: {actual_filename} (using prefixed name)")
            else:
                # System lookup
                download_url = build_api_url(source_api_type, source_group,
                                             path=f'/system/lookups/{lookup_filename}/content',
                                             query='raw=1')

            debug_log(f"   Download URL: {download_url}")
            headers = {"Authorization": f"Bearer {token}"}
            
            # Retry logic for downloads (large files can timeout)
            max_retries = 3
            retry_delay = 2
            response = None
            
            for attempt in range(1, max_retries + 1):
                try:
                    debug_log(f"   [DOWNLOAD] Attempt {attempt}/{max_retries}...")
                    # Increased timeout to 120 seconds for large files, stream the response
                    response = requests.get(download_url, headers=headers, timeout=120, stream=True)
                    response.raise_for_status()
                    
                    # Download with progress indication
                    content = b''
                    total_size = int(response.headers.get('content-length', 0))
                    if total_size > 0:
                        debug_log(f"   [INFO] File size: {total_size / 1024:.2f} KB")
                    
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            content += chunk
                    
                    debug_log(f"   [OK] Downloaded {len(content)} bytes")
                    break  # Success, exit retry loop
                    
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                    if attempt < max_retries:
                        debug_log(f"   [WARN] Connection issue: {type(e).__name__}, retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                    else:
                        debug_log(f"   [ERROR] Failed after {max_retries} attempts")
                        raise
            
            if response is None:
                raise Exception("Failed to download file after all retries")
        
        # Save to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(target_filename).suffix) as tmp_file:
            tmp_file.write(content)
            tmp_filename = tmp_file.name
        
        # Step 2: Upload to target (use target filename)
        debug_log(f"   [STEP 2] Uploading to target as {target_filename}...")
        # Set content type based on file extension
        if target_filename.endswith('.csv'):
            content_type = "text/csv"
        elif target_filename.endswith('.mmdb'):
            content_type = "application/octet-stream"
        elif target_filename.endswith('.gz'):
            content_type = "application/gzip"
        elif target_filename.endswith('.json'):
            content_type = "application/json"
        else:
            content_type = "application/octet-stream"  # Default for binary files
        
        upload_url = build_api_url(target_api_type, target_group, 
                                   path='/system/lookups', 
                                   query=f'filename={target_filename}')
        
        debug_log(f"   Upload URL: {upload_url}")
        
        upload_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type
        }
        
        # Retry logic for uploads
        max_retries = 3
        retry_delay = 2
        upload_success = False
        
        for attempt in range(1, max_retries + 1):
            try:
                debug_log(f"   [UPLOAD] Attempt {attempt}/{max_retries}...")
                with open(tmp_filename, 'rb') as f:
                    response = requests.put(upload_url, headers=upload_headers, data=f, timeout=120)
                response.raise_for_status()
                upload_success = True
                break  # Success, exit retry loop
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < max_retries:
                    debug_log(f"   [WARN] Connection issue: {type(e).__name__}, retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    debug_log(f"   [ERROR] Failed after {max_retries} attempts")
                    raise
        
        if not upload_success:
            raise Exception("Failed to upload file after all retries")
        
        temp_file_response = response.json()
        temp_file_name = temp_file_response.get('filename')
        
        debug_log(f"   [OK] Uploaded to temp file: {temp_file_name}")
        
        # Step 3: Try to create the lookup (will update if exists)
        debug_log(f"   [STEP 3] Creating/updating lookup...")
        lookup_url = build_api_url(target_api_type, target_group, path='/system/lookups')
        
        # Try POST first (create new)
        payload = {
            "id": target_filename,  # Full filename WITH extension (Cribl uses this as the ID)
            "fileInfo": {"filename": temp_file_name}
        }
        
        # Set mode based on lookup type (Cribl uses mode: "disk" for disk-based, absent/memory for memory-based)
        if lookup_type == 'memory':
            # Don't set mode field for memory-based (or set to "memory")
            # payload["mode"] = "memory"  # Optional - can be omitted
            debug_log(f"   [INFO] Creating memory-based lookup (mode not set)")
        else:
            payload["mode"] = "disk"
            debug_log(f"   [INFO] Creating disk-based lookup (mode=disk)")
        
        lookup_headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        debug_log(f"   Lookup ID: {target_filename}")
        debug_log(f"   Lookup URL: {lookup_url}")
        
        # Try POST, if it fails with 409 (conflict) or 500 (already exists), try PATCH
        lookup_exists = False
        try:
            response = requests.post(lookup_url, headers=lookup_headers, json=payload, timeout=10)
            response.raise_for_status()
            debug_log(f"   [OK] Created new lookup")
        except requests.exceptions.HTTPError as e:
            # Check if lookup already exists (409 conflict or 500 with "already exists" message)
            if e.response.status_code == 409:
                lookup_exists = True
            elif e.response.status_code == 500:
                try:
                    error_data = e.response.json()
                    error_msg = error_data.get('message', '').lower()
                    if 'already exists' in error_msg:
                        lookup_exists = True
                except:
                    pass
            
            if lookup_exists:
                # Lookup exists, update it
                debug_log(f"   [INFO] Lookup exists, updating...")
                # PATCH URL and payload both need FULL filename with extension
                lookup_url_patch = f"{lookup_url}/{target_filename}"
                # Update payload to include full filename in id field for PATCH
                patch_payload = {
                    "id": target_filename,  # Full filename WITH extension for PATCH
                    "fileInfo": {"filename": temp_file_name}
                }
                # Set mode based on lookup type (same as POST)
                if lookup_type == 'memory':
                    # Don't set mode field for memory-based
                    debug_log(f"   [INFO] Updating to memory-based lookup (mode not set)")
                else:
                    patch_payload["mode"] = "disk"
                    debug_log(f"   [INFO] Updating to disk-based lookup (mode=disk)")
                
                try:
                    response = requests.patch(lookup_url_patch, headers=lookup_headers, json=patch_payload, timeout=10)
                    response.raise_for_status()
                    debug_log(f"   [OK] Updated existing lookup")
                except requests.exceptions.HTTPError as patch_error:
                    # Check if it's a mode change error
                    mode_change_handled = False
                    if patch_error.response.status_code == 400:
                        try:
                            error_data = patch_error.response.json()
                            error_msg = error_data.get('message', '')
                            if 'mode can not be changed' in error_msg.lower():
                                debug_log(f"   [INFO] Mode change detected - auto-deleting and re-creating lookup")

                                # Delete the existing lookup
                                delete_url = build_api_url(target_api_type, target_group, path=f'/system/lookups/{target_filename}')
                                debug_log(f"   [DELETE] Deleting existing lookup: {delete_url}")

                                delete_response = requests.delete(delete_url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
                                delete_response.raise_for_status()
                                debug_log(f"   [OK] Deleted existing lookup")

                                # Now retry the POST to create with new type
                                debug_log(f"   [RETRY] Re-creating lookup with new type...")
                                retry_response = requests.post(lookup_url, headers=lookup_headers, json=payload, timeout=10)
                                retry_response.raise_for_status()
                                debug_log(f"   [OK] Re-created lookup with new type")
                                mode_change_handled = True
                        except requests.exceptions.HTTPError as delete_error:
                            debug_log(f"   [ERROR] Failed to delete/recreate: {delete_error}")
                            return jsonify({
                                'success': False,
                                'error': f'Failed to change lookup type for "{target_filename}"',
                                'message': f'Could not delete and recreate lookup: {str(delete_error)}'
                            }), 400
                        except Exception as mode_error:
                            debug_log(f"   [ERROR] Mode change handling failed: {mode_error}")

                    # Re-raise if not a mode change error or mode change wasn't handled
                    if not mode_change_handled:
                        raise patch_error
            else:
                # Some other error
                debug_log(f"   [ERROR] Error creating lookup: {e.response.status_code} - {e.response.text}")
                raise
        
        # Transfer complete - file uploaded successfully
        # Now commit ONLY this file (partial commit)
        debug_log(f"   [OK] Lookup file uploaded successfully!")
        debug_log(f"   [STEP 4] Committing only the transferred lookup file...")
        
        try:
            # Build the file paths that need to be committed
            # Cribl stores lookups in groups/{group}/data/lookups/
            lookup_csv_path = f"groups/{target_group}/data/lookups/{target_filename}"
            lookup_yml_path = f"groups/{target_group}/data/lookups/{Path(target_filename).stem}.yml"
            
            commit_url = build_api_url(target_api_type, target_group, path='/version/commit')
            commit_payload = {
                "message": f"{COMMIT_PREFIX} Transfer lookup: {target_filename}",
                "group": target_group,
                "files": [lookup_csv_path, lookup_yml_path]
            }
            
            commit_headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
            
            debug_log(f"   Commit URL: {commit_url}")
            debug_log(f"   Committing files: {commit_payload['files']}")
            
            commit_response = requests.post(commit_url, headers=commit_headers, json=commit_payload, timeout=10)
            commit_response.raise_for_status()
            commit_data = commit_response.json()
            
            debug_log(f"   [DATA] Commit response: {json.dumps(commit_data, indent=2)}")
            
            # Extract commit ID
            commit_id = None
            if 'items' in commit_data and isinstance(commit_data['items'], list) and len(commit_data['items']) > 0:
                first_item = commit_data['items'][0]
                commit_id = (first_item.get('commit') or 
                            first_item.get('hash') or
                            first_item.get('version'))
            
            if not commit_id:
                commit_id = commit_data.get('commit') or commit_data.get('hash', 'unknown')
            
            debug_log(f"   [OK] Committed lookup file: {commit_id}")

            # Store the commit ID for the deploy endpoint to use for partial deployment
            # Use a dict to support bulk transfers to multiple targets
            if 'transfer_commits' not in app_config:
                app_config['transfer_commits'] = {}

            # Key by "group:api_type" to support multiple targets
            commit_key = f"{target_group}:{target_api_type}"
            app_config['transfer_commits'][commit_key] = {
                'commit_id': commit_id,
                'group': target_group,
                'api_type': target_api_type,
                'files': [lookup_csv_path, lookup_yml_path]
            }

            # Also keep the legacy single values for backwards compatibility
            app_config['last_transfer_commit_id'] = commit_id
            app_config['last_transfer_group'] = target_group
            app_config['last_transfer_api_type'] = target_api_type
            app_config['last_transfer_files'] = [lookup_csv_path, lookup_yml_path]

            debug_log(f"   [INFO] Use Deploy button to push to workers")
            
        except Exception as commit_error:
            debug_log(f"   [WARN] Warning: Commit failed: {str(commit_error)}")
            debug_log(f"   [WARN] File uploaded but not committed. Use Commit button to commit manually.")
            # Don't fail the whole transfer if commit fails - file is already uploaded
        
        # Cleanup
        os.unlink(tmp_filename)
        
        success_message = f'Successfully transferred {lookup_filename}'
        if target_filename != lookup_filename:
            success_message += f' as {target_filename}'
        success_message += f' from {source_group} to {target_group} and committed'
        
        return jsonify({
            'success': True,
            'message': success_message,
            'committed': True,
            'requiresDeploy': True,
            'commit_id': commit_id if 'commit_id' in locals() else None,
            'target_group': target_group,
            'target_api_type': target_api_type
        })
        
    except requests.exceptions.HTTPError as e:
        # HTTP error - log the response details
        error_msg = f"{e.response.status_code} {e.response.reason}"
        try:
            error_details = e.response.json()
            error_msg += f": {error_details}"
            debug_log(f"   [ERROR] HTTP Error {error_msg}")
        except:
            error_msg += f": {e.response.text}"
            debug_log(f"   [ERROR] HTTP Error {error_msg}")
        
        # Cleanup on error
        try:
            if 'tmp_filename' in locals():
                os.unlink(tmp_filename)
        except:
            pass
        return jsonify({'error': error_msg}), 500
        
    except Exception as e:
        # Other error
        error_msg = str(e)
        debug_log(f"   [ERROR] Error: {error_msg}")
        
        # Cleanup on error
        try:
            if 'tmp_filename' in locals():
                os.unlink(tmp_filename)
        except:
            pass
        return jsonify({'error': error_msg}), 500

@app.route('/api/commit', methods=['POST'])
def commit_changes():
    """
    Commit all pending changes for a worker group.

    Note: This commits ALL pending changes, not just transferred lookups.
    For selective commits, the transfer endpoint does partial commits automatically.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    worker_group = data.get('worker_group')
    api_type = data.get('api_type', 'stream')
    raw_commit_message = data.get('commit_message', 'Update lookup files')
    # Add prefix if not already present
    if raw_commit_message.startswith(COMMIT_PREFIX):
        commit_message = raw_commit_message
    else:
        commit_message = f"{COMMIT_PREFIX} {raw_commit_message}"
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    
    debug_log(f"\n[COMMIT] Committing changes to {worker_group}...")
    debug_log(f"   Message: {commit_message}")
    
    try:
        # Get pending changes
        status_url = build_api_url(api_type, worker_group, path='/version')
        headers = {"Authorization": f"Bearer {token}"}
        
        status_response = requests.get(status_url, headers=headers, timeout=10)
        status_response.raise_for_status()
        status_data = status_response.json()
        
        pending_count = status_data.get('count', 0)
        debug_log(f"   Pending changes: {pending_count} files")
        
        if pending_count == 0:
            return jsonify({
                'success': True,
                'message': 'No pending changes to commit'
            })
        
        # Commit all pending changes
        commit_url = build_api_url(api_type, worker_group, path='/version/commit')
        commit_payload = {
            "message": commit_message,
            "group": worker_group
        }
        
        debug_log(f"   Commit URL: {commit_url}")
        
        response = requests.post(commit_url, headers=headers, json=commit_payload, timeout=10)
        response.raise_for_status()
        commit_data = response.json()
        
        debug_log(f"   [DATA] Commit response: {json.dumps(commit_data, indent=2)}")
        
        # Extract commit ID from response - try multiple patterns
        commit_id = None
        changes_count = 0
        
        if 'items' in commit_data and isinstance(commit_data['items'], list) and len(commit_data['items']) > 0:
            first_item = commit_data['items'][0]
            # Try multiple field names for the commit hash
            commit_id = (first_item.get('commit') or 
                        first_item.get('hash') or  # Git commit hash
                        first_item.get('version'))
            
            # Get changes count from summary if available
            if 'summary' in first_item and isinstance(first_item['summary'], dict):
                changes_count = first_item['summary'].get('changes', 0)
                debug_log(f"   [INFO] Summary: {changes_count} changes, "
                      f"{first_item['summary'].get('insertions', 0)} insertions, "
                      f"{first_item['summary'].get('deletions', 0)} deletions")
        
        if not commit_id:
            commit_id = commit_data.get('commit') or commit_data.get('hash')

        # If we still don't have a commit ID, fetch the latest committed version
        if not commit_id or commit_id == 'unknown':
            debug_log(f"   [INFO] Commit ID not in response, fetching latest committed version...")
            try:
                # Get the committed version from /version/committed endpoint
                committed_url = build_api_url(api_type, worker_group, path='/version/committed')
                committed_response = requests.get(committed_url, headers=headers, timeout=10)
                committed_response.raise_for_status()
                committed_data = committed_response.json()
                debug_log(f"   [DATA] Committed version response: {json.dumps(committed_data, indent=2)}")

                # The response should have 'commit' field with the hash
                if 'commit' in committed_data:
                    commit_id = committed_data['commit']
                    debug_log(f"   [OK] Got commit ID from /version/committed: {commit_id}")
                elif 'version' in committed_data:
                    commit_id = committed_data['version']
                    debug_log(f"   [OK] Got version from /version/committed: {commit_id}")
            except Exception as e:
                debug_log(f"   [WARN] Could not fetch committed version: {e}")

        debug_log(f"   [SUCCESS] Committed: {commit_id}")

        # Store the commit ID in transfer_commits dict for deploy to use
        if 'transfer_commits' not in app_config:
            app_config['transfer_commits'] = {}

        commit_key = f"{worker_group}:{api_type}"
        app_config['transfer_commits'][commit_key] = {
            'commit_id': commit_id,
            'group': worker_group,
            'api_type': api_type,
            'files': []
        }
        debug_log(f"   [INFO] Stored commit for deploy: {commit_key} -> {commit_id}")

        # Also store legacy values
        app_config['last_commit_id'] = commit_id
        app_config['last_commit_group'] = worker_group
        app_config['last_transfer_commit_id'] = commit_id
        app_config['last_transfer_group'] = worker_group
        app_config['last_transfer_api_type'] = api_type

        return jsonify({
            'success': True,
            'message': f'Successfully committed {changes_count or pending_count} changes',
            'commit_id': commit_id,
            'files_count': pending_count,
            'changes_count': changes_count
        })
        
    except Exception as e:
        error_msg = str(e)
        debug_log(f"   [ERROR] Commit error: {error_msg}")
        return jsonify({'error': error_msg}), 500

@app.route('/api/deploy', methods=['POST'])
def deploy_changes():
    """
    Deploy committed changes to workers in a worker group.

    This deploys ONLY the most recently transferred lookup file(s) to avoid
    accidentally deploying other team members' changes.

    The commit version is stored from the previous transfer operation.
    If no recent transfer exists for the target group, returns an error.

    Uses PATCH /api/v1/master/groups/{group}/deploy with version parameter.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    worker_group = data.get('worker_group')
    api_type = data.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    base_url = get_base_url()  # Use helper function
    
    debug_log(f"\n[DEPLOY] Deploying to {worker_group}...")

    # Look up commit ID from transfer_commits dict (supports bulk transfers)
    commit_key = f"{worker_group}:{api_type}"
    transfer_commits = app_config.get('transfer_commits', {})

    try:
        commit_version = None

        # Check the new dict-based storage first
        if commit_key in transfer_commits:
            commit_info = transfer_commits[commit_key]
            commit_version = commit_info['commit_id']
            debug_log(f"   [OK] Using commit ID from transfer: {commit_version}")
            debug_log(f"   [PARTIAL] This will deploy ONLY the transferred lookup, not other changes")
        # Fall back to legacy single value
        elif (app_config.get('last_transfer_commit_id') and
              app_config.get('last_transfer_group') == worker_group and
              app_config.get('last_transfer_api_type') == api_type):
            commit_version = app_config['last_transfer_commit_id']
            debug_log(f"   [OK] Using commit ID from legacy storage: {commit_version}")
        else:
            # No recent transfer - fetch the latest committed version from group info
            debug_log(f"   [INFO] No recent transfer found for {worker_group} ({api_type})")
            debug_log(f"   [INFO] Fetching configVersion from group info...")

            # Fetch the group info which includes configVersion
            headers = {"Authorization": f"Bearer {token}"}
            group_url = f"{base_url}/api/v1/master/groups/{worker_group}"
            debug_log(f"   [INFO] Fetching group info from: {group_url}")

            try:
                group_response = requests.get(group_url, headers=headers, timeout=10)
                group_response.raise_for_status()
                group_data = group_response.json()
                debug_log(f"   [DATA] Group info response keys: {list(group_data.keys()) if isinstance(group_data, dict) else 'not a dict'}")

                # Try to find configVersion in the response
                # Response may be wrapped in 'items' array or be direct object
                config_version = None

                if isinstance(group_data, dict):
                    # Direct object response
                    config_version = group_data.get('configVersion')
                    if not config_version and 'items' in group_data:
                        # Wrapped in items array
                        items = group_data['items']
                        if items and len(items) > 0:
                            config_version = items[0].get('configVersion')

                if config_version:
                    commit_version = config_version
                    debug_log(f"   [OK] Got configVersion: {commit_version}")
                else:
                    debug_log(f"   [ERROR] No configVersion in group info: {json.dumps(group_data, indent=2)[:500]}")
                    return jsonify({
                        'error': 'Could not determine version to deploy',
                        'details': 'No configVersion found in group info'
                    }), 400
            except Exception as e:
                debug_log(f"   [ERROR] Could not fetch group info: {e}")
                return jsonify({
                    'error': f'Could not fetch group info: {str(e)}',
                    'details': 'Failed to get /master/groups/{group}'
                }), 500
        
        # Initialize headers
        headers = {"Authorization": f"Bearer {token}"}
        
        # Deploy the commit
        # Stream uses /master/groups/{group}/deploy
        # Edge uses /master/groups/{fleet}/deploy (same pattern, fleets are treated as groups)
        deploy_url = f"{base_url}/api/v1/master/groups/{worker_group}/deploy"
        
        debug_log(f"   [INFO] Deploying to: {deploy_url}")
        debug_log(f"   [INFO] Version: {commit_version}")
        
        deploy_payload = {"version": commit_version}
        
        response = requests.patch(deploy_url, headers=headers, json=deploy_payload, timeout=10)
        response.raise_for_status()

        debug_log(f"   [SUCCESS] Deployed: {commit_version}")

        # Clear the commit from storage after successful deploy
        if commit_key in transfer_commits:
            del transfer_commits[commit_key]
            debug_log(f"   [INFO] Cleared commit for {commit_key}")

        return jsonify({
            'success': True,
            'message': f'Successfully deployed to {worker_group}',
            'version': commit_version
        })
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"HTTP {e.response.status_code}"
        try:
            error_data = e.response.json()
            error_msg += f": {error_data}"
        except:
            error_msg += f": {e.response.text[:200]}"
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500







# =============================================================================
# DELETE OPERATIONS
# =============================================================================

@app.route('/api/lookups/<worker_group>/<lookup_filename>', methods=['DELETE'])
def delete_lookup(worker_group, lookup_filename):
    """
    Delete a lookup file from a worker group.

    Performs a partial commit of only the deletion-related files to avoid
    committing other pending changes. If partial commit fails, the deletion
    succeeds but user must commit manually in Cribl UI.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    api_type = request.args.get('api_type', 'stream')
    token = app_config['token']
    
    # SECURITY: Validate inputs
    try:
        worker_group = validate_worker_group(worker_group)
        lookup_filename = validate_filename(lookup_filename)
        api_type = validate_api_type(api_type)
    except ValueError as e:
        debug_log(f"   [SECURITY] Input validation failed: {str(e)}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    
    debug_log(f"\n[DELETE] Deleting {lookup_filename} from {worker_group} ({api_type})")
    
    try:
        # Build URL to delete the lookup
        delete_url = build_api_url(api_type, worker_group, path=f'/system/lookups/{lookup_filename}')
        
        debug_log(f"   Delete URL: {delete_url}")
        headers = {"Authorization": f"Bearer {token}"}
        
        response = requests.delete(delete_url, headers=headers, timeout=10)
        response.raise_for_status()
        
        debug_log(f"   [OK] Successfully deleted {lookup_filename}")
        
        # Get the actual list of pending changes to do a true partial commit
        debug_log(f"   [STEP 2] Getting pending changes to identify deletion-related files...")
        status_url = build_api_url(api_type, worker_group, path='/version/status')
        
        try:
            status_response = requests.get(status_url, headers=headers, timeout=10)
            status_response.raise_for_status()
            status_data = status_response.json()

            # Try to extract the actual file paths from pending changes
            pending_files = []
            
            # Try different response structures
            if 'items' in status_data and isinstance(status_data['items'], list):
                for item in status_data['items']:
                    if isinstance(item, dict) and 'file' in item:
                        pending_files.append(item['file'])
                    elif isinstance(item, str):
                        pending_files.append(item)
            elif 'files' in status_data and isinstance(status_data['files'], list):
                pending_files = status_data['files']
            
            debug_log(f"   [INFO] Found {len(pending_files)} pending files")
            if pending_files:
                debug_log(f"   [INFO] Pending files: {pending_files}")
            
            # Filter to only files related to the deleted lookup
            lookup_base = Path(lookup_filename).stem
            deletion_files = [f for f in pending_files if lookup_filename in f or lookup_base in f]
            
            debug_log(f"   [INFO] Deletion-related files: {deletion_files}")
            
            # If we couldn't get the file list, build the expected paths manually
            if not deletion_files:
                debug_log(f"   [WARNING] Could not identify deletion files from status response")
                debug_log(f"   [WARNING] Building expected paths manually...")
                lookup_csv_path = f"groups/{worker_group}/data/lookups/{lookup_filename}"
                lookup_yml_path = f"groups/{worker_group}/data/lookups/{lookup_base}.yml"
                deletion_files = [lookup_csv_path, lookup_yml_path]
                debug_log(f"   [INFO] Expected deletion files: {deletion_files}")
            
            # Attempt partial commit with deletion files
            debug_log(f"   [STEP 3] Attempting partial commit of deletion files only...")
            commit_message = f"{COMMIT_PREFIX} Deleted lookup: {lookup_filename}"
            commit_url = build_api_url(api_type, worker_group, path='/version/commit')
            
            commit_data = {
                "message": commit_message,
                "group": worker_group,
                "files": deletion_files  # PARTIAL COMMIT - only deletion files
            }
            
            debug_log(f"   Commit URL: {commit_url}")
            debug_log(f"   Committing files (partial commit): {commit_data['files']}")
            
            try:
                commit_response = requests.post(commit_url, json=commit_data, headers=headers, timeout=30)
                commit_response.raise_for_status()
                commit_result = commit_response.json()
                
                debug_log(f"   [DATA] Commit response: {json.dumps(commit_result, indent=2)}")
                
                # Extract commit ID from response for deployment
                commit_id = None
                if 'items' in commit_result and isinstance(commit_result['items'], list) and len(commit_result['items']) > 0:
                    first_item = commit_result['items'][0]
                    commit_id = (first_item.get('commit') or 
                                first_item.get('hash') or
                                first_item.get('version'))
                
                if not commit_id:
                    commit_id = commit_result.get('commit') or commit_result.get('hash') or commit_result.get('version', 'unknown')
                
                debug_log(f"   [OK] Partial commit successful: {str(commit_id)[:8]}...")
                debug_log(f"   [OK] Only deletion files were committed (other pending changes untouched)")
                
                # Store commit ID for deployment (same as transfer)
                app_config['last_transfer_commit_id'] = commit_id
                app_config['last_transfer_group'] = worker_group
                app_config['last_transfer_api_type'] = api_type
                app_config['last_transfer_files'] = deletion_files
                
                debug_log(f"   [INFO] Deletion committed and ready for partial deployment")
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully deleted {lookup_filename}',
                    'committed': True,
                    'commit_id': commit_id,
                    'partial_commit': True
                })
                
            except requests.exceptions.HTTPError as commit_error:
                # Partial commit with deleted files failed (likely 500 error)
                debug_log(f"   [ERROR] Partial commit failed: {commit_error.response.status_code}")
                debug_log(f"   [ERROR] This is expected - Cribl API may not support partial commit of deleted files")
                debug_log(f"   [WARNING] Deletion succeeded but NOT committed to prevent committing other changes")
                debug_log(f"   [WARNING] Please commit manually in Cribl UI to complete the deletion")
                
                return jsonify({
                    'success': True,
                    'message': f'Successfully deleted {lookup_filename} but could not do partial commit',
                    'committed': False,
                    'warning': 'Cribl API does not support partial commit of deleted files. Please commit manually in Cribl UI to avoid committing other pending changes.',
                    'manual_commit_required': True
                })
                
        except Exception as status_error:
            debug_log(f"   [ERROR] Could not get pending changes: {str(status_error)}")
            debug_log(f"   [WARNING] Cannot verify partial commit is possible")
            debug_log(f"   [WARNING] Deletion succeeded but NOT committing to be safe")
            
            return jsonify({
                'success': True,
                'message': f'Successfully deleted {lookup_filename} but could not verify partial commit',
                'committed': False,
                'warning': 'Could not verify partial commit is safe. Please commit manually in Cribl UI.',
                'manual_commit_required': True
            })
        
    except requests.exceptions.HTTPError as e:
        error_msg = f"{e.response.status_code} {e.response.reason}"
        debug_log(f"   [ERROR] {error_msg}")
        return jsonify({'error': error_msg}), 500
    except Exception as e:
        debug_log(f"   [ERROR] {str(e)}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# VERSION STATUS ENDPOINTS
# =============================================================================

@app.route('/api/pending-changes', methods=['GET'])
def get_pending_changes():
    """
    Get count of pending (uncommitted) changes for a worker group.

    Uses the /version/status endpoint to check for modified, created,
    and deleted files that haven't been committed yet.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    
    debug_log(f"\n[PENDING] Checking pending changes for {worker_group} ({api_type})")
    
    try:
        # Use /version/status endpoint to check for uncommitted changes
        status_url = build_api_url(api_type, worker_group, path='/version/status')
        headers = {"Authorization": f"Bearer {token}"}
        
        debug_log(f"   [INFO] Querying: {status_url}")
        
        response = requests.get(status_url, headers=headers, timeout=10)
        response.raise_for_status()
        status_data = response.json()
        
        debug_log(f"   [DATA] Status Response: {json.dumps(status_data, indent=2)}")
        
        # Count pending changes from the status response
        pending_count = 0
        
        # Check for files object with modified/created/deleted arrays
        if 'files' in status_data:
            files = status_data['files']
            if isinstance(files, dict):
                modified = files.get('modified', [])
                created = files.get('created', [])
                deleted = files.get('deleted', [])
                
                if isinstance(modified, list):
                    pending_count += len(modified)
                if isinstance(created, list):
                    pending_count += len(created)
                if isinstance(deleted, list):
                    pending_count += len(deleted)
                    
                debug_log(f"   [INFO] Modified: {len(modified) if isinstance(modified, list) else 0}")
                debug_log(f"   [INFO] Created: {len(created) if isinstance(created, list) else 0}")
                debug_log(f"   [INFO] Deleted: {len(deleted) if isinstance(deleted, list) else 0}")
        
        # Check for changes field directly
        elif 'changes' in status_data:
            pending_count = status_data.get('changes', 0)
            debug_log(f"   [INFO] Direct changes count: {pending_count}")
        
        # Check if there's a summary object
        elif 'summary' in status_data and isinstance(status_data['summary'], dict):
            summary = status_data['summary']
            pending_count = summary.get('changes', 0)
            debug_log(f"   [INFO] Summary changes count: {pending_count}")
        
        debug_log(f"   [SUCCESS] Pending changes: {pending_count}")
        
        return jsonify({
            'success': True,
            'pending_count': pending_count
        })
        
    except requests.exceptions.HTTPError as e:
        # If status endpoint doesn't exist or returns error, return 0
        debug_log(f"   [WARNING] Status endpoint error: {e.response.status_code}")
        try:
            debug_log(f"   [WARNING] Response: {e.response.text[:500]}")
        except:
            pass
        return jsonify({'success': True, 'pending_count': 0})
        
    except Exception as e:
        debug_log(f"   [ERROR] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': True, 'pending_count': 0, 'error': str(e)})


@app.route('/api/verify-km-commit', methods=['GET'])
def verify_km_commit():
    """
    Verify if a Knowledge Manager commit is still valid/pending.

    Compares a stored commit ID against the current committed version.
    Returns whether the commit is still the latest (pending deploy) or
    has been superseded (should clear localStorage).

    Query params:
      - worker_group: The worker group to check
      - api_type: stream, edge, or search
      - commit_id: The stored commit ID to verify

    Returns:
      - still_valid: True if commit ID matches current committed version
      - should_clear: True if the commit ID differs (superseded by newer commit)
      - current_version: The current committed version
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401

    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    commit_id = request.args.get('commit_id')

    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400

    token = app_config['token']

    debug_log(f"\n[VERIFY-KM] Verifying KM commit for {worker_group} ({api_type})")
    debug_log(f"   [INFO] Stored commit ID: {commit_id}")

    try:
        # Get current committed version from /version/committed endpoint
        committed_url = build_api_url(api_type, worker_group, path='/version/committed')
        headers = {"Authorization": f"Bearer {token}"}

        debug_log(f"   [INFO] Querying: {committed_url}")

        response = requests.get(committed_url, headers=headers, timeout=10)
        response.raise_for_status()
        committed_data = response.json()

        debug_log(f"   [DATA] Committed version response: {json.dumps(committed_data, indent=2)[:500]}")

        # Extract the current committed version
        current_version = None
        if 'commit' in committed_data:
            current_version = committed_data['commit']
        elif 'version' in committed_data:
            current_version = committed_data['version']
        elif 'items' in committed_data and len(committed_data.get('items', [])) > 0:
            current_version = committed_data['items'][0].get('commit') or committed_data['items'][0].get('version')

        debug_log(f"   [INFO] Current committed version: {current_version}")

        # If no commit_id was provided, can't verify - assume still valid
        if not commit_id:
            debug_log(f"   [INFO] No commit ID provided, cannot verify")
            return jsonify({
                'success': True,
                'still_valid': True,
                'should_clear': False,
                'reason': 'No commit ID provided for verification',
                'current_version': current_version
            })

        # Compare stored commit ID with current version
        # If they match, our commit is still the latest (pending deploy)
        # If they differ, a newer commit was made (clear localStorage)
        still_valid = (commit_id == current_version)

        if still_valid:
            debug_log(f"   [OK] Commit ID matches current version - still pending deploy")
        else:
            debug_log(f"   [INFO] Commit ID differs - newer commit exists, should clear localStorage")

        return jsonify({
            'success': True,
            'still_valid': still_valid,
            'should_clear': not still_valid,
            'stored_commit': commit_id,
            'current_version': current_version,
            'reason': 'Commit matches current version' if still_valid else 'Newer commit exists'
        })

    except requests.exceptions.HTTPError as e:
        debug_log(f"   [WARNING] Could not get committed version: {e.response.status_code}")
        # If we can't verify, assume still valid to be safe
        return jsonify({
            'success': True,
            'still_valid': True,
            'should_clear': False,
            'reason': f'Could not verify: HTTP {e.response.status_code}'
        })

    except Exception as e:
        debug_log(f"   [ERROR] Error: {str(e)}")
        return jsonify({
            'success': True,
            'still_valid': True,
            'should_clear': False,
            'reason': f'Could not verify: {str(e)}'
        })


@app.route('/api/current-version', methods=['GET'])
def get_current_version():
    """
    Get the current deployed/committed version for a worker group.

    Returns the commit hash of the currently deployed configuration.
    Used to display version info in the UI.
    """
    if not app_config['authenticated']:
        return jsonify({'error': 'Not authenticated'}), 401
    
    worker_group = request.args.get('worker_group')
    api_type = request.args.get('api_type', 'stream')
    
    if not worker_group:
        return jsonify({'error': 'Worker group required'}), 400
    
    token = app_config['token']
    
    debug_log(f"\n[VERSION] Getting current version for {worker_group} ({api_type})")
    
    try:
        version_url = build_api_url(api_type, worker_group, path='/version')
        headers = {"Authorization": f"Bearer {token}"}
        
        debug_log(f"   [INFO] Querying: {version_url}")
        
        response = requests.get(version_url, headers=headers, timeout=10)
        
        # Handle 404 gracefully - endpoint might not exist for this worker group
        if response.status_code == 404:
            debug_log(f"   [WARNING] /version endpoint not found for {worker_group} (HTTP 404)")
            debug_log(f"   [INFO] This worker group may not support version tracking")
            return jsonify({
                'success': True,
                'version': None,
                'warning': 'Version endpoint not available for this worker group'
            })
        
        response.raise_for_status()
        version_data = response.json()
        
        debug_log(f"   [DATA] Version response: {json.dumps(version_data, indent=2)}")
        
        # Try to extract the current version/commit
        current_version = None
        
        # Method 1: Direct commit field
        if 'commit' in version_data and version_data['commit']:
            current_version = version_data['commit']
            debug_log(f"   [OK] Found commit field: {current_version}")
        
        # Method 2: Git object
        elif 'git' in version_data and isinstance(version_data['git'], dict):
            if 'commit' in version_data['git'] and version_data['git']['commit']:
                current_version = version_data['git']['commit']
                debug_log(f"   [OK] Found git.commit: {current_version}")
        
        # Method 3: Items array
        elif 'items' in version_data and isinstance(version_data['items'], list) and len(version_data['items']) > 0:
            first_item = version_data['items'][0]
            debug_log(f"   [INFO] Checking items[0]: {list(first_item.keys())}")
            if isinstance(first_item, dict):
                current_version = (first_item.get('commit') or 
                                 first_item.get('configVersion') or 
                                 first_item.get('version') or
                                 first_item.get('hash'))  # Git commit hash
                if current_version:
                    debug_log(f"   [OK] Found in items[0]: {current_version}")
                    # Log which field we used
                    for key in ['commit', 'configVersion', 'version', 'hash']:
                        if first_item.get(key) == current_version:
                            debug_log(f"   [OK] Used field: items[0].{key}")
                            break
        
        # Method 4: ConfigVersion field
        elif 'configVersion' in version_data and version_data['configVersion']:
            current_version = version_data['configVersion']
            debug_log(f"   [OK] Found configVersion: {current_version}")
        
        if not current_version:
            debug_log(f"   [ERROR] Could not find version in response")
            debug_log(f"   [ERROR] Available keys: {list(version_data.keys())}")
            return jsonify({
                'success': False, 
                'error': 'Could not find version in API response',
                'response_keys': list(version_data.keys())
            }), 500
        
        debug_log(f"   [SUCCESS] Current version: {current_version}")
        
        return jsonify({
            'success': True,
            'version': current_version
        })
        
    except Exception as e:
        debug_log(f"   [ERROR] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# MARKETPLACE API ENDPOINTS
# =============================================================================

@app.route('/api/marketplace/providers', methods=['GET'])
def get_feed_providers():
    """Get list of available feed providers."""
    providers = []
    for provider_id, config in FEED_PROVIDERS.items():
        providers.append({
            'id': provider_id,
            'name': config['name'],
            'description': config['description'],
            'category': config['category'],
            'auth_type': config['auth_type'],
            'default_filename': config['default_filename'],
            'update_frequency': config['update_frequency'],
            'note': config.get('note')
        })
    return jsonify({'providers': providers})

@app.route('/api/marketplace/feeds', methods=['GET'])
def get_feeds():
    """Get all configured feeds."""
    init_marketplace_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM feeds ORDER BY created_at DESC')
    feeds = [feed_row_to_dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'feeds': feeds})

@app.route('/api/marketplace/feeds', methods=['POST'])
def create_feed():
    """Create a new feed configuration."""
    init_marketplace_db()
    data = request.json

    provider_id = data.get('provider_id')
    if provider_id not in FEED_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider_id}'}), 400

    provider = FEED_PROVIDERS[provider_id]

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO feeds (
                provider_id, name, enabled, lookup_filename,
                schedule_cron, target_api_type,
                target_worker_groups, auto_deploy, auth_config
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            provider_id,
            data.get('name', provider['name']),
            1 if data.get('enabled', True) else 0,
            data.get('lookup_filename', provider['default_filename']),
            data.get('schedule_cron', '0 6 * * *'),
            data.get('target_api_type', 'stream'),
            data.get('target_worker_group', 'default'),
            1 if data.get('auto_deploy', False) else 0,
            json.dumps(data.get('auth_config', {}))
        ))

        feed_id = cursor.lastrowid
        conn.commit()

        # Schedule the job if enabled
        if data.get('enabled', True):
            schedule_feed_job(feed_id, data.get('schedule_cron', '0 6 * * *'))

        # Fetch the created feed
        cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
        feed = feed_row_to_dict(cursor.fetchone())
        conn.close()

        return jsonify({'success': True, 'feed': feed}), 201

    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/marketplace/feeds/<int:feed_id>', methods=['GET'])
def get_feed(feed_id):
    """Get a specific feed configuration."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
    feed = feed_row_to_dict(cursor.fetchone())
    conn.close()

    if not feed:
        return jsonify({'error': 'Feed not found'}), 404

    return jsonify(feed)

@app.route('/api/marketplace/feeds/<int:feed_id>', methods=['PUT'])
def update_feed(feed_id):
    """Update a feed configuration."""
    data = request.json

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if feed exists
    cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
    existing = cursor.fetchone()
    if not existing:
        conn.close()
        return jsonify({'error': 'Feed not found'}), 404

    try:
        cursor.execute('''
            UPDATE feeds SET
                name = ?,
                enabled = ?,
                lookup_filename = ?,
                schedule_cron = ?,
                target_api_type = ?,
                target_worker_groups = ?,
                auto_deploy = ?,
                auth_config = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            data.get('name', existing['name']),
            1 if data.get('enabled', existing['enabled']) else 0,
            data.get('lookup_filename', existing['lookup_filename']),
            data.get('schedule_cron', existing['schedule_cron'] or '0 6 * * *'),
            data.get('target_api_type', existing['target_api_type']),
            data.get('target_worker_groups', existing['target_worker_groups'] or 'default'),
            1 if data.get('auto_deploy', existing['auto_deploy']) else 0,
            json.dumps(data.get('auth_config', json.loads(existing['auth_config'] or '{}'))),
            feed_id
        ))

        conn.commit()

        # Update scheduled job
        if data.get('enabled', existing['enabled']):
            schedule_feed_job(feed_id, data.get('schedule_cron', existing['schedule_cron'] or '0 6 * * *'))
        else:
            # Remove job if disabled
            job_id = f"feed_{feed_id}"
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)

        # Fetch updated feed
        cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
        feed = feed_row_to_dict(cursor.fetchone())
        conn.close()

        return jsonify({'success': True, 'feed': feed})

    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

@app.route('/api/marketplace/feeds/<int:feed_id>', methods=['DELETE'])
def delete_feed(feed_id):
    """Delete a feed configuration."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if feed exists
    cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Feed not found'}), 404

    # Remove scheduled job
    job_id = f"feed_{feed_id}"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)

    # Delete feed and history
    cursor.execute('DELETE FROM sync_history WHERE feed_id = ?', (feed_id,))
    cursor.execute('DELETE FROM feeds WHERE id = ?', (feed_id,))
    conn.commit()
    conn.close()

    return jsonify({'success': True})

@app.route('/api/marketplace/feeds/<int:feed_id>/sync', methods=['POST'])
def sync_feed(feed_id):
    """Manually trigger a feed sync."""
    success, message, preview_data = execute_feed_sync(feed_id, manual=True)
    if success:
        response = {'success': True, 'message': message}
        if preview_data:
            response['preview'] = preview_data
        return jsonify(response)
    else:
        return jsonify({'success': False, 'error': message}), 500

@app.route('/api/marketplace/feeds/<int:feed_id>/history', methods=['GET'])
def get_feed_history(feed_id):
    """Get sync history for a feed."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM sync_history
        WHERE feed_id = ?
        ORDER BY sync_time DESC
        LIMIT 50
    ''', (feed_id,))
    history = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(history)

@app.route('/api/marketplace/feeds/<int:feed_id>/preview', methods=['GET'])
def preview_feed(feed_id):
    """Preview feed content without saving (download and parse only)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM feeds WHERE id = ?', (feed_id,))
    feed = feed_row_to_dict(cursor.fetchone())
    conn.close()

    if not feed:
        return jsonify({'error': 'Feed not found'}), 404

    provider_id = feed['provider_id']
    auth_config = json.loads(feed['auth_config']) if feed['auth_config'] else None

    # Download and parse
    content, error = download_feed_content(provider_id, auth_config)
    if error:
        return jsonify({'success': False, 'error': f"Download failed: {error}"}), 500

    csv_content, record_count, parse_error = parse_feed_to_csv(provider_id, content)
    if parse_error:
        return jsonify({'success': False, 'error': f"Parse failed: {parse_error}"}), 500

    # Return preview (first 100 lines)
    lines = csv_content.split('\n')[:101]
    preview = '\n'.join(lines)

    return jsonify({
        'success': True,
        'record_count': record_count,
        'preview': preview,
        'preview_lines': min(100, record_count + 1)
    })

@app.route('/api/marketplace/test-provider', methods=['POST'])
def test_provider():
    """Test a feed provider with given auth config."""
    data = request.json
    provider_id = data.get('provider_id')
    auth_config = data.get('auth_config', {})

    if provider_id not in FEED_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider_id}'}), 400

    # Try to download
    content, error = download_feed_content(provider_id, auth_config)
    if error:
        return jsonify({'success': False, 'error': error})

    # Try to parse
    csv_content, record_count, parse_error = parse_feed_to_csv(provider_id, content)
    if parse_error:
        return jsonify({'success': False, 'error': parse_error})

    return jsonify({
        'success': True,
        'message': f'Successfully downloaded and parsed {record_count} records'
    })

@app.route('/api/marketplace/scheduler/status', methods=['GET'])
def get_scheduler_status():
    """Get scheduler status and scheduled jobs."""
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            'id': job.id,
            'next_run_time': str(job.next_run_time) if job.next_run_time else None,
            'trigger': str(job.trigger)
        })

    return jsonify({
        'running': scheduler.running,
        'jobs': jobs
    })


# =============================================================================
# SERVER STARTUP UTILITIES
# =============================================================================

def is_port_available(port):
    """Check if a port is available for binding."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        sock.close()
        return True
    except OSError:
        return False

def get_available_port(preferred_port=42002):
    """
    Get an available port, prompting user if preferred port is in use.

    Tries the preferred port first, then searches nearby ports.
    If no nearby port is available, prompts user for custom port.
    """
    if is_port_available(preferred_port):
        return preferred_port
    
    print(f"\n[WARN] Port {preferred_port} is already in use.")
    
    # Try to find an available port nearby
    for port in range(preferred_port + 1, preferred_port + 100):
        if is_port_available(port):
            print(f"[OK] Found available port: {port}")
            response = input(f"Would you like to use port {port}? (y/n): ").strip().lower()
            if response == 'y':
                return port
    
    # Ask user for custom port
    while True:
        try:
            custom_port = input("Please enter a port number to use (1024-65535): ").strip()
            port = int(custom_port)
            
            if port < 1024 or port > 65535:
                print("[ERROR] Port must be between 1024 and 65535")
                continue
            
            if is_port_available(port):
                return port
            else:
                print(f"[ERROR] Port {port} is not available. Please try another port.")
        except ValueError:
            print("[ERROR] Please enter a valid number")
        except KeyboardInterrupt:
            print("\n\n[EXIT] Exiting...")
            sys.exit(0)

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

if __name__ == '__main__':
    # Display startup banner
    print("\n" + "="*60)
    print("[SERVER] Cribl Knowledge Manager v4.0.0")
    print("="*60)
    
    # Check for credentials (environment variables or config file)
    print("\n[CONFIG] Checking for credentials...")
    config, source = load_config_file()
    if config and all(config.values()):
        if source == 'env':
            print("[OK] Credentials found in environment variables - auto-login will be available")
        else:
            print("[OK] Credentials found in config.ini - auto-login will be available")
            print("     (File permissions secured to owner-only)")
    else:
        print("[WARN] No credentials found - manual login required")
        print("   Option 1: Set environment variables (more secure):")
        print("             CRIBL_CLIENT_ID, CRIBL_CLIENT_SECRET, CRIBL_ORG_ID")
        print("   Option 2: Create config.ini from config.ini.template")

    # Initialize Marketplace database and scheduler
    print("\n[MARKETPLACE] Initializing feed scheduler...")
    init_marketplace_db()
    scheduler.start()
    load_scheduled_jobs()
    atexit.register(lambda: scheduler.shutdown())
    print("[OK] Marketplace scheduler started")

    # Get available port
    default_port = 42002
    print("\n[PORT] Checking port availability...")
    port = get_available_port(default_port)
    print(f"[OK] Using port: {port}")

    print(f"\n{'='*60}")
    print(f"[OK] Server starting on http://localhost:{port}")
    print(f"{'='*60}")
    print("\n[INFO] Press Ctrl+C to stop the server\n")

    # Browser launch logic
    url = f"http://localhost:{port}"
    if port == default_port:
        # Default port available - auto-launch browser
        print(f"[INFO] Opening browser to {url}...")
        browser_thread = threading.Thread(target=lambda: webbrowser.open(url))
        browser_thread.daemon = True
        browser_thread.start()
    else:
        # Non-default port - ask user
        print(f"[INFO] Server will be available at: {url}")
        response = input("\nWould you like to open this in your browser? (y/n): ").strip().lower()
        if response == 'y':
            print("[INFO] Opening browser...")
            browser_thread = threading.Thread(target=lambda: webbrowser.open(url))
            browser_thread.daemon = True
            browser_thread.start()
        else:
            print(f"[INFO] You can manually open {url} in your browser anytime.")
    
    print("\n" + "="*60)
    print("Starting Flask server...")
    print("="*60 + "\n")
    
    try:
        app.run(debug=False, host='0.0.0.0', port=port, use_reloader=False)
    except KeyboardInterrupt:
        print("\n\n[SHUTDOWN] Shutting down gracefully...")
        print("[OK] Server stopped")
        sys.exit(0)
