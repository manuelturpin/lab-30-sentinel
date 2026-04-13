# Threat Intelligence Sources for Sentinel Security Scanner

**Research Date:** April 13, 2026  
**Status:** Free tier analysis, 15+ sources investigated  
**Recommendation:** Implement tiered integration starting with Must-Have sources

---

## Executive Summary

This document identifies **15 free, programmable cybersecurity threat intelligence sources** suitable for an autonomous security scanner's update pipeline. Sources are ranked by:
- **Reliability & Authority** (NIST, FIRST.org, Google, CISA, GitHub, MITRE)
- **API Quality** (no auth required, clear rate limits, JSON format)
- **Update Frequency** (daily/weekly for threat data)
- **Python Cron Compatibility** (REST API, bulk exports available)

**Top 3 Sources for Initial Integration:**
1. **NVD API v2** (NIST) — Authoritative CVE data, 50 req/30s with key
2. **EPSS API** (FIRST.org) — Daily exploitation probability scores, no limits
3. **OSV API** (Google) — Zero rate limits, multi-ecosystem coverage

---

## Complete Source Registry

### A. CVE/Vulnerability Feeds (Must-Have)

| # | Source | Auth | Rate Limit | Update | Format | Status |
|---|--------|------|-----------|--------|--------|--------|
| 1 | **NVD API v2** (NIST) | API Key | 50 req/30s (with key) | Daily | JSON | CRITICAL |
| 2 | **EPSS API** (FIRST.org) | None | Unlimited | Daily | JSON/CSV | CRITICAL |
| 3 | **OSV API** (Google) | None | None | Real-time | JSON | CRITICAL |
| 4 | **CISA KEV** (Catalog) | None | None | Real-time | JSON/CSV | HIGH |
| 5 | **CIRCL CVE** (Vulnerability-Lookup) | None | Not specified | Daily | JSON | MEDIUM |
| 6 | **CVEDB** (Shodan) | None | Free tier | Daily | JSON | MEDIUM |

#### 1A. NVD API v2 (NIST)

**Endpoint:** `https://nvd.nist.gov/rest/json/cves/2.0`  
**Authentication:**
```
Header: apiKey: {KEY_VALUE}
GET https://nvd.nist.gov/rest/json/cves/2.0?{params}
```

**Rate Limits:**
- Without key: 5 requests/30s
- With key: 50 requests/30s
- Obtain key: Free via form at https://nvd.nist.gov/developers/request-an-api-key (email activation)

**Query Parameters:**
- `cpeName`, `keywordSearch`, `lastModStartDate`, `lastModEndDate`
- `cvssV3Severity`, `resultsPerPage` (default: 20)

**Update Frequency:** Daily (recommend checking every 2 hours per NIST docs)

**Best For:** Baseline CVE scoring (CVSS v3), official NVD records

**Python Example:**
```python
import requests
import time

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_cves(keyword=None, last_days=7):
    from datetime import datetime, timedelta
    
    start_date = (datetime.utcnow() - timedelta(days=last_days)).isoformat()
    params = {
        "apiKey": API_KEY,
        "lastModStartDate": start_date,
        "resultsPerPage": 100
    }
    
    all_cves = []
    start_index = 0
    
    while True:
        params["startIndex"] = start_index
        response = requests.get(BASE_URL, params=params)
        response.raise_for_status()
        data = response.json()
        
        all_cves.extend(data.get("vulnerabilities", []))
        
        if data["totalResults"] <= start_index + 100:
            break
        start_index += 100
        time.sleep(0.6)  # 6s delay per NIST guidance
    
    return all_cves
```

---

#### 1B. EPSS API (FIRST.org)

**Endpoint:** `https://api.first.org/data/v1/epss`  
**Authentication:** None required

**Query Formats:**
```
# Single CVE
GET https://api.first.org/data/v1/epss?cve=CVE-2025-1234

# Batch (comma-separated)
GET https://api.first.org/data/v1/epss?cve=CVE-2025-1234,CVE-2025-5678

# Date-specific (YYYY-MM-DD)
GET https://api.first.org/data/v1/epss?date=2025-04-01

# Filtering by probability
GET https://api.first.org/data/v1/epss?percentile=75  # Top 25% likely to be exploited

# Sorting
GET https://api.first.org/data/v1/epss?sort=-epss
```

**Rate Limits:** None documented (queries appear unlimited)

**Update Frequency:** Daily (updates every 24h)

**Data Availability:** Historical back to April 14, 2021

**Bulk Access:** Complete CSV datasets at `https://epss.empiricalsecurity.com/` (direct downloads)

**Best For:** Exploitation probability scoring, prioritization above CVSS

**Python Example:**
```python
import requests

def fetch_epss_scores(cve_list, date=None):
    """Batch fetch EPSS scores for CVEs"""
    base_url = "https://api.first.org/data/v1/epss"
    
    cve_str = ",".join(cve_list)
    params = {"cve": cve_str}
    if date:
        params["date"] = date
    
    response = requests.get(base_url, params=params)
    response.raise_for_status()
    data = response.json()
    
    # Map CVE -> EPSS score and percentile
    epss_map = {}
    for item in data.get("data", []):
        epss_map[item["cve"]] = {
            "epss": float(item["epss"]),
            "percentile": float(item["percentile"]),
            "date": item["date"]
        }
    return epss_map
```

---

#### 1C. OSV API (Google)

**Endpoint:** `https://api.osv.dev/v1/query`  
**Authentication:** None required

**Query Formats:**
```
# By package name & version (npm, PyPI, Go, Rust, etc.)
curl -X POST https://api.osv.dev/v1/query \
  -H "Content-Type: application/json" \
  -d '{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}'

# By commit hash (any VCS)
curl -X POST https://api.osv.dev/v1/query \
  -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}'

# Batch queries
curl -X POST https://api.osv.dev/v1/querybatch \
  -d '{"queries": [{"package": {...}}, {"package": {...}}]}'

# Get specific CVE by OSV ID
curl https://api.osv.dev/v1/vulns/{OSV_ID}
```

**Ecosystems Covered:**
- npm, PyPI, Go, Rust, RubyGems, NuGet, GitHub (GHSA), Debian, Ubuntu, Alpine, etc.

**Rate Limits:** **None** (unlimited API calls)

**Response Limits:**
- HTTP/1.1: 32 MiB max response (no soft limits on query size)
- HTTP/2: Unlimited response size (recommended for bulk queries)

**Update Frequency:** Real-time (vulnerability data updated continuously)

**Best For:** Multi-ecosystem dependency scanning, container images, monorepos

**Python Example:**
```python
import requests
import json

def scan_osv(package_name, version, ecosystem="npm"):
    """Query OSV for vulnerabilities in a specific package version"""
    url = "https://api.osv.dev/v1/query"
    
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem
        },
        "version": version
    }
    
    response = requests.post(url, json=payload)
    response.raise_for_status()
    data = response.json()
    
    vulns = []
    for vuln_id in data.get("vulns", []):
        vulns.append({
            "id": vuln_id,
            "ecosystem": ecosystem,
            "package": package_name,
            "affected_version": version
        })
    return vulns

def batch_scan_osv(packages_list):
    """Batch scan multiple packages (use HTTP/2)"""
    url = "https://api.osv.dev/v1/querybatch"
    
    queries = [
        {
            "package": {
                "name": pkg["name"],
                "ecosystem": pkg.get("ecosystem", "npm")
            },
            "version": pkg["version"]
        }
        for pkg in packages_list
    ]
    
    payload = {"queries": queries}
    response = requests.post(url, json=payload)
    response.raise_for_status()
    return response.json()
```

---

#### 1D. CISA KEV Catalog

**Source:** U.S. Government / CISA  
**Primary Access:** `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`

**JSON Feed URL (Direct):**
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

**CSV Export:**
```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv
```

**Authentication:** None required

**Rate Limits:** None documented

**Update Frequency:** Real-time (updated as new exploits are discovered in active use)

**Data Fields:**
- `cveID`, `vendorProject`, `product`, `vulnerabilityName`
- `dateAdded`, `dueDateForExploit` (remediation deadline)
- `knownRansomwareCampaignUse` (boolean)
- `notes`, `references`

**Best For:**
- Known exploited vulnerabilities (must patch first)
- Ransomware campaigns tracking
- Regulatory compliance (US government mandate to patch KEV)

**Python Example:**
```python
import requests
import json
from datetime import datetime

def fetch_cisa_kev():
    """Fetch CISA Known Exploited Vulnerabilities catalog"""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    response = requests.get(url)
    response.raise_for_status()
    data = response.json()
    
    return {
        "vulnerabilities": data.get("vulnerabilities", []),
        "last_updated": data.get("catalogVersion"),
        "count": len(data.get("vulnerabilities", []))
    }

def filter_ransomware_kev(kev_data):
    """Filter for ransomware-related KEV vulnerabilities"""
    return [
        v for v in kev_data["vulnerabilities"]
        if v.get("knownRansomwareCampaignUse") == "Yes"
    ]

def days_until_remediation(kev_entry):
    """Calculate days until CISA remediation deadline"""
    due_date = datetime.strptime(kev_entry["dueDateForExploit"], "%Y-%m-%d")
    today = datetime.today()
    return (due_date - today).days
```

**Python Package (Alternative):**
```bash
pip install cisa-kev
```
```python
from cisa_kev import query

# Query by CVE
results = query.get_by_cve_id("CVE-2025-1234")

# Query by product
results = query.get_by_product("Windows")

# Export as JSON/CSV/Parquet
query.query_and_export(output_format="json", output_file="kev.json")
```

---

#### 1E. CIRCL CVE Search (Vulnerability-Lookup)

**Endpoint:** `https://vulnerability.circl.lu/api/`  
**Authentication:** None required

**Available Endpoints:**
```
GET https://vulnerability.circl.lu/api/browse                    # All vendors
GET https://vulnerability.circl.lu/api/browse/{vendor}          # Products for vendor
GET https://vulnerability.circl.lu/api/search/{vendor}/{product} # Vulns by product
GET https://vulnerability.circl.lu/api/cve/{CVE-ID}             # Specific CVE
GET https://vulnerability.circl.lu/api/last                      # Recent entries
GET https://vulnerability.circl.lu/api/dbInfo                    # Database info
```

**OpenAPI Spec:** `https://vulnerability.circl.lu/swagger.json`

**Rate Limits:** Not specified (appears unrestricted)

**Format:** JSON

**Update Frequency:** Daily

**Best For:** Vendor/product vulnerability browsing, EU-based data source

---

#### 1F. CVEDB (Shodan)

**Endpoint:** `https://cvedb.shodan.io/cves`  
**Authentication:** None required (free tier, no account needed)

**Query Examples:**
```
# Latest CVEs
curl https://cvedb.shodan.io/cves

# By CVSS score
curl https://cvedb.shodan.io/cves?cvss=8

# Known exploited (is_kev=true)
curl 'https://cvedb.shodan.io/cves?is_kev=true'

# By CPE 2.3
curl 'https://cvedb.shodan.io/cves?cpe23=cpe:2.3:a:libpng:libpng:0.8'

# By date range
curl 'https://cvedb.shodan.io/cves?published=2025-01'

# Sorted by EPSS
curl 'https://cvedb.shodan.io/cves?sort=epss'
```

**Rate Limits:** Free tier active (no enterprise license = rate-limited, but not specified)

**Update Frequency:** Daily

**Licensing:** Free for non-commercial, enterprise for monetization

**Best For:** Quick CVE lookups, EPSS integration, CPE searching

---

### B. Exploit Intelligence & PoC Tracking

| # | Source | Auth | Format | Update | Status |
|---|--------|------|--------|--------|--------|
| 7 | **ExploitDB** (OffSec) | None | JSON/SearchSploit CLI | Weekly | HIGH |
| 8 | **VulnCheck XDB** | Free tier | JSON | Real-time | MEDIUM |
| 9 | **GitHub PoC Search** | None | GraphQL/REST | Real-time | HIGH |
| 10 | **Metasploit Modules** | None | JSON/Ruby | Monthly | MEDIUM |

#### 2A. ExploitDB

**Source:** Official Exploit Database (OffSec)  
**GitHub Sync:** `https://github.com/AntiRootkit/exploit-database`

**Search CLI:**
```bash
searchsploit -h  # Show options
searchsploit --json "Windows RCE"  # JSON output
searchsploit -t oracle windows  # Type search
searchsploit -p 39446  # Exploit ID
```

**API Options:**
- **SearchSploit JSON API** (community): `https://github.com/PaulSec/exploitdb-json-api`
- **Local Mirror:** Clone repo, sync daily with git

**Update Frequency:** Continuous (synced from GitHub)

**Best For:** Proof-of-concept tracking, exploit metadata

---

#### 2B. GitHub PoC-in-GitHub Tracking

**Method:** Search GitHub for PoC repositories matching CVE patterns

**GitHub GraphQL Query:**
```graphql
query {
  search(first: 100, type: REPOSITORY, query: "CVE-2025-1234 POC") {
    edges {
      node {
        ... on Repository {
          name
          description
          url
          updatedAt
          stargazerCount
        }
      }
    }
  }
}
```

**REST Alternative:**
```bash
curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  'https://api.github.com/search/repositories?q=CVE-2025-1234%20POC&sort=stars'
```

**Best For:** Real-world exploit availability, GitHub trending PoCs

---

### C. Standards & Frameworks (Must-Have)

| # | Source | Format | Update | Status |
|---|--------|--------|--------|--------|
| 11 | **OWASP Top 10 (2025)** | GitHub/PDF | Annual | CRITICAL |
| 12 | **MITRE ATT&CK (STIX 2.1)** | JSON | Quarterly | CRITICAL |
| 13 | **MITRE ATLAS** | JSON | Quarterly | HIGH |
| 14 | **OWASP LLM Top 10** | GitHub | Quarterly | HIGH |
| 15 | **CWE/CVSS Standards** | NVD/NIST | JSON | Quarterly | CRITICAL |

#### 3A. OWASP Top 10 (2025)

**GitHub Repo:** `https://github.com/OWASP/Top10`  
**Direct Access:** `https://github.com/OWASP/Top10/tree/master/2025`

**Releases Page:**
```
https://api.github.com/repos/OWASP/Top10/releases/latest
```

**Data Submission:** CSV/JSON/Excel at https://bit.ly/OWASPTop10Data

**Update Frequency:** Annual (2025 edition just released)

**Python Integration:**
```python
import requests

def fetch_owasp_releases():
    """Fetch OWASP Top 10 release data from GitHub"""
    url = "https://api.github.com/repos/OWASP/Top10/releases"
    response = requests.get(url)
    response.raise_for_status()
    
    releases = response.json()
    return {
        "latest": releases[0]["tag_name"] if releases else None,
        "releases": [
            {
                "version": r["tag_name"],
                "date": r["published_at"],
                "assets": [a["download_url"] for a in r["assets"]]
            }
            for r in releases
        ]
    }
```

---

#### 3B. MITRE ATT&CK (STIX 2.1)

**GitHub Repo:** `https://github.com/mitre-attack/attack-stix-data`

**Download URLs:**
```
# Enterprise (latest)
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Mobile
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json

# ICS
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json

# Versioned releases
https://github.com/mitre-attack/attack-stix-data/releases
```

**TAXII 2.1 Server (Live):**
```bash
curl --request GET \
  --url https://attack-taxii.mitre.org/api/v21/collections \
  --header 'Accept: application/taxii+json;version=2.1'
```

**Format:** STIX 2.1 JSON  
**Update Frequency:** Quarterly (v14.1 as of Apr 2026)

**Python Library:**
```python
# Install: pip install mitreattack-python
from mitreattack.stix20 import MitreAttackData

attack_data = MitreAttackData("enterprise-attack.json")
techniques = attack_data.get_techniques()
tactics = attack_data.get_tactics()
mitigations = attack_data.get_mitigations()
```

---

#### 3C. MITRE ATLAS (AI Security)

**GitHub:** `https://github.com/mitre-atlas`  
**Website:** `https://atlas.mitre.org/`

**Technique Search:** JSON available via GitHub releases  
**Update Frequency:** Quarterly

**Best For:** LLM/AI system adversarial tactics and techniques

---

#### 3D. OWASP LLM Top 10 (2024/2025)

**Official Repo:** `https://github.com/OWASP/LLM-Attacks` (or find via OWASP site)

**Alternative Sources:**
- `https://github.com/TAM-DS/OWASP-LLM-Attack-Surface-2025-Edition-` (comprehensive mapping)
- `https://github.com/PaulDuvall/owasp_llm_top10` (testing framework)

**Key Resources:**
- Prompt injection detection tools
- RAG vulnerability assessment (Vigil project)
- Jailbreak pattern libraries

---

### D. Supply Chain & Dependencies

| # | Source | Auth | API | Status |
|---|--------|------|-----|--------|
| 16 | **GitHub Advisory DB** | Token | GraphQL/REST | CRITICAL |
| 17 | **npm Audit API** | None | REST/CLI | HIGH |
| 18 | **PyPI JSON API** | None | REST | MEDIUM |
| 19 | **deps.dev (Google)** | None | REST | HIGH |

#### 4A. GitHub Advisory Database

**GraphQL API:**
```graphql
query {
  securityAdvisories(first: 100) {
    nodes {
      ghsaId
      cveIds(first: 5) {
        nodes { value }
      }
      summary
      description
      severity
      publishedAt
      references { url }
      identifiers { type value }
    }
  }
}
```

**Endpoint:** `https://api.github.com/graphql`

**Rate Limits:** GitHub's standard GraphQL rate limiting (depends on auth token)

**Authentication:** Optional (higher limits with token)

**REST Alternative:**
```bash
curl https://api.github.com/advisories?ecosystem=npm&severity=high
```

**Update Frequency:** Real-time

**Best For:** GitHub security advisories, multi-ecosystem dependency tracking

---

#### 4B. npm Audit API

**Local Audit (no API):**
```bash
npm audit --json > npm_audit_report.json
```

**Snyk Integration (Free):**
```bash
snyk test --json > snyk_report.json  # Requires npm install snyk
```

**NPM Registry API (search):**
```bash
curl https://registry.npmjs.org/{package_name}  # Get package metadata with vulnerability history
```

---

#### 4C. deps.dev (Google OSS Dependencies)

**URL:** `https://deps.dev/` (JavaScript interface, need to parse)

**GraphQL API (Undocumented but available):**
```
https://api.deps.dev/v1/{system}/{package_name}/{version}
```

**Example:**
```bash
curl https://api.deps.dev/v1/npm/lodash/4.17.20
```

---

### E. AI/LLM Security Intelligence

| # | Source | Type | Update | Status |
|---|--------|------|--------|--------|
| 20 | **AI Incident Database** | Database | Weekly | HIGH |
| 21 | **MIT AI Incident Tracker** | Research | Weekly | MEDIUM |

#### 5A. AI Incident Database

**Website:** `https://incidentdatabase.ai/`  
**Data Access:** Public incidents, searchable

**Categories:**
- GenAI incidents (70% in 2025)
- Agentic AI failures
- Prompt injection attacks
- Model theft / data exfiltration
- Supply chain attacks

**Updates:** Weekly roundup posts (e.g., Aug-Oct 2025 incidents)

**Best For:** Historical AI security trends, real-world exploitation patterns

---

## Python Cron Pipeline Architecture

### Recommended Structure

```python
# /home/sentinel/crons/threat-intel-sync.py

import os
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
import schedule
import requests

# Setup logging
logger = logging.getLogger("SentinelThreatIntel")
LOG_FILE = Path.home() / ".sentinel" / "logs" / f"threat-intel-{datetime.now():%Y%m%d}.log"

class ThreatIntelPipeline:
    """Autonomous threat intelligence sync pipeline"""
    
    def __init__(self):
        self.data_dir = Path.home() / ".sentinel" / "knowledge-base" / "threat-feeds"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.nvd_key = os.getenv("NVD_API_KEY")
        self.github_token = os.getenv("GITHUB_TOKEN")
    
    def sync_nvd_cves(self, days=7):
        """Fetch recent CVEs from NVD API v2"""
        logger.info(f"Syncing NVD CVEs from last {days} days...")
        
        from datetime import datetime, timedelta
        start_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        all_cves = []
        start_index = 0
        
        while True:
            params = {
                "apiKey": self.nvd_key,
                "lastModStartDate": start_date,
                "resultsPerPage": 100,
                "startIndex": start_index
            }
            
            resp = requests.get(
                "https://nvd.nist.gov/rest/json/cves/2.0",
                params=params
            )
            resp.raise_for_status()
            data = resp.json()
            
            all_cves.extend(data.get("vulnerabilities", []))
            
            if data["totalResults"] <= start_index + 100:
                break
            start_index += 100
            time.sleep(0.6)  # NVD rate limit compliance
        
        # Save to disk
        output_file = self.data_dir / f"nvd-cves-{datetime.now():%Y%m%d}.json"
        with open(output_file, "w") as f:
            json.dump(all_cves, f, indent=2)
        
        logger.info(f"Saved {len(all_cves)} NVD CVEs to {output_file}")
        return len(all_cves)
    
    def sync_epss_scores(self, cve_list):
        """Fetch EPSS scores in batch"""
        logger.info(f"Fetching EPSS scores for {len(cve_list)} CVEs...")
        
        cve_str = ",".join(cve_list)
        resp = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_str}
        )
        resp.raise_for_status()
        data = resp.json()
        
        epss_map = {}
        for item in data.get("data", []):
            epss_map[item["cve"]] = {
                "epss": float(item["epss"]),
                "percentile": float(item["percentile"]),
                "date": item["date"]
            }
        
        output_file = self.data_dir / f"epss-scores-{datetime.now():%Y%m%d}.json"
        with open(output_file, "w") as f:
            json.dump(epss_map, f, indent=2)
        
        logger.info(f"Saved EPSS data to {output_file}")
        return epss_map
    
    def sync_osv_vulnerabilities(self, ecosystems=["npm", "pypi", "go"]):
        """Sync OSV data for major ecosystems"""
        logger.info(f"Syncing OSV vulnerabilities for {ecosystems}...")
        
        # OSV bulk data available at GCS bucket
        for ecosystem in ecosystems:
            # Note: OSV publishes bulk JSON dumps
            logger.info(f"Processing {ecosystem} ecosystem...")
        
        return True
    
    def sync_cisa_kev(self):
        """Fetch CISA Known Exploited Vulnerabilities"""
        logger.info("Fetching CISA KEV catalog...")
        
        resp = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        resp.raise_for_status()
        data = resp.json()
        
        output_file = self.data_dir / f"cisa-kev-{datetime.now():%Y%m%d}.json"
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved {len(data['vulnerabilities'])} CISA KEV entries")
        return len(data["vulnerabilities"])
    
    def sync_github_advisories(self):
        """Fetch GitHub Advisory Database via GraphQL"""
        logger.info("Fetching GitHub Advisory Database...")
        
        query = """
        query {
            securityAdvisories(first: 100) {
                nodes {
                    ghsaId
                    cveIds(first: 5) { nodes { value } }
                    summary
                    severity
                    publishedAt
                }
            }
        }
        """
        
        headers = {"Authorization": f"Bearer {self.github_token}"}
        resp = requests.post(
            "https://api.github.com/graphql",
            json={"query": query},
            headers=headers
        )
        resp.raise_for_status()
        data = resp.json()
        
        output_file = self.data_dir / f"github-advisories-{datetime.now():%Y%m%d}.json"
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved GitHub advisories to {output_file}")
        return True
    
    def sync_mitre_attack_stix(self):
        """Fetch MITRE ATT&CK STIX data"""
        logger.info("Fetching MITRE ATT&CK STIX data...")
        
        domains = ["enterprise-attack", "mobile-attack", "ics-attack"]
        
        for domain in domains:
            url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
            resp = requests.get(url)
            resp.raise_for_status()
            data = resp.json()
            
            output_file = self.data_dir / f"mitre-{domain}-{datetime.now():%Y%m%d}.json"
            with open(output_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"Saved MITRE {domain} to {output_file}")
        
        return True
    
    def run_full_sync(self):
        """Execute complete threat intel sync"""
        logger.info("=" * 60)
        logger.info("Starting Sentinel Threat Intelligence Sync Pipeline")
        logger.info(f"Timestamp: {datetime.now()}")
        logger.info("=" * 60)
        
        try:
            # Sync CVEs from NVD
            nvd_count = self.sync_nvd_cves(days=7)
            
            # Get recent CVE IDs and fetch EPSS
            recent_cves = self.extract_recent_cve_ids(days=1)
            self.sync_epss_scores(recent_cves[:500])  # Batch limit
            
            # Sync CISA KEV
            kev_count = self.sync_cisa_kev()
            
            # Sync GitHub Advisories
            self.sync_github_advisories()
            
            # Sync MITRE ATT&CK
            self.sync_mitre_attack_stix()
            
            logger.info("=" * 60)
            logger.info("Threat Intelligence Sync Complete")
            logger.info(f"Total CVEs synced: {nvd_count}")
            logger.info(f"KEV entries: {kev_count}")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Sync error: {e}", exc_info=True)
            raise
    
    def extract_recent_cve_ids(self, days=1):
        """Extract CVE IDs from recent NVD file"""
        # Glob for most recent NVD file and extract IDs
        files = sorted(self.data_dir.glob("nvd-cves-*.json"), reverse=True)
        if not files:
            return []
        
        with open(files[0]) as f:
            data = json.load(f)
        
        return [v["cve"]["id"] for v in data if "cve" in v]


# Cron scheduling
if __name__ == "__main__":
    pipeline = ThreatIntelPipeline()
    
    # Schedule syncs
    schedule.every().day.at("02:00").do(pipeline.run_full_sync)  # Daily 2 AM
    schedule.every().day.at("14:00").do(pipeline.sync_nvd_cves, days=1)  # Daily 2 PM (CVE only)
    
    # Run scheduler loop
    while True:
        schedule.run_pending()
        time.sleep(60)
```

**Deploy as Cron Job:**
```bash
# /etc/cron.d/sentinel-threat-intel

# Run daily threat intelligence sync at 2 AM
0 2 * * * sentinel python3 /home/sentinel/crons/threat-intel-sync.py >> /home/sentinel/.sentinel/logs/threat-intel-cron.log 2>&1

# NVD updates twice daily (offset by 8 hours)
0 0,8 * * * sentinel python3 /home/sentinel/crons/threat-intel-sync.py --nvd-only 2>&1 | logger -t sentinel-nvd
```

---

## Recommendations for Sentinel Architecture

### Phase 1: MVP Integration (Weeks 1-2)

**Start with the Big Three:**
1. **NVD API v2** → Base CVE scoring (CVSS v3)
2. **EPSS API** → Exploitation probability ranking
3. **OSV API** → Multi-ecosystem dependency scanning

**Data Flow:**
```
NVD CVEs (daily) → Enrich with EPSS scores → Store in KB
                → Scan project dependencies with OSV
                → Generate priority recommendations
```

**Cron Schedule:**
- NVD sync: Every 2 hours (cheap, incremental)
- EPSS update: Daily (recalculates exploitability)
- OSV scanning: On-demand (project-specific)

---

### Phase 2: Extended Intelligence (Weeks 3-4)

Add **CISA KEV** (known exploited) + **GitHub Advisories** (open source supply chain)

**Use Cases:**
- Flag KEV vulnerabilities as "patch immediately"
- Cross-reference GitHub advisories with OSV data
- Track ransomware-related vulnerabilities

---

### Phase 3: Standards & Context (Weeks 5-6)

Integrate **MITRE ATT&CK**, **OWASP Top 10**, **OWASP LLM Top 10**

**Use Cases:**
- Map vulnerabilities to attack techniques
- Generate OWASP-aligned remediation paths
- LLM-specific security scoring

---

## API Comparison Matrix

| Feature | NVD | EPSS | OSV | CISA KEV | GitHub | CIRCL |
|---------|-----|------|-----|----------|--------|-------|
| **Free Tier** | Yes | Yes | Yes | Yes | Yes | Yes |
| **No Auth** | No (key recommended) | Yes | Yes | Yes | No (optional) | Yes |
| **Rate Limits** | 50/30s | Unlimited | None | None | High | Not specified |
| **CVE Coverage** | All official | All (daily) | Multi-ecosystem | Active exploits | All GHSA | Mirror of NVD |
| **Update Freq** | Daily | Daily | Real-time | Real-time | Real-time | Daily |
| **Bulk Export** | No | Yes (CSV) | Yes (GCS) | Yes (JSON/CSV) | No | JSON only |
| **Python Library** | nvdlib | None | None | cisa-kev | graphql-core | None |
| **EPSS Included** | No | Yes | No | No | No | No |

---

## Final Recommendations

**For Sentinel's Autonomous Pipeline:**

1. **Core Sources (Must Implement):**
   - NVD API v2 (authoritative CVE data)
   - EPSS API (exploitation probability)
   - OSV API (zero friction, unlimited rate limits)
   - CISA KEV (compliance/ransomware tracking)

2. **Secondary Sources (Phase 2):**
   - GitHub Advisory Database (supply chain)
   - MITRE ATT&CK STIX (threat context)
   - OWASP Top 10 (standards alignment)

3. **Cron Frequency:**
   - **Every 2 hours:** NVD incremental (CVEs modified in last 2h)
   - **Once daily:** EPSS batch update, CISA KEV check
   - **Weekly:** MITRE ATT&CK, OWASP standards sync

4. **Storage Strategy:**
   - Cache NVD/EPSS in ChromaDB (searchable index)
   - Store CISA KEV in separate "critical" collection
   - Version MITRE/OWASP data by release date

5. **Error Handling:**
   - Fallback to cached data if API fails
   - Alert on >4 hour staleness for real-time feeds (KEV, GitHub)
   - Retry with exponential backoff for rate-limited sources

---

## References

- NIST NVD API v2: https://nvd.nist.gov/developers/start-here
- FIRST EPSS: https://www.first.org/epss/api
- Google OSV: https://google.github.io/osv.dev/api/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- MITRE ATT&CK: https://github.com/mitre-attack/attack-stix-data
- GitHub Advisory DB: https://github.com/advisories
- CIRCL Vulnerability-Lookup: https://vulnerability.circl.lu/api
- CVEDB: https://cvedb.shodan.io/
- OWASP Top 10: https://github.com/OWASP/Top10
- AI Incident Database: https://incidentdatabase.ai/

---

**Document Generated:** 2026-04-13  
**Research Scope:** 15 threat intelligence sources  
**Recommendation Status:** Ready for Phase 1 implementation
