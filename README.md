<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/providers-AWS%20%7C%20Azure%20%7C%20GCP-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
</p>

<h1 align="center">vamp-cloud-enum</h1>
<p align="center"><em>Cloud Storage Bucket Enumerator — VampSecure Labs</em></p>

---

## Overview

**vamp-cloud-enum** discovers and audits misconfigured cloud storage buckets across AWS S3, Azure Blob Storage, and Google Cloud Storage. Starting from one or more target domain names, the tool generates a candidate bucket name wordlist (40+ suffix and prefix permutations) and probes each combination across all three cloud providers simultaneously.

For each bucket found, the tool determines whether it is publicly accessible, whether directory listing is enabled, and whether the bucket name or exposed contents contain sensitive keywords — escalating severity accordingly. Public buckets with listing enabled are classified as CRITICAL; exposed namespaces without listing are classified based on sensitive-keyword presence.

---

## Features

- Three-provider coverage: AWS S3 (virtual-hosted, path-style, listing API, website endpoint), Azure Blob Storage (account and container enumeration), GCP Cloud Storage (path-style and virtual-hosted)
- 40+ bucket name candidates generated from target domain permutations
- Sensitive keyword detection for automatic severity escalation (backup, credentials, private, secret, config, etc.)
- Custom wordlist support for organization-specific naming conventions
- Provider filtering — run against a single provider or all three
- Content listing detection — distinguishes PUBLIC (browseable) from PUBLIC (opaque)
- Configurable concurrency and timeout for rate-sensitive environments

---

## Requirements

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Installation

```bash
git clone https://github.com/belky-me/vamp-cloud-enum.git
cd vamp-cloud-enum
pip install -r requirements.txt
```

---

## Usage

```
python vamp_cloud_enum.py -d DOMAIN [OPTIONS]

Target (required, repeatable):
  -d, --domain DOMAIN            Target domain — use multiple times for multiple domains

Wordlist:
  -w, --wordlist FILE            Custom wordlist for bucket name generation

Provider selection:
      --providers PROVIDER,...   Comma-separated: s3, azure, gcp (default: all)

Performance:
      --concurrency N            Concurrent HTTP workers (default: 30)
      --timeout N                Per-request timeout in seconds (default: 8)

Analysis control:
      --no-content-listing       Skip directory listing detection probes

Output:
      --json FILE                Write findings to JSON
      --html FILE                Generate standalone HTML report
```

---

## Examples

Enumerate all providers for a single target domain:

```bash
python vamp_cloud_enum.py -d example.com
```

Enumerate multiple domains and generate a JSON report:

```bash
python vamp_cloud_enum.py -d example.com -d subsidiary.com -o cloud_findings.json
```

Check only AWS S3 with a custom wordlist:

```bash
python vamp_cloud_enum.py -d example.com --providers s3 -w corp_names.txt
```

Full enumeration with HTML report for client delivery:

```bash
python vamp_cloud_enum.py -d example.com -d example-cdn.com \
  --providers s3,azure,gcp \
  --concurrency 50 \
  --html cloud_report.html
```

---

## Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with provider, bucket name, status, listing, and severity |
| JSON | `--json FILE` | Full structured findings with URL, provider, status code, and keywords found |
| HTML | `--html FILE` | Standalone dark-theme report for client delivery or archival |

---

## Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No public buckets found | Pass gate |
| `1` | HIGH findings — public bucket without listing | Escalate to owner |
| `2` | CRITICAL findings — listing enabled or sensitive-name public bucket | Fail gate — immediate action required |

---

## Severity Model

| Severity | Condition |
|----------|-----------|
| CRITICAL | Bucket is PUBLIC and directory listing is enabled, **or** public bucket name contains sensitive keywords |
| HIGH | Bucket is PUBLIC — accessible but listing is disabled |
| MEDIUM | Bucket is PRIVATE but name contains sensitive keywords (namespace exposure) |
| LOW | Bucket namespace exists but content is fully private |

---

## Part of VampSecure Labs Toolkit

`vamp-cloud-enum` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/belky-me/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/belky-me/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/belky-me/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/belky-me/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/belky-me/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/belky-me/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>
