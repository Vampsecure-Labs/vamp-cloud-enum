<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->
<p align="center">
  <img src="https://img.shields.io/badge/version-1.4-crimson?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/providers-AWS%20%7C%20Azure%20%7C%20GCP-teal?style=flat-square" />
  <img src="https://img.shields.io/badge/VampSecure_Labs-Security_Research-8b0000?style=flat-square" />
  <img src="https://github.com/Vampsecure-Labs/vamp-cloud-enum/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</p>

<h1 align="center">vamp-cloud-enum</h1>
<p align="center"><em>Cloud Storage Bucket Enumerator — VampSecure Labs</em></p>

**VampSecure Labs · Security Research Division**

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

**vamp-cloud-enum** discovers and audits misconfigured cloud storage buckets across AWS S3, Azure Blob Storage, and Google Cloud Storage. Starting from one or more target domain names, the tool generates a candidate bucket name wordlist (40+ suffix and prefix permutations) and probes each combination across all three cloud providers simultaneously.

For each bucket found, the tool determines whether it is publicly accessible, whether directory listing is enabled, and whether the bucket name or exposed contents contain sensitive keywords — escalating severity accordingly. Public buckets with listing enabled are classified as CRITICAL; exposed namespaces without listing are classified based on sensitive-keyword presence.

---

### Features

- Three-provider coverage: AWS S3 (virtual-hosted, path-style, listing API, website endpoint), Azure Blob Storage (account and container enumeration), GCP Cloud Storage (path-style and virtual-hosted)
- 40+ bucket name candidates generated from target domain permutations
- Sensitive keyword detection for automatic severity escalation (backup, credentials, private, secret, config, etc.)
- Custom wordlist support for organization-specific naming conventions
- Provider filtering — run against a single provider or all three
- Content listing detection — distinguishes PUBLIC (browseable) from PUBLIC (opaque)
- Configurable concurrency and timeout for rate-sensitive environments

---

### Requirements

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

### Installation

```bash
pip install vamp-cloud-enum
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-cloud-enum
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-cloud-enum.git
cd vamp-cloud-enum
pip install -r requirements.txt
```

---

### Usage

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

### Examples

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

### Output Formats

| Format | How to enable | Description |
|--------|---------------|-------------|
| Console | Default | Rich table with provider, bucket name, status, listing, and severity |
| JSON | `--json FILE` | Full structured findings with URL, provider, status code, and keywords found |
| HTML | `--html FILE` | Standalone dark-theme report for client delivery or archival |

---

### Exit Codes

| Code | Meaning | CI/CD usage |
|------|---------|-------------|
| `0` | No public buckets found | Pass gate |
| `1` | HIGH findings — public bucket without listing | Escalate to owner |
| `2` | CRITICAL findings — listing enabled or sensitive-name public bucket | Fail gate — immediate action required |

---

### Severity Model

| Severity | Condition |
|----------|-----------|
| CRITICAL | Bucket is PUBLIC and directory listing is enabled, **or** public bucket name contains sensitive keywords |
| HIGH | Bucket is PUBLIC — accessible but listing is disabled |
| MEDIUM | Bucket is PRIVATE but name contains sensitive keywords (namespace exposure) |
| LOW | Bucket namespace exists but content is fully private |

---

### Sample Output

```bash
$ python vamp_cloud_enum.py -d example.com --providers s3,azure,gcp
  vamp-cloud-enum v1.4 — Cloud Storage Bucket Enumerator
  Target: example.com | Providers: S3 · Azure · GCP
  Generating 43 candidate bucket names...
  ────────────────────────────────────────────────────────────

  [CRITICAL] S3 — example-com-backup
    URL: https://example-com-backup.s3.amazonaws.com
    Status: PUBLIC · Listing: ENABLED
    Keywords detected: backup
    Objects visible: 47  (includes .sql.gz, .tar.gz, config/)

  [HIGH]     S3 — example-assets
    URL: https://example-assets.s3.amazonaws.com
    Status: PUBLIC · Listing: disabled
    Keywords: none

  [MEDIUM]   Azure — examplecomcredentials
    URL: https://examplecomcredentials.blob.core.windows.net
    Status: PRIVATE · Namespace: exposed
    Keywords detected: credentials

  ────────────────────────────────────────────────────────────
  Candidates tested: 129 (43 × 3 providers) | Buckets found: 3
  CRITICAL: 1 | HIGH: 1 | MEDIUM: 1 | Duration: 4.2 s
  Exit code: 2
```

---

### Why vamp-cloud-enum vs. CloudEnum · S3Scanner · GrayhatWarfare

| Feature | vamp-cloud-enum | CloudEnum | S3Scanner | GrayhatWarfare |
|---------|:---------------:|:---------:|:---------:|:--------------:|
| AWS S3 enumeration | ✅ | ✅ | ✅ | ✅ |
| Azure Blob Storage | ✅ | ✅ | ❌ | ⚠️ search only |
| GCP Cloud Storage | ✅ | ✅ | ❌ | ⚠️ search only |
| Sensitive keyword severity escalation | ✅ | ❌ | ❌ | ❌ |
| Directory listing detection | ✅ | ⚠️ | ✅ | ❌ |
| Async concurrent probing (aiohttp) | ✅ | ❌ sync | ❌ | n/a |
| Standalone HTML report | ✅ dark theme | ❌ | ❌ | ✅ web UI |
| OWASP Cloud Top 10 mapping | ✅ | ❌ | ❌ | ❌ |
| CIS Cloud Foundations alignment | ✅ | ❌ | ❌ | ❌ |
| Self-hosted / no account required | ✅ | ✅ | ✅ | ❌ SaaS |

- **Severity escalation**: automatic CRITICAL upgrade when an exposed bucket name contains sensitive keywords (`backup`, `secret`, `credentials`, `config`, `private`) — surfaces the highest-impact findings without manual triage.
- **Async three-provider sweep**: all three cloud providers are probed simultaneously per candidate, not in sequence — 43 candidates × 3 providers in under 5 seconds.
- **Client-ready HTML**: dark-theme standalone report is the only format in this category suitable for immediate pentest deliverable inclusion.

---

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| CE-001 | S3 bucket publicly accessible with directory listing enabled | OWASP Cloud C4 | CRITICAL |
| CE-002 | Azure Blob container public with listing (anonymous read+list) | OWASP Cloud C4 · CIS Azure 3.3 | CRITICAL |
| CE-003 | GCP bucket public with object listing enabled | CIS GCP 5.1 | CRITICAL |
| CE-004 | S3 bucket public but listing disabled (opaque public) | OWASP Cloud C5 | HIGH |
| CE-005 | Azure Blob public without listing (unauthenticated read) | CIS Azure 3.3 | HIGH |
| CE-006 | GCP bucket public without listing enabled | CIS GCP 5.2 | HIGH |
| CE-007 | S3 website endpoint active (unauthenticated index.html) | OWASP Cloud C4 | HIGH |
| CE-008 | Private bucket with sensitive keyword in name (namespace leak) | OWASP Cloud C5 | MEDIUM |
| CE-009 | Bucket namespace exposed — private, no sensitive keywords | CIS Cloud L1 | LOW |
| CE-010 | Multiple public buckets sharing the same domain root | CIS Cloud Foundations 2.1 | HIGH |

---

### Part of VampSecure Labs Toolkit

`vamp-cloud-enum` is part of the **VampSecure Labs Security Research Toolkit** — a collection of professional-grade, self-hosted security assessment tools.

| Tool | Purpose |
|------|---------|
| [vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) | Multi-vendor edge device CVE scanner |
| [vamp-cve-oracle](https://github.com/Vampsecure-Labs/vamp-cve-oracle) | CVE intelligence and RBVM engine |
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Passive recon and attack surface mapping |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Subdomain takeover vulnerability scanner |
| [vamp-cloud-enum](https://github.com/Vampsecure-Labs/vamp-cloud-enum) | Cloud storage bucket enumerator |
| [vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator) | Multi-tool assessment orchestrator |

---

### Version History

| Version | Main changes |
|---------|-------------|
| v1.4 | Bilingual README (EN/ES) |
| v1.3 | GCP Cloud Functions detection |
| v1.1 | Cloud Storage Bucket Enumerator — AWS S3, Azure, GCP |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  For authorized security assessments only. Unauthorized use is prohibited.
</p>

---
---

<a name="español"></a>
## 🇪🇸 Español

**vamp-cloud-enum** descubre y audita buckets de almacenamiento cloud mal configurados en AWS S3, Azure Blob Storage y Google Cloud Storage. A partir de uno o más dominios objetivo, la herramienta genera una lista de candidatos de nombres de bucket (más de 40 permutaciones de sufijos y prefijos) y prueba cada combinación en los tres proveedores simultáneamente.

Para cada bucket encontrado, determina si es públicamente accesible, si el listado de directorios está habilitado y si el nombre del bucket o el contenido expuesto contiene palabras clave sensibles — escalando la severidad según corresponda. Los buckets públicos con listado habilitado se clasifican como CRITICAL; los espacios de nombres expuestos sin listado se clasifican según la presencia de palabras clave sensibles.

---

### Características

- Cobertura de tres proveedores: AWS S3 (virtual-hosted, path-style, listing API, website endpoint), Azure Blob Storage (enumeración de cuentas y contenedores), GCP Cloud Storage (path-style y virtual-hosted)
- Más de 40 nombres candidatos de bucket generados a partir de permutaciones del dominio objetivo
- Detección de palabras clave sensibles para escalado automático de severidad (backup, credentials, private, secret, config, etc.)
- Soporte de wordlist personalizada para convenciones de nomenclatura específicas de la organización
- Filtrado por proveedor — ejecutar contra un solo proveedor o los tres
- Detección de listado de contenido — distingue PÚBLICO (navegable) de PÚBLICO (opaco)
- Concurrencia y timeout configurables para entornos sensibles a la tasa de peticiones

---

### Requisitos

```
Python 3.11+
aiohttp >= 3.9.0
rich >= 13.7.0
```

Instalar dependencias:

```bash
pip install -r requirements.txt
```

---

### Instalación

```bash
pip install vamp-cloud-enum
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-cloud-enum
```

```bash
git clone https://github.com/Vampsecure-Labs/vamp-cloud-enum.git
cd vamp-cloud-enum
pip install -r requirements.txt
```

---

### Uso

```
python vamp_cloud_enum.py -d DOMINIO [OPCIONES]

Objetivo (obligatorio, repetible):
  -d, --domain DOMINIO           Dominio objetivo — usar varias veces para múltiples dominios

Wordlist:
  -w, --wordlist FICHERO         Wordlist personalizada para la generación de nombres de bucket

Selección de proveedor:
      --providers PROVEEDOR,...  Lista separada por comas: s3, azure, gcp (por defecto: todos)

Rendimiento:
      --concurrency N            Workers HTTP concurrentes (por defecto: 30)
      --timeout N                Timeout por petición en segundos (por defecto: 8)

Control de análisis:
      --no-content-listing       Omitir sondas de detección de listado de directorios

Salida:
      --json FICHERO             Escribir hallazgos en JSON
      --html FICHERO             Generar informe HTML standalone
```

---

### Ejemplos

Enumerar todos los proveedores para un dominio objetivo:

```bash
python vamp_cloud_enum.py -d ejemplo.com
```

Enumerar múltiples dominios y generar un informe JSON:

```bash
python vamp_cloud_enum.py -d ejemplo.com -d filial.com -o hallazgos_cloud.json
```

Comprobar solo AWS S3 con una wordlist personalizada:

```bash
python vamp_cloud_enum.py -d ejemplo.com --providers s3 -w nombres_empresa.txt
```

Enumeración completa con informe HTML para entrega al cliente:

```bash
python vamp_cloud_enum.py -d ejemplo.com -d ejemplo-cdn.com \
  --providers s3,azure,gcp \
  --concurrency 50 \
  --html informe_cloud.html
```

---

### Formatos de salida

| Formato | Cómo activar | Descripción |
|---------|--------------|-------------|
| Consola | Por defecto | Tabla Rich con proveedor, nombre de bucket, estado, listado y severidad |
| JSON | `--json FICHERO` | Hallazgos estructurados completos con URL, proveedor, código de estado y palabras clave encontradas |
| HTML | `--html FICHERO` | Informe standalone dark-theme para entrega al cliente o archivo |

---

### Exit codes

| Código | Significado | Uso en CI/CD |
|--------|-------------|--------------|
| `0` | No se encontraron buckets públicos | Pasa el gate |
| `1` | Hallazgos HIGH — bucket público sin listado | Escalar al responsable |
| `2` | Hallazgos CRITICAL — listado habilitado o bucket público con nombre sensible | Falla el gate — acción inmediata requerida |

---

### Modelo de severidad

| Severidad | Condición |
|-----------|-----------|
| CRITICAL | El bucket es PÚBLICO y el listado de directorios está habilitado, **o** el nombre del bucket público contiene palabras clave sensibles |
| HIGH | El bucket es PÚBLICO — accesible pero sin listado |
| MEDIUM | El bucket es PRIVADO pero el nombre contiene palabras clave sensibles (exposición de namespace) |
| LOW | El namespace del bucket existe pero el contenido es completamente privado |

---

### Salida de ejemplo

```bash
$ python vamp_cloud_enum.py -d ejemplo.com --providers s3,azure,gcp
  vamp-cloud-enum v1.4 — Cloud Storage Bucket Enumerator
  Target: ejemplo.com | Providers: S3 · Azure · GCP
  Generando 43 nombres candidatos de bucket...
  ────────────────────────────────────────────────────────────

  [CRITICAL] S3 — ejemplo-com-backup
    URL: https://ejemplo-com-backup.s3.amazonaws.com
    Status: PUBLIC · Listing: ENABLED
    Keywords detected: backup
    Objects visible: 47  (incluye .sql.gz, .tar.gz, config/)

  [HIGH]     S3 — ejemplo-assets
    URL: https://ejemplo-assets.s3.amazonaws.com
    Status: PUBLIC · Listing: disabled
    Keywords: none

  [MEDIUM]   Azure — ejemplocomcredentials
    URL: https://ejemplocomcredentials.blob.core.windows.net
    Status: PRIVATE · Namespace: exposed
    Keywords detected: credentials

  ────────────────────────────────────────────────────────────
  Candidatos probados: 129 (43 × 3 providers) | Buckets encontrados: 3
  CRITICAL: 1 | HIGH: 1 | MEDIUM: 1 | Duración: 4.2 s
  Exit code: 2
```

---

### Why vamp-cloud-enum vs. CloudEnum · S3Scanner · GrayhatWarfare

| Feature | vamp-cloud-enum | CloudEnum | S3Scanner | GrayhatWarfare |
|---------|:---------------:|:---------:|:---------:|:--------------:|
| AWS S3 enumeration | ✅ | ✅ | ✅ | ✅ |
| Azure Blob Storage | ✅ | ✅ | ❌ | ⚠️ solo búsqueda |
| GCP Cloud Storage | ✅ | ✅ | ❌ | ⚠️ solo búsqueda |
| Sensitive keyword severity escalation | ✅ | ❌ | ❌ | ❌ |
| Directory listing detection | ✅ | ⚠️ | ✅ | ❌ |
| Async concurrent probing (aiohttp) | ✅ | ❌ sync | ❌ | n/a |
| Standalone HTML report | ✅ dark theme | ❌ | ❌ | ✅ web UI |
| OWASP Cloud Top 10 mapping | ✅ | ❌ | ❌ | ❌ |
| CIS Cloud Foundations alignment | ✅ | ❌ | ❌ | ❌ |
| Self-hosted / no account required | ✅ | ✅ | ✅ | ❌ SaaS |

- **Escalado de severidad**: upgrade automático a CRITICAL cuando el nombre de un bucket expuesto contiene palabras clave sensibles (`backup`, `secret`, `credentials`, `config`, `private`) — permite detectar los hallazgos de mayor impacto sin triaje manual.
- **Barrido asíncrono de tres proveedores**: los tres proveedores cloud se sondean simultáneamente por candidato, no en secuencia — 43 candidatos × 3 proveedores en menos de 5 segundos.
- **HTML listo para cliente**: el informe standalone dark-theme es el único formato de esta categoría adecuado para su inclusión directa en entregables de pentest.

---

### Check Coverage

| Check ID | Description | Standard | Severity |
|----------|-------------|----------|----------|
| CE-001 | S3 bucket publicly accessible with directory listing enabled | OWASP Cloud C4 | CRITICAL |
| CE-002 | Azure Blob container public with listing (anonymous read+list) | OWASP Cloud C4 · CIS Azure 3.3 | CRITICAL |
| CE-003 | GCP bucket public with object listing enabled | CIS GCP 5.1 | CRITICAL |
| CE-004 | S3 bucket public but listing disabled (opaque public) | OWASP Cloud C5 | HIGH |
| CE-005 | Azure Blob public without listing (unauthenticated read) | CIS Azure 3.3 | HIGH |
| CE-006 | GCP bucket public without listing enabled | CIS GCP 5.2 | HIGH |
| CE-007 | S3 website endpoint active (unauthenticated index.html) | OWASP Cloud C4 | HIGH |
| CE-008 | Private bucket with sensitive keyword in name (namespace leak) | OWASP Cloud C5 | MEDIUM |
| CE-009 | Bucket namespace exposed — private, no sensitive keywords | CIS Cloud L1 | LOW |
| CE-010 | Multiple public buckets sharing the same domain root | CIS Cloud Foundations 2.1 | HIGH |

---

### Parte del toolkit VampSecure Labs

`vamp-cloud-enum` es parte del **toolkit de investigación de seguridad de VampSecure Labs** — una colección de herramientas de evaluación de seguridad profesionales y auto-hospedadas.

| Herramienta | Propósito |
|-------------|-----------|
| [vamp-forticheck](https://github.com/Vampsecure-Labs/vamp-forticheck) | Escáner CVE multi-vendor de dispositivos de borde |
| [vamp-cve-oracle](https://github.com/Vampsecure-Labs/vamp-cve-oracle) | Inteligencia CVE y motor RBVM |
| [vamp-passive-recon](https://github.com/Vampsecure-Labs/vamp-passive-recon) | Reconocimiento pasivo y mapeo de superficie de ataque |
| [vamp-subdomain-takeover](https://github.com/Vampsecure-Labs/vamp-subdomain-takeover) | Escáner de vulnerabilidades de subdomain takeover |
| [vamp-cloud-enum](https://github.com/Vampsecure-Labs/vamp-cloud-enum) | Enumerador de buckets de almacenamiento cloud |
| [vamp-orchestrator](https://github.com/Vampsecure-Labs/vamp-orchestrator) | Orquestador de evaluaciones multi-herramienta |

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.4 | README bilingüe (EN/ES) |
| v1.3 | Detección de GCP Cloud Functions |
| v1.1 | Cloud Storage Bucket Enumerator — AWS S3, Azure, GCP |

---

<p align="center">
  © VampSecure Studios — VampSecure Labs Security Research Division<br/>
  Solo para evaluaciones de seguridad autorizadas. El uso no autorizado está prohibido.
</p>
