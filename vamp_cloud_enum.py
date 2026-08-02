#!/usr/bin/env python3
"""
vamp_cloud_enum.py — Enumerador de Buckets/Blobs Cloud Públicos
================================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Herramienta de enumeración pasiva de almacenamiento cloud expuesto para los
principales proveedores: AWS S3, Azure Blob Storage y Google Cloud Storage.

Genera candidatos de nombre de bucket a partir de un dominio o nombre de
empresa objetivo, combinándolos con una lista de sufijos/prefijos habituales,
y verifica de forma concurrente cuáles están accesibles públicamente sin
autenticación (lectura libre o listado de contenido habilitado).

Todas las comprobaciones son PASIVAS: únicamente se realizan peticiones HEAD
y GET de sólo lectura. No se sube, modifica ni elimina ningún dato.

ARQUITECTURA DE EJECUCIÓN
--------------------------
  Fase 1 — Generación de candidatos
    Para cada objetivo (-d), genera combinaciones nombre+sufijos/prefijos.
    También acepta lista de nombres personalizados (--wordlist).

  Fase 2 — Sondeo concurrente (asyncio + aiohttp)
    Hasta --concurrency peticiones simultáneas. Timeout configurable por
    petición. Controla el semáforo para no saturar el proveedor.

  Fase 3 — Clasificación y reporte
    Asigna severidad por resultado (CRITICAL/HIGH/MEDIUM/LOW/INFO).
    Muestra tabla Rich en consola, exporta JSON, HTML dark-theme y el
    informe unificado VSL (formato de entrega al cliente).

PROVEEDORES SOPORTADOS
-----------------------
  · AWS S3         — HEAD/GET en *.s3.amazonaws.com y s3.amazonaws.com/{bucket}
                     Verificación de listado (?list-type=2), website endpoint
  · Azure Blob     — HEAD en *.blob.core.windows.net, listado por container
                     (?restype=container&comp=list) en containers habituales
  · GCP Storage    — GET en storage.googleapis.com/{bucket} y *.storage.googleapis.com
                     Detección de ListBucketResult vs AccessDenied vs NoSuchBucket

SEVERIDAD
----------
  CRITICAL : Bucket con listado público habilitado o acceso total de lectura
  HIGH     : Bucket accesible (200) sin listado
  MEDIUM   : Bucket existente con nombre sensible (backup, secrets, db…)
  LOW      : Bucket existe pero es privado (403 → namespace expuesto)
  INFO     : Sin hallazgos

DEPENDENCIAS
------------
  aiohttp >= 3.9.0  — cliente HTTP asíncrono
  rich    >= 13.7.0 — salida de consola enriquecida, progress bar

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import json as _json_mod
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from vampsec_report import (
    Finding as VSLFinding,
    VampSecReport,
    add_report_args,
    meta_from_args,
)

# =============================================================================
# CONSTANTES Y CONFIGURACIÓN
# =============================================================================

VERSION   = "1.0"
TOOL_NAME = "vamp-cloud-enum"
AUTHOR    = "© VampSecure Studios — VampSecure Labs Security Research Division"

console = Console()

BANNER = r"""
  __   ___   __  __ ____     ____ _     ___  _   _ ____       _____ _   _ _   _ __  __
  \ \ / / \ / / |  \/  |  _ / ___| |   / _ \| | | |  _ \     | ____| \ | | | | |  \/  |
   \ V / _ ` /  | |\/| | (_) |   | |  | | | | | | | | | |    |  _| |  \| | | | | |\/| |
    | | (_| |   | |  | |_/ /| |___| |__| |_| | |_| | |_| |   | |___| |\  | |_| | |  | |
    |_|\__,_|   |_|  |_(_)  \____|_____\___/ \___/|____/    |_____|_| \_|\___/|_|  |_|
      by VampSecure Studios · vamp-cloud-enum v1.0 · Cloud Bucket Enumerator
      ─────────────────────────────────────────────────────────────────────
      USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Sufijos/prefijos estándar de uso habitual en nombres de bucket
BUCKET_SUFFIXES: List[str] = [
    "assets", "backup", "backups", "bak", "data", "db", "dev", "docs",
    "downloads", "files", "images", "img", "internal", "logs", "media",
    "private", "prod", "public", "releases", "staging", "static", "storage",
    "test", "uploads", "web", "www", "cdn", "config", "secrets", "archive",
    "bucket", "s3", "store", "resources", "content", "api", "build", "cache",
    "temp", "tmp", "dump", "export", "import", "raw", "source", "deploy",
]

# Nombres de container Azure habituales a comprobar dentro de cada cuenta
AZURE_CONTAINERS: List[str] = [
    "$web", "public", "files", "uploads", "static", "assets", "backup", "data",
]

# Regiones S3 para el endpoint de website estático
S3_WEBSITE_REGIONS: List[str] = ["us-east-1", "eu-west-1"]

# Palabras clave que elevan la severidad de un bucket privado a MEDIUM
SENSITIVE_KEYWORDS: set = {
    "backup", "backups", "bak", "db", "secret", "secrets", "config",
    "private", "internal", "prod", "dump", "export", "import", "key",
    "keys", "password", "passwords", "credentials", "creds",
}

# Cabeceras de interés para evidencias
HEADERS_OF_INTEREST: List[str] = [
    "content-type", "x-amz-bucket-region", "x-amz-request-id",
    "x-ms-request-id", "x-ms-version", "x-ms-error-code",
    "x-goog-request-id", "x-goog-stored-content-length",
    "last-modified", "server",
]


# =============================================================================
# DATACLASSES
# =============================================================================

@dataclass
class BucketResult:
    """
    Resultado de la comprobación de un candidato de bucket/blob en un proveedor.

    Attributes
    ----------
    name         : Nombre del bucket candidato
    provider     : Proveedor cloud ("s3" / "azure" / "gcp")
    url          : URL completa que devolvió el resultado positivo
    status       : Estado lógico ("LISTING" / "PUBLIC" / "PRIVATE" / "NOT_FOUND")
    http_code    : Código HTTP obtenido
    headers      : Cabeceras relevantes de la respuesta
    body_snippet : Primeros 500 bytes del cuerpo (si es XML de listado)
    severity     : Severidad asignada (CRITICAL / HIGH / MEDIUM / LOW / INFO)
    finding_id   : Identificador del hallazgo (CLOUD-NNN)
    container    : Nombre del container (sólo Azure)
    """
    name         : str
    provider     : str
    url          : str
    status       : str
    http_code    : int
    headers      : Dict[str, str]
    body_snippet : str
    severity     : str
    finding_id   : str
    container    : str = ""


@dataclass
class CloudEnumResult:
    """
    Resultado agregado de la enumeración de buckets para un objetivo.

    Attributes
    ----------
    target          : Nombre o dominio objetivo
    buckets_checked : Número total de candidatos comprobados
    buckets_found   : Lista de BucketResult con acceso positivo (no NOT_FOUND)
    error           : Mensaje de error si la enumeración falló
    """
    target          : str
    buckets_checked : int
    buckets_found   : List[BucketResult] = field(default_factory=list)
    error           : Optional[str] = None


# =============================================================================
# GENERACIÓN DE CANDIDATOS
# =============================================================================

def _normalize_name(target: str) -> str:
    """
    Normaliza un dominio o nombre de empresa a un identificador válido
    para nombre de bucket: convierte puntos a guiones y pasa a minúsculas.
    """
    name = target.lower().strip()
    name = re.sub(r"[^a-z0-9\-]", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    return name


def _strip_tld_variants(target: str) -> List[str]:
    """
    Genera variantes del objetivo eliminando el TLD y sus partes.

    Ejemplo: "vampsecurestudios.com" → ["vampsecurestudios", "vampsecure"]
    Aplica heurísticas simples: elimina la última parte (TLD) y parte
    del dominio de segundo nivel si contiene un separador reconocible.
    """
    variants: List[str] = []
    parts = target.split(".")
    if len(parts) >= 2:
        # Sin TLD
        base = ".".join(parts[:-1])
        variants.append(base)
        # Si el dominio tiene subdivisiones con guion, tomar la primera parte
        base_norm = _normalize_name(base)
        sub_parts = base_norm.split("-")
        if len(sub_parts) >= 2:
            variants.append(sub_parts[0])
    return variants


def generate_bucket_candidates(
    targets: List[str],
    extra_suffixes: List[str] | None = None,
) -> List[Tuple[str, str]]:
    """
    Genera la lista completa de candidatos de nombre de bucket para los objetivos dados.

    Para cada objetivo genera:
      · {name}
      · {name}-{suffix} / {name}_{suffix}
      · {suffix}-{name} / {suffix}_{name}
      · {name}.{suffix}  (para GCP y Azure que permiten puntos)
      · Variantes sin TLD con los mismos patrones

    Devuelve una lista de tuplas (nombre_candidato, origen_objetivo) sin
    duplicados, manteniendo el orden de generación.

    Parameters
    ----------
    targets       : Lista de dominios o nombres de empresa
    extra_suffixes: Sufijos adicionales desde --wordlist
    """
    all_suffixes = list(BUCKET_SUFFIXES)
    if extra_suffixes:
        all_suffixes += [s.strip() for s in extra_suffixes if s.strip()]

    seen: set = set()
    candidates: List[Tuple[str, str]] = []

    def _add(name: str, origin: str) -> None:
        """Añade un candidato si no está ya en el conjunto."""
        if name and name not in seen and len(name) >= 3:
            seen.add(name)
            candidates.append((name, origin))

    for target in targets:
        # Variantes del nombre base
        names_to_try = [_normalize_name(target)]
        for variant in _strip_tld_variants(target):
            vn = _normalize_name(variant)
            if vn not in names_to_try:
                names_to_try.append(vn)

        for name in names_to_try:
            _add(name, target)
            for sfx in all_suffixes:
                _add(f"{name}-{sfx}", target)
                _add(f"{name}_{sfx}", target)
                _add(f"{sfx}-{name}", target)
                _add(f"{sfx}_{name}", target)
                _add(f"{name}.{sfx}", target)

    return candidates


# =============================================================================
# CLASIFICACIÓN DE SEVERIDAD
# =============================================================================

def _bucket_severity(name: str, status: str) -> str:
    """
    Determina la severidad de un hallazgo en función del estado del bucket
    y de si el nombre contiene palabras clave sensibles.

    CRITICAL : listado público o acceso completo de lectura
    HIGH     : bucket accesible (200) sin listado
    MEDIUM   : bucket privado con nombre sensible → namespace expuesto + dato
    LOW      : bucket privado (403) → namespace expuesto
    INFO     : no encontrado o sin relevancia
    """
    if status == "LISTING":
        return "CRITICAL"
    if status == "PUBLIC":
        name_lower = name.lower().replace("-", "_")
        parts = set(name_lower.replace(".", "_").split("_"))
        if parts & SENSITIVE_KEYWORDS:
            return "CRITICAL"
        return "HIGH"
    if status == "PRIVATE":
        name_lower = name.lower().replace("-", "_")
        parts = set(name_lower.replace(".", "_").split("_"))
        if parts & SENSITIVE_KEYWORDS:
            return "MEDIUM"
        return "LOW"
    return "INFO"


# =============================================================================
# MÓDULO DE SONDEO — AWS S3
# =============================================================================

class S3Prober:
    """
    Módulo de sondeo pasivo para buckets AWS S3.

    Comprueba acceso público mediante HEAD y listado de contenido con GET.
    También verifica el endpoint de website estático en las regiones más comunes.
    """

    _UA = f"{TOOL_NAME}/{VERSION} VampSecureLabs"

    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: int,
        check_listing: bool,
    ) -> None:
        self._session      = session
        self._timeout      = aiohttp.ClientTimeout(total=timeout)
        self._check_listing = check_listing

    async def probe(self, name: str) -> Optional[BucketResult]:
        """
        Ejecuta todas las comprobaciones S3 sobre el nombre de bucket dado.

        Devuelve el BucketResult más severo encontrado, o None si el bucket
        no existe en ninguno de los endpoints probados.
        """
        results: List[BucketResult] = []

        # 1. Endpoint virtual-hosted
        r = await self._check_virtual_hosted(name)
        if r:
            results.append(r)

        # 2. Endpoint path-style
        r2 = await self._check_path_style(name)
        if r2 and (not results or _sev_rank(r2.severity) < _sev_rank(results[0].severity)):
            results.append(r2)

        # 3. Listado de contenido
        if self._check_listing and not _any_status(results, "LISTING"):
            r3 = await self._check_listing_api(name)
            if r3:
                results.append(r3)

        # 4. Website endpoint
        r4 = await self._check_website(name)
        if r4:
            results.append(r4)

        if not results:
            return None

        # Devolver el resultado de mayor severidad
        results.sort(key=lambda x: _sev_rank(x.severity))
        return results[0]

    async def _check_virtual_hosted(self, name: str) -> Optional[BucketResult]:
        """HEAD a https://{name}.s3.amazonaws.com/ para detectar existencia."""
        url = f"https://{name}.s3.amazonaws.com/"
        try:
            async with self._session.head(
                url, timeout=self._timeout, allow_redirects=True,
                headers={"User-Agent": self._UA},
            ) as resp:
                if resp.status == 404:
                    body = await _safe_read(resp, 200)
                    if "NoSuchBucket" in body:
                        return None
                    # 404 sin NoSuchBucket puede indicar bucket inexistente
                    return None
                if resp.status == 403:
                    return _make_result(
                        name, "s3", url, "PRIVATE", resp.status,
                        _extract_headers(resp),
                        "",
                        _bucket_severity(name, "PRIVATE"),
                    )
                if resp.status == 200:
                    return _make_result(
                        name, "s3", url, "PUBLIC", resp.status,
                        _extract_headers(resp),
                        "",
                        _bucket_severity(name, "PUBLIC"),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None

    async def _check_path_style(self, name: str) -> Optional[BucketResult]:
        """GET a https://s3.amazonaws.com/{name}/ como endpoint path-style."""
        url = f"https://s3.amazonaws.com/{name}/"
        try:
            async with self._session.get(
                url, timeout=self._timeout, allow_redirects=True,
                headers={"User-Agent": self._UA},
            ) as resp:
                body = await _safe_read(resp, 500)
                if resp.status == 403:
                    if "NoSuchBucket" in body:
                        return None
                    return _make_result(
                        name, "s3", url, "PRIVATE", resp.status,
                        _extract_headers(resp), body,
                        _bucket_severity(name, "PRIVATE"),
                    )
                if resp.status == 200:
                    if "<ListBucketResult" in body:
                        return _make_result(
                            name, "s3", url, "LISTING", resp.status,
                            _extract_headers(resp), body[:500],
                            "CRITICAL",
                        )
                    return _make_result(
                        name, "s3", url, "PUBLIC", resp.status,
                        _extract_headers(resp), body[:500],
                        _bucket_severity(name, "PUBLIC"),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None

    async def _check_listing_api(self, name: str) -> Optional[BucketResult]:
        """GET con parámetros de listado para detectar listado público habilitado."""
        url = f"https://{name}.s3.amazonaws.com/?list-type=2&max-keys=5"
        try:
            async with self._session.get(
                url, timeout=self._timeout,
                headers={"User-Agent": self._UA},
            ) as resp:
                body = await _safe_read(resp, 500)
                if resp.status == 200 and "<ListBucketResult" in body:
                    return _make_result(
                        name, "s3", url, "LISTING", resp.status,
                        _extract_headers(resp), body[:500],
                        "CRITICAL",
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None

    async def _check_website(self, name: str) -> Optional[BucketResult]:
        """Comprueba el endpoint de website estático de S3 en regiones habituales."""
        for region in S3_WEBSITE_REGIONS:
            url = f"http://{name}.s3-website.{region}.amazonaws.com/"
            try:
                async with self._session.get(
                    url, timeout=self._timeout,
                    headers={"User-Agent": self._UA},
                ) as resp:
                    body = await _safe_read(resp, 300)
                    if resp.status == 200 and "NoSuchBucket" not in body:
                        return _make_result(
                            name, "s3", url, "PUBLIC", resp.status,
                            _extract_headers(resp), body[:300],
                            _bucket_severity(name, "PUBLIC"),
                        )
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        return None


# =============================================================================
# MÓDULO DE SONDEO — AZURE BLOB STORAGE
# =============================================================================

class AzureProber:
    """
    Módulo de sondeo pasivo para cuentas de almacenamiento Azure Blob Storage.

    Comprueba la existencia de la cuenta y, en los containers conocidos,
    si el listado público de blobs está habilitado.
    """

    _UA = f"{TOOL_NAME}/{VERSION} VampSecureLabs"

    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: int,
        check_listing: bool,
    ) -> None:
        self._session       = session
        self._timeout       = aiohttp.ClientTimeout(total=timeout)
        self._check_listing = check_listing

    async def probe(self, name: str) -> Optional[BucketResult]:
        """
        Ejecuta las comprobaciones Azure sobre el nombre de cuenta dado.

        Primero verifica la existencia de la cuenta de almacenamiento y luego,
        si existe, comprueba cada container conocido buscando acceso público.
        """
        # Los nombres Azure no pueden tener puntos o guiones bajos como S3/GCP
        # Normalizar: sólo letras y dígitos, 3-24 caracteres
        az_name = re.sub(r"[^a-z0-9]", "", name.lower())[:24]
        if len(az_name) < 3:
            return None

        base_url = f"https://{az_name}.blob.core.windows.net/"
        exists = await self._account_exists(az_name, base_url)
        if not exists:
            return None

        # Cuenta existe: comprobar containers
        best: Optional[BucketResult] = None

        for container in AZURE_CONTAINERS:
            r = await self._check_container(az_name, container)
            if r and (best is None or _sev_rank(r.severity) < _sev_rank(best.severity)):
                best = r
            if best and best.status == "LISTING":
                break  # Ya encontramos el peor caso

        if best:
            return best

        # Cuenta existe pero sin containers accesibles
        return _make_result(
            az_name, "azure", base_url, "PRIVATE", 200,
            {}, "",
            _bucket_severity(az_name, "PRIVATE"),
        )

    async def _account_exists(self, name: str, base_url: str) -> bool:
        """Verifica si la cuenta de almacenamiento Azure existe mediante HEAD."""
        try:
            async with self._session.head(
                base_url, timeout=self._timeout,
                headers={"User-Agent": self._UA},
            ) as resp:
                # 200 o 400 (con mensaje de error de Azure) → cuenta existe
                if resp.status in (200, 400, 403, 409):
                    return True
                # 404 con StorageErrorCode indica que no existe la cuenta
                if resp.status == 404:
                    return False
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return False

    async def _check_container(
        self, account: str, container: str
    ) -> Optional[BucketResult]:
        """
        Comprueba si un container concreto es accesible públicamente.
        Intenta listar blobs con restype=container&comp=list.
        """
        url = (
            f"https://{account}.blob.core.windows.net/"
            f"{container}?restype=container&comp=list&maxresults=5"
        )
        try:
            async with self._session.get(
                url, timeout=self._timeout,
                headers={"User-Agent": self._UA},
            ) as resp:
                body = await _safe_read(resp, 500)
                if resp.status == 200 and "<EnumerationResults" in body:
                    return _make_result(
                        account, "azure", url, "LISTING", resp.status,
                        _extract_headers(resp), body[:500],
                        "CRITICAL",
                        container=container,
                    )
                if resp.status == 200:
                    return _make_result(
                        account, "azure", url, "PUBLIC", resp.status,
                        _extract_headers(resp), body[:500],
                        _bucket_severity(account, "PUBLIC"),
                        container=container,
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None


# =============================================================================
# MÓDULO DE SONDEO — GCP CLOUD STORAGE
# =============================================================================

class GCPProber:
    """
    Módulo de sondeo pasivo para buckets Google Cloud Storage.

    Comprueba acceso mediante los dos endpoints públicos GCS:
      · https://storage.googleapis.com/{bucket}/
      · https://{bucket}.storage.googleapis.com/
    """

    _UA = f"{TOOL_NAME}/{VERSION} VampSecureLabs"

    def __init__(
        self,
        session: aiohttp.ClientSession,
        timeout: int,
        check_listing: bool,
    ) -> None:
        self._session       = session
        self._timeout       = aiohttp.ClientTimeout(total=timeout)
        self._check_listing = check_listing

    async def probe(self, name: str) -> Optional[BucketResult]:
        """
        Ejecuta las comprobaciones GCS sobre el nombre de bucket dado.

        Devuelve el BucketResult más severo encontrado, o None si el bucket
        no existe en ninguno de los endpoints.
        """
        results: List[BucketResult] = []

        r1 = await self._check_path_style(name)
        if r1:
            results.append(r1)

        r2 = await self._check_virtual_hosted(name)
        if r2 and (not results or _sev_rank(r2.severity) < _sev_rank(results[0].severity)):
            results.append(r2)

        if not results:
            return None

        results.sort(key=lambda x: _sev_rank(x.severity))
        return results[0]

    async def _check_path_style(self, name: str) -> Optional[BucketResult]:
        """GET a https://storage.googleapis.com/{name}/"""
        url = f"https://storage.googleapis.com/{name}/"
        try:
            async with self._session.get(
                url, timeout=self._timeout,
                headers={"User-Agent": self._UA},
            ) as resp:
                body = await _safe_read(resp, 500)
                if resp.status == 404 and "NoSuchBucket" in body:
                    return None
                if resp.status == 403 and "AccessDenied" in body:
                    return _make_result(
                        name, "gcp", url, "PRIVATE", resp.status,
                        _extract_headers(resp), body[:300],
                        _bucket_severity(name, "PRIVATE"),
                    )
                if resp.status == 200:
                    if "<ListBucketResult" in body:
                        return _make_result(
                            name, "gcp", url, "LISTING", resp.status,
                            _extract_headers(resp), body[:500],
                            "CRITICAL",
                        )
                    return _make_result(
                        name, "gcp", url, "PUBLIC", resp.status,
                        _extract_headers(resp), body[:500],
                        _bucket_severity(name, "PUBLIC"),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None

    async def _check_virtual_hosted(self, name: str) -> Optional[BucketResult]:
        """GET a https://{name}.storage.googleapis.com/"""
        url = f"https://{name}.storage.googleapis.com/"
        try:
            async with self._session.get(
                url, timeout=self._timeout,
                headers={"User-Agent": self._UA},
            ) as resp:
                body = await _safe_read(resp, 500)
                if resp.status == 404 and "NoSuchBucket" in body:
                    return None
                if resp.status == 403 and "AccessDenied" in body:
                    return _make_result(
                        name, "gcp", url, "PRIVATE", resp.status,
                        _extract_headers(resp), body[:300],
                        _bucket_severity(name, "PRIVATE"),
                    )
                if resp.status == 200:
                    if "<ListBucketResult" in body:
                        return _make_result(
                            name, "gcp", url, "LISTING", resp.status,
                            _extract_headers(resp), body[:500],
                            "CRITICAL",
                        )
                    return _make_result(
                        name, "gcp", url, "PUBLIC", resp.status,
                        _extract_headers(resp), body[:500],
                        _bucket_severity(name, "PUBLIC"),
                    )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        return None


# =============================================================================
# UTILIDADES INTERNAS
# =============================================================================

def _sev_rank(severity: str) -> int:
    """Devuelve el rango numérico de una severidad (menor = más severo)."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity, 99)


def _any_status(results: List[BucketResult], status: str) -> bool:
    """Comprueba si alguno de los resultados tiene el estado dado."""
    return any(r.status == status for r in results)


async def _safe_read(resp: aiohttp.ClientResponse, limit: int) -> str:
    """
    Lee hasta `limit` bytes del cuerpo de la respuesta de forma segura.
    Devuelve cadena vacía si hay error o el cuerpo está vacío.
    """
    try:
        raw = await resp.content.read(limit)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_headers(resp: aiohttp.ClientResponse) -> Dict[str, str]:
    """
    Extrae las cabeceras de interés de la respuesta aiohttp.
    Devuelve un diccionario con las cabeceras encontradas en minúsculas.
    """
    result: Dict[str, str] = {}
    for h in HEADERS_OF_INTEREST:
        val = resp.headers.get(h)
        if val:
            result[h] = val
    return result


_finding_counter = 0


def _make_result(
    name: str,
    provider: str,
    url: str,
    status: str,
    http_code: int,
    headers: Dict[str, str],
    body_snippet: str,
    severity: str,
    container: str = "",
) -> BucketResult:
    """
    Construye un BucketResult con un finding_id único correlativo.
    """
    global _finding_counter
    _finding_counter += 1
    return BucketResult(
        name         = name,
        provider     = provider,
        url          = url,
        status       = status,
        http_code    = http_code,
        headers      = headers,
        body_snippet = body_snippet,
        severity     = severity,
        finding_id   = f"CLOUD-{_finding_counter:03d}",
        container    = container,
    )


# =============================================================================
# MOTOR DE ENUMERACIÓN PRINCIPAL
# =============================================================================

class CloudEnumerator:
    """
    Orquestador de la enumeración de buckets cloud.

    Coordina los módulos de sondeo S3, Azure y GCP, gestiona el semáforo
    de concurrencia y actualiza el progress bar de Rich en tiempo real.
    """

    def __init__(
        self,
        providers: List[str],
        concurrency: int,
        timeout: int,
        check_listing: bool,
    ) -> None:
        self._providers     = providers
        self._concurrency   = concurrency
        self._timeout       = timeout
        self._check_listing = check_listing

    async def enumerate(
        self,
        candidates: List[Tuple[str, str]],
        progress: Progress,
        task_id,
    ) -> List[BucketResult]:
        """
        Comprueba todos los candidatos en todos los proveedores seleccionados,
        de forma concurrente con un semáforo de control.

        Parameters
        ----------
        candidates : Lista de (nombre_bucket, origen_objetivo)
        progress   : Barra de progreso Rich (para actualizar avance)
        task_id    : ID de la tarea en el progress bar

        Returns
        -------
        Lista de BucketResult donde status != NOT_FOUND
        """
        semaphore = asyncio.Semaphore(self._concurrency)
        found: List[BucketResult] = []

        connector = aiohttp.TCPConnector(
            limit=self._concurrency,
            ssl=False,           # desactivar verificación SSL para robustez
            enable_cleanup_closed=True,
        )
        async with aiohttp.ClientSession(connector=connector) as session:
            s3_prober    = S3Prober(session, self._timeout, self._check_listing)
            azure_prober = AzureProber(session, self._timeout, self._check_listing)
            gcp_prober   = GCPProber(session, self._timeout, self._check_listing)

            async def _probe_one(name: str) -> None:
                """Comprueba un candidato en todos los proveedores configurados."""
                async with semaphore:
                    for provider in self._providers:
                        try:
                            if provider == "s3":
                                result = await s3_prober.probe(name)
                            elif provider == "azure":
                                result = await azure_prober.probe(name)
                            elif provider == "gcp":
                                result = await gcp_prober.probe(name)
                            else:
                                result = None

                            if result and result.status != "NOT_FOUND":
                                found.append(result)
                        except Exception:
                            pass
                    progress.advance(task_id)

            tasks = [asyncio.create_task(_probe_one(name)) for name, _ in candidates]
            await asyncio.gather(*tasks, return_exceptions=True)

        return found


# =============================================================================
# SALIDA Y REPORTE
# =============================================================================

_STATUS_STYLE: Dict[str, str] = {
    "LISTING" : "bold red",
    "PUBLIC"  : "bold yellow",
    "PRIVATE" : "dim cyan",
    "NOT_FOUND": "dim",
}

_SEV_STYLE: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH"    : "bold yellow",
    "MEDIUM"  : "bold magenta",
    "LOW"     : "cyan",
    "INFO"    : "dim",
}

_PROVIDER_LABEL: Dict[str, str] = {
    "s3"   : "[bold orange1]AWS S3[/]",
    "azure": "[bold blue]Azure[/]",
    "gcp"  : "[bold green]GCP[/]",
}


def print_summary_table(results: List[BucketResult]) -> None:
    """
    Muestra la tabla de resumen de buckets encontrados agrupada por proveedor.
    """
    if not results:
        console.print("\n[dim]No se encontraron buckets/blobs accesibles.[/dim]\n")
        return

    tbl = Table(
        title=f"\n[bold]Buckets / Blobs Cloud Encontrados[/] — {len(results)} resultado(s)",
        show_header=True,
        header_style="bold",
        border_style="dim",
        expand=False,
    )
    tbl.add_column("ID",        style="dim", width=10)
    tbl.add_column("Bucket",    style="bold white", min_width=28)
    tbl.add_column("Proveedor", width=9)
    tbl.add_column("Estado",    width=10)
    tbl.add_column("HTTP",      width=5, justify="right")
    tbl.add_column("Severidad", width=10)
    tbl.add_column("URL",       no_wrap=False, min_width=30)

    # Ordenar: CRITICAL primero, luego por proveedor
    sorted_results = sorted(results, key=lambda r: (_sev_rank(r.severity), r.provider, r.name))

    for r in sorted_results:
        sev_text   = Text(r.severity, style=_SEV_STYLE.get(r.severity, ""))
        status_text = Text(r.status, style=_STATUS_STYLE.get(r.status, ""))
        tbl.add_row(
            r.finding_id,
            r.name + (f"\n[dim]container: {r.container}[/dim]" if r.container else ""),
            _PROVIDER_LABEL.get(r.provider, r.provider),
            status_text,
            str(r.http_code),
            sev_text,
            r.url,
        )

    console.print(tbl)


def print_critical_panels(results: List[BucketResult]) -> None:
    """
    Imprime paneles detallados para cada hallazgo CRITICAL o HIGH,
    con evidencia completa y recomendación de remediación.
    """
    top = [r for r in results if r.severity in ("CRITICAL", "HIGH")]
    if not top:
        return

    console.print()
    for r in sorted(top, key=lambda x: _sev_rank(x.severity)):
        remediation = _get_remediation(r)
        headers_str = "\n".join(f"  {k}: {v}" for k, v in r.headers.items()) or "  (sin cabeceras registradas)"
        body_str    = r.body_snippet[:400] if r.body_snippet else "(sin cuerpo)"

        contenido = (
            f"[bold]Bucket:[/]     {r.name}\n"
            f"[bold]Proveedor:[/]  {r.provider.upper()}\n"
            f"[bold]Estado:[/]     {r.status}\n"
            f"[bold]URL:[/]        {r.url}\n"
            f"[bold]HTTP:[/]       {r.http_code}\n"
            + (f"[bold]Container:[/] {r.container}\n" if r.container else "")
            + f"\n[bold]Cabeceras de interés:[/]\n{headers_str}\n"
            + f"\n[bold]Cuerpo (fragmento):[/]\n[dim]{body_str}[/dim]\n"
            + f"\n[bold yellow]Remediación:[/]\n{remediation}"
        )

        border = "red" if r.severity == "CRITICAL" else "yellow"
        console.print(Panel(
            contenido,
            title=f"[bold {border}]{r.finding_id} · {r.severity}[/] — {r.name}",
            border_style=border,
            expand=False,
        ))


def _get_remediation(r: BucketResult) -> str:
    """Devuelve el texto de remediación según el proveedor y el estado."""
    if r.provider == "s3":
        if r.status == "LISTING":
            return (
                "Deshabilitar el acceso de listado público en la consola de AWS S3:\n"
                "  · Bucket → Permissions → Block Public Access → habilitar todas las opciones\n"
                "  · Revisar la Bucket Policy y eliminar las cláusulas con 's3:GetObject' o "
                "'s3:ListBucket' abiertas a '*' (Principal: *).\n"
                "  · Auditar los objetos contenidos por si hay datos sensibles expuestos."
            )
        if r.status == "PUBLIC":
            return (
                "Restringir el acceso público al bucket:\n"
                "  · Habilitar 'Block Public Access' en AWS S3.\n"
                "  · Eliminar permisos ACL 'public-read' o 'public-read-write'.\n"
                "  · Revisar la Bucket Policy para accesos sin condición de autenticación."
            )
        return (
            "El bucket existe y su nombre está expuesto en el espacio de nombres de S3 (AWS).\n"
            "  · Confirmar que el acceso privado es intencional.\n"
            "  · Eliminar el bucket si ya no está en uso para reducir la superficie de ataque."
        )
    if r.provider == "azure":
        if r.status == "LISTING":
            return (
                "Deshabilitar el acceso público en Azure Blob Storage:\n"
                "  · Storage Account → Configuration → 'Allow Blob public access' → Disabled\n"
                "  · Revisar el nivel de acceso de cada container (Private / Blob / Container).\n"
                "  · Utilizar SAS Tokens o Azure AD para accesos controlados."
            )
        if r.status == "PUBLIC":
            return (
                "Restringir el nivel de acceso del container de Azure Blob:\n"
                "  · Cambiar el acceso del container a 'Private'.\n"
                "  · Deshabilitar 'Allow Blob public access' a nivel de cuenta."
            )
        return (
            "La cuenta de almacenamiento Azure existe y su nombre está expuesto.\n"
            "  · Confirmar que los containers tienen el nivel de acceso correcto.\n"
            "  · Eliminar la cuenta si ya no está en uso."
        )
    # GCP
    if r.status == "LISTING":
        return (
            "Eliminar el permiso allUsers en GCS:\n"
            "  · Cloud Console → Storage → Bucket → Permissions → Eliminar 'allUsers' y 'allAuthenticatedUsers'.\n"
            "  · Usar Cloud IAM con cuentas de servicio para accesos controlados.\n"
            "  · Habilitar 'Uniform bucket-level access' para mayor coherencia de permisos."
        )
    if r.status == "PUBLIC":
        return (
                "Restringir el acceso público al bucket GCS:\n"
                "  · Eliminar ACL y permisos IAM de 'allUsers'.\n"
                "  · Activar 'Uniform bucket-level access' en el bucket."
        )
    return (
        "El bucket GCS existe y su nombre está expuesto.\n"
        "  · Confirmar que los permisos IAM son correctos.\n"
        "  · Eliminar el bucket si ya no está en uso."
    )


# =============================================================================
# EXPORTACIÓN JSON / HTML DARK-THEME
# =============================================================================

def export_json(results: List[CloudEnumResult], path: str) -> None:
    """
    Exporta los resultados en formato JSON estructurado VSL.

    El fichero incluye metadatos de la ejecución, resumen por proveedor
    y la lista completa de hallazgos con toda la evidencia.
    """
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "schema"    : "vamp-cloud-enum-v1",
        "generated" : now,
        "tool"      : TOOL_NAME,
        "version"   : VERSION,
        "targets"   : list({r.target for r in results}),
        "summary"   : {
            "total_checked" : sum(r.buckets_checked for r in results),
            "total_found"   : sum(len(r.buckets_found) for r in results),
            "by_severity"   : _count_by(results, "severity"),
            "by_provider"   : _count_by(results, "provider"),
            "by_status"     : _count_by(results, "status"),
        },
        "results"   : [
            {
                "target"          : res.target,
                "buckets_checked" : res.buckets_checked,
                "error"           : res.error,
                "buckets"         : [
                    {
                        "finding_id"   : b.finding_id,
                        "name"         : b.name,
                        "provider"     : b.provider,
                        "url"          : b.url,
                        "status"       : b.status,
                        "http_code"    : b.http_code,
                        "severity"     : b.severity,
                        "headers"      : b.headers,
                        "body_snippet" : b.body_snippet,
                        "container"    : b.container,
                    }
                    for b in sorted(res.buckets_found, key=lambda x: _sev_rank(x.severity))
                ],
            }
            for res in results
        ],
    }
    Path(path).write_text(_json_mod.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _count_by(results: List[CloudEnumResult], attr: str) -> Dict[str, int]:
    """Cuenta hallazgos por un atributo dado del BucketResult."""
    counts: Dict[str, int] = {}
    for res in results:
        for b in res.buckets_found:
            key = getattr(b, attr, "unknown")
            counts[key] = counts.get(key, 0) + 1
    return counts


def export_html(results: List[CloudEnumResult], path: str) -> None:
    """
    Genera un informe HTML dark-theme standalone para vamp-cloud-enum.

    Incluye:
      · Cabecera con metadatos de la ejecución
      · Tabla de resumen con código de color por severidad
      · Tarjetas detalladas para cada hallazgo con evidencia y remediación
      · Completamente standalone: sin CDN ni dependencias externas
    """
    now         = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_buckets = sorted(
        [b for res in results for b in res.buckets_found],
        key=lambda x: (_sev_rank(x.severity), x.provider, x.name),
    )

    sev_colors = {
        "CRITICAL": "#c0392b",
        "HIGH"    : "#e67e22",
        "MEDIUM"  : "#8e44ad",
        "LOW"     : "#2980b9",
        "INFO"    : "#7f8c8d",
    }

    def badge(sev: str) -> str:
        color = sev_colors.get(sev, "#555")
        return (
            f'<span style="background:{color};color:#fff;padding:2px 8px;'
            f'border-radius:3px;font-size:.75em;font-weight:700">{sev}</span>'
        )

    filas = ""
    for b in all_buckets:
        filas += (
            f"<tr>"
            f"<td><code>{b.finding_id}</code></td>"
            f"<td>{b.name}{('<br><small style=color:#888>'+b.container+'</small>') if b.container else ''}</td>"
            f"<td style='text-transform:uppercase;font-size:.8em'>{b.provider}</td>"
            f"<td style='font-weight:700'>{b.status}</td>"
            f"<td style='text-align:center'>{b.http_code}</td>"
            f"<td>{badge(b.severity)}</td>"
            f"<td style='font-size:.8em;word-break:break-all'><a href='{b.url}' style='color:#5dade2'>{b.url}</a></td>"
            f"</tr>\n"
        )

    tarjetas = ""
    for b in all_buckets:
        if b.severity not in ("CRITICAL", "HIGH"):
            continue
        color     = sev_colors.get(b.severity, "#888")
        hdrs      = "\n".join(f"{k}: {v}" for k, v in b.headers.items()) or "(sin cabeceras)"
        rem       = _get_remediation(b).replace("\n", "<br>").replace("  ·", "&nbsp;&nbsp;·")
        container = f"<p><strong>Container:</strong> {b.container}</p>" if b.container else ""
        tarjetas += f"""
<div style="border:1px solid #333;border-left:4px solid {color};border-radius:6px;margin:14px 0;overflow:hidden">
  <div style="background:#1e1e2e;padding:12px 16px;display:flex;gap:10px;align-items:center">
    <code style="color:#888;font-size:.8em">{b.finding_id}</code>
    <strong style="flex:1">{b.name}</strong>
    {badge(b.severity)}
  </div>
  <div style="padding:14px 16px;font-size:.88em">
    <p><strong>Proveedor:</strong> {b.provider.upper()}</p>
    <p><strong>Estado:</strong> {b.status}</p>
    <p><strong>URL:</strong> <a href="{b.url}" style="color:#5dade2">{b.url}</a></p>
    {container}
    <p><strong>HTTP:</strong> {b.http_code}</p>
    <details style="margin-top:10px"><summary style="cursor:pointer;color:#aaa">Cabeceras de interés</summary>
      <pre style="background:#111;padding:8px;border-radius:4px;font-size:.8em">{hdrs}</pre>
    </details>
    {'<details style="margin-top:10px"><summary style="cursor:pointer;color:#aaa">Fragmento de respuesta</summary><pre style="background:#111;padding:8px;border-radius:4px;font-size:.8em;white-space:pre-wrap">' + b.body_snippet[:500] + '</pre></details>' if b.body_snippet else ''}
    <div style="margin-top:12px;background:#0d2b1a;padding:10px 12px;border-radius:4px;font-size:.85em">
      <strong style="color:#2ecc71">Remediación:</strong><br>{rem}
    </div>
  </div>
</div>"""

    targets_str = ", ".join({r.target for r in results})
    total_found = len(all_buckets)
    total_checked = sum(r.buckets_checked for r in results)

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>vamp-cloud-enum — Informe Cloud Enum — {now}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,monospace;
        background:#0d0d1a;color:#d0d0e8;line-height:1.65;font-size:14px}}
  a{{color:#5dade2;text-decoration:none}}
  code{{font-family:'Courier New',monospace;background:#1a1a2e;
        padding:1px 5px;border-radius:3px;font-size:.88em}}
  pre{{background:#111;border:1px solid #2a2a3e;border-radius:4px;
       padding:10px;font-size:.8em;white-space:pre-wrap;word-break:break-all}}
  .wrap{{max-width:1100px;margin:0 auto;padding:0 0 60px}}
  .header{{background:linear-gradient(140deg,#0d0d1a 0%,#1a0a0a 60%,#3a0505 100%);
           padding:40px 32px 32px;border-bottom:2px solid #c0392b}}
  .header h1{{font-size:1.6em;color:#fff;margin-bottom:4px}}
  .header p{{font-size:.85em;color:#888}}
  .section{{padding:24px 32px;border-bottom:1px solid #1e1e2e}}
  .section h2{{font-size:1em;color:#c0392b;text-transform:uppercase;
               letter-spacing:.6px;margin-bottom:16px}}
  .kpis{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
  .kpi{{background:#1a1a2e;border:1px solid #2a2a3e;border-radius:6px;
        padding:12px 18px;text-align:center;min-width:100px}}
  .kv{{font-size:2em;font-weight:700;color:#fff}}
  .kl{{font-size:.7em;color:#666;text-transform:uppercase;letter-spacing:.4px;margin-top:2px}}
  table{{width:100%;border-collapse:collapse;font-size:.84em}}
  th{{background:#111;color:#666;padding:8px 10px;text-align:left;
      border-bottom:2px solid #222;font-size:.76em;text-transform:uppercase;
      letter-spacing:.4px;font-weight:700}}
  td{{padding:8px 10px;border-bottom:1px solid #1a1a2a;vertical-align:top}}
  tr:hover td{{background:#111}}
  .brand{{padding:20px 32px;font-size:.72em;color:#444;border-top:1px solid #1a1a2e;margin-top:20px}}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
  <h1>&#x2601; vamp-cloud-enum v{VERSION} — Cloud Bucket Enumerator</h1>
  <p>Generado: {now} &nbsp;·&nbsp; Objetivos: {targets_str}</p>
  <p style="color:#666;font-size:.8em">{AUTHOR}</p>
</div>

<div class="section">
  <h2>Resumen</h2>
  <div class="kpis">
    <div class="kpi"><div class="kv">{total_checked}</div><div class="kl">Comprobados</div></div>
    <div class="kpi"><div class="kv">{total_found}</div><div class="kl">Encontrados</div></div>
    {"".join(
        f'<div class="kpi"><div class="kv" style="color:{sev_colors[s]}">'
        f'{sum(1 for b in all_buckets if b.severity==s)}</div><div class="kl">{s}</div></div>'
        for s in ("CRITICAL","HIGH","MEDIUM","LOW") if any(b.severity==s for b in all_buckets)
    )}
  </div>
</div>

<div class="section">
  <h2>Tabla de hallazgos</h2>
  <table>
  <tr><th>ID</th><th>Bucket</th><th>Proveedor</th><th>Estado</th><th>HTTP</th><th>Severidad</th><th>URL</th></tr>
  {filas if filas else '<tr><td colspan="7" style="text-align:center;color:#444;padding:20px">Sin hallazgos</td></tr>'}
  </table>
</div>

{'<div class="section"><h2>Hallazgos CRITICAL / HIGH — Detalle</h2>' + tarjetas + '</div>' if tarjetas else ''}

<div class="brand">
  {AUTHOR} &nbsp;·&nbsp; USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS
</div>
</div>
</body>
</html>"""
    Path(path).write_text(html, encoding="utf-8")


# =============================================================================
# CONVERSIÓN A FORMATO INFORME UNIFICADO VSL
# =============================================================================

def _to_vsl_findings(results: List[CloudEnumResult]) -> List[VSLFinding]:
    """
    Convierte los BucketResult al formato Finding del módulo vampsec_report.

    Sólo se incluyen hallazgos con severidad CRITICAL, HIGH o MEDIUM.
    Para los LOW, se genera un hallazgo agrupado por proveedor si hay muchos.
    """
    findings: List[VSLFinding] = []
    all_buckets = sorted(
        [b for res in results for b in res.buckets_found],
        key=lambda x: _sev_rank(x.severity),
    )

    for b in all_buckets:
        if b.severity == "INFO":
            continue

        hdrs_str = "\n".join(f"{k}: {v}" for k, v in b.headers.items()) or "(sin cabeceras)"
        body_str = f"\nFragmento de cuerpo:\n{b.body_snippet[:400]}" if b.body_snippet else ""
        container_str = f"\nContainer: {b.container}" if b.container else ""

        if b.severity == "CRITICAL":
            if b.status == "LISTING":
                description = (
                    f"El bucket '{b.name}' en {b.provider.upper()} tiene el listado de contenido "
                    f"habilitado públicamente. Cualquier usuario de Internet puede enumerar y "
                    f"descargar todos los objetos/blobs sin autenticación."
                )
            else:
                description = (
                    f"El bucket '{b.name}' en {b.provider.upper()} es accesible públicamente "
                    f"sin autenticación. El acceso de lectura está abierto a cualquier usuario "
                    f"de Internet."
                )
            refs = [
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
                if b.provider == "s3" else
                "https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent"
                if b.provider == "azure" else
                "https://cloud.google.com/storage/docs/access-control/making-data-public",
            ]
        elif b.severity == "HIGH":
            description = (
                f"El bucket '{b.name}' en {b.provider.upper()} es accesible públicamente "
                f"(HTTP {b.http_code}) pero el listado de contenido no está habilitado o "
                f"no pudo verificarse. El acceso sin autenticación representa un riesgo alto."
            )
            refs = []
        elif b.severity == "MEDIUM":
            description = (
                f"El bucket '{b.name}' en {b.provider.upper()} existe y tiene un nombre "
                f"que sugiere contenido sensible (backup, secrets, config, etc.). "
                f"Aunque actualmente es privado (HTTP {b.http_code}), su exposición en el "
                f"espacio de nombres público supone un riesgo de fuga de información si "
                f"la configuración de acceso cambia."
            )
            refs = []
        else:  # LOW
            description = (
                f"El bucket '{b.name}' en {b.provider.upper()} existe (HTTP {b.http_code}) "
                f"y es privado, pero su nombre está expuesto en el espacio de nombres público "
                f"del proveedor. Esto puede facilitar ataques de enumeración o de "
                f"bucket squatting."
            )
            refs = []

        findings.append(VSLFinding(
            id          = b.finding_id,
            title       = f"{b.provider.upper()} bucket {'con listado público' if b.status=='LISTING' else 'accesible' if b.status=='PUBLIC' else 'existente'}: {b.name}"[:80],
            severity    = b.severity,
            description = description,
            evidence    = (
                f"URL: {b.url}\n"
                f"HTTP: {b.http_code}\n"
                f"Estado: {b.status}\n"
                + container_str + "\n"
                + f"Cabeceras:\n{hdrs_str}"
                + body_str
            ),
            affected    = b.url,
            remediation = _get_remediation(b),
            references  = refs,
            tags        = ["cloud", "storage", b.provider, b.status.lower(), "passive"],
        ))

    return findings


# =============================================================================
# ARGUMENTOS CLI
# =============================================================================

def parse_args() -> argparse.Namespace:
    """Parsea y valida los argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            f"VampSecure Labs Cloud Enum v{VERSION} — "
            "Enumerador pasivo de buckets S3 · Azure Blob · GCP Storage"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Ejemplos:
  %(prog)s -d ejemplo.com
  %(prog)s -d ejemplo.com -d miempresa.es --providers s3,gcp
  %(prog)s -d empresa.com --wordlist mis_buckets.txt --concurrency 50
  %(prog)s -d empresa.com --json resultado.json --html informe.html
  %(prog)s -d empresa.com --no-content-listing --timeout 5
        """,
    )

    p.add_argument(
        "-d", "--domain",
        metavar="DOMINIO",
        action="append",
        dest="domains",
        required=True,
        help="Dominio o nombre de empresa objetivo (puede repetirse: -d a.com -d b.com)",
    )
    p.add_argument(
        "-w", "--wordlist",
        metavar="FICHERO",
        help="Wordlist personalizada de sufijos/prefijos de nombre de bucket (uno por línea)",
    )
    p.add_argument(
        "--providers",
        metavar="LISTA",
        default="all",
        help="Proveedores a comprobar: s3,azure,gcp o 'all' (default: all)",
    )
    p.add_argument(
        "--concurrency",
        metavar="N",
        type=int,
        default=30,
        help="Máximo de peticiones concurrentes (default: 30)",
    )
    p.add_argument(
        "--timeout",
        metavar="SEG",
        type=int,
        default=8,
        help="Timeout por petición en segundos (default: 8)",
    )
    p.add_argument(
        "--no-content-listing",
        action="store_true",
        dest="no_listing",
        help="Omitir la comprobación de listado de contenido (sólo verificar acceso público)",
    )
    p.add_argument(
        "--json",
        metavar="FICHERO",
        dest="json_out",
        help="Guardar resultados en formato JSON",
    )
    p.add_argument(
        "--html",
        metavar="FICHERO",
        dest="html_out",
        help="Guardar informe HTML dark-theme",
    )

    add_report_args(p)
    return p.parse_args()


def _resolve_providers(providers_arg: str) -> List[str]:
    """
    Convierte el argumento --providers en la lista de proveedores activos.
    Devuelve ["s3", "azure", "gcp"] si el valor es "all".
    """
    valid = {"s3", "azure", "gcp"}
    if providers_arg.lower() == "all":
        return ["s3", "azure", "gcp"]
    selected = [p.strip().lower() for p in providers_arg.split(",")]
    unknown  = [p for p in selected if p not in valid]
    if unknown:
        console.print(f"[yellow]⚠ Proveedores desconocidos ignorados: {', '.join(unknown)}[/yellow]")
    return [p for p in selected if p in valid]


def _load_wordlist(path: str) -> List[str]:
    """
    Carga una wordlist desde un fichero de texto, una entrada por línea.
    Ignora líneas vacías y comentarios (#).
    """
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    except OSError as e:
        console.print(f"[red]Error al cargar wordlist '{path}': {e}[/red]")
        return []


# =============================================================================
# FUNCIÓN PRINCIPAL
# =============================================================================

async def run(args: argparse.Namespace) -> int:
    """
    Orquesta la enumeración completa de buckets cloud.

    1. Genera candidatos para todos los objetivos
    2. Sondeo concurrente con progress bar Rich
    3. Muestra tabla de resultados y paneles detallados
    4. Exporta JSON/HTML/informe VSL si se solicitó
    5. Devuelve código de salida: 2=CRITICAL, 1=HIGH, 0=limpio
    """
    providers    = _resolve_providers(args.providers)
    extra_sfx    = _load_wordlist(args.wordlist) if args.wordlist else None
    check_listing = not args.no_listing

    if not providers:
        console.print("[red]Error: no hay proveedores válidos seleccionados.[/red]")
        return 1

    # ── Panel de configuración ────────────────────────────────────────────────
    console.print(Panel.fit(
        f"Objetivos : [bold]{', '.join(args.domains)}[/]\n"
        f"Proveedores: [bold]{', '.join(p.upper() for p in providers)}[/]\n"
        f"Concurrencia: {args.concurrency} · Timeout: {args.timeout}s · "
        f"Listado: {'sí' if check_listing else 'no (--no-content-listing)'}\n"
        f"Wordlist: {args.wordlist or '(sin wordlist adicional)'}",
        title="[bold cyan]VampSecure Labs — Cloud Enum[/]",
        border_style="cyan",
    ))

    # ── Generar candidatos ────────────────────────────────────────────────────
    candidates = generate_bucket_candidates(args.domains, extra_suffixes=extra_sfx)
    total_probes = len(candidates) * len(providers)

    console.print(
        f"\n[cyan]Candidatos generados:[/] {len(candidates)} nombres × {len(providers)} proveedor(es) "
        f"= [bold]{total_probes}[/] sondeos\n"
    )

    # ── Sondeo con progress bar ───────────────────────────────────────────────
    enumerator = CloudEnumerator(
        providers     = providers,
        concurrency   = args.concurrency,
        timeout       = args.timeout,
        check_listing = check_listing,
    )

    all_results: List[CloudEnumResult] = []

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_id = progress.add_task(
            "[cyan]Sondeando buckets cloud…[/]",
            total=len(candidates),
        )
        found_all = await enumerator.enumerate(candidates, progress, task_id)

    # Agrupar por objetivo (heurística: asignar todos al primer objetivo
    # ya que los candidatos mezclan todos los objetivos)
    result = CloudEnumResult(
        target          = " | ".join(args.domains),
        buckets_checked = len(candidates),
        buckets_found   = found_all,
    )
    all_results.append(result)

    # ── Salida en consola ─────────────────────────────────────────────────────
    print_summary_table(found_all)
    print_critical_panels(found_all)

    # ── Exportaciones ─────────────────────────────────────────────────────────
    if args.json_out:
        export_json(all_results, args.json_out)
        console.print(f"[green]✔[/] JSON guardado en {args.json_out}")

    if args.html_out:
        export_html(all_results, args.html_out)
        console.print(f"[green]✔[/] HTML guardado en {args.html_out}")

    # Informes de cliente (formato unificado VSL)
    report_html = getattr(args, "report_html", None)
    report_pdf  = getattr(args, "report_pdf", None)
    if report_html or report_pdf:
        meta    = meta_from_args(args, tool=TOOL_NAME, version=VERSION)
        vsl_rep = VampSecReport(meta, _to_vsl_findings(all_results))
        if report_html:
            vsl_rep.to_html_client(report_html)
            console.print(f"[green]✔[/] Informe cliente HTML: {report_html}")
        if report_pdf:
            try:
                vsl_rep.to_pdf(report_pdf)
                console.print(f"[green]✔[/] Informe cliente PDF: {report_pdf}")
            except RuntimeError as e:
                console.print(f"[yellow]⚠ PDF no generado: {e}[/yellow]")

    # ── Resumen final + código de salida ──────────────────────────────────────
    n_critical = sum(1 for b in found_all if b.severity == "CRITICAL")
    n_high     = sum(1 for b in found_all if b.severity == "HIGH")
    n_medium   = sum(1 for b in found_all if b.severity == "MEDIUM")
    n_low      = sum(1 for b in found_all if b.severity == "LOW")

    console.print()
    console.print(Panel(
        f"Candidatos comprobados : [bold]{len(candidates)}[/]\n"
        f"Buckets encontrados    : [bold]{len(found_all)}[/]\n"
        f"[bold red]CRITICAL[/] : {n_critical}  "
        f"[bold yellow]HIGH[/] : {n_high}  "
        f"[bold magenta]MEDIUM[/] : {n_medium}  "
        f"[cyan]LOW[/] : {n_low}",
        title="[bold]Resumen Final[/]",
        border_style="cyan",
    ))

    if n_critical > 0:
        return 2
    if n_high > 0:
        return 1
    return 0


# =============================================================================
# PUNTO DE ENTRADA
# =============================================================================

def main() -> None:
    """Punto de entrada principal de vamp-cloud-enum."""
    console.print(BANNER, style="bold cyan")

    args = parse_args()
    try:
        exit_code = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)
        sys.exit(130)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
