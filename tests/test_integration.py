# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp_cloud_enum.py.

Simula respuestas HTTP de S3, Azure Blob y GCP GCS usando mocks de aiohttp.
No realiza peticiones reales a la red ni requiere credenciales.
"""

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock


sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_cloud_enum import (
    S3Prober,
    _bucket_severity,
    _normalize_name,
    generate_bucket_candidates,
)


def run_async(coro):
    """Ejecuta una corrutina asyncio en el event loop de test."""
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Helper: construye una sesión aiohttp mockeada con control por método/URL
# ---------------------------------------------------------------------------

def _mock_session(metodo: str, codigo: int, cuerpo: str, headers: dict = None) -> MagicMock:
    """
    Crea una sesión aiohttp mockeada que responde con el código y cuerpo dados
    para el método HTTP especificado ('head' o 'get').
    """
    headers = headers or {}
    session = MagicMock()

    def mock_ctx(url, **kwargs):
        resp = AsyncMock()
        resp.status = codigo
        resp.headers = headers
        resp.__aenter__ = AsyncMock(return_value=resp)
        resp.__aexit__ = AsyncMock(return_value=False)
        # _safe_read usa resp.content.read() internamente
        cuerpo_bytes = cuerpo.encode("utf-8") if cuerpo else b""
        resp.content = MagicMock()
        resp.content.read = AsyncMock(return_value=cuerpo_bytes)
        resp.read = AsyncMock(return_value=cuerpo_bytes)
        return resp

    setattr(session, metodo, mock_ctx)
    # Ambos métodos necesitan existir para que S3Prober no falle
    if metodo == "head":
        session.get = mock_ctx
    else:
        session.head = mock_ctx
    return session


# ---------------------------------------------------------------------------
# Test integración 1: S3 path-style devuelve LISTING con ListBucketResult XML
# ---------------------------------------------------------------------------

class TestS3ListingDetection:
    """S3Prober detecta ListBucketResult XML como LISTING → CRITICAL."""

    def test_s3_listbucketresult_xml_genera_listing_critical(self, s3_listing_xml):
        """Respuesta S3 con ListBucketResult en body → status=LISTING, severity=CRITICAL."""
        session = _mock_session("get", 200, s3_listing_xml)
        # HEAD devuelve 200 también (bucket público)
        session.head = _mock_session("head", 200, "").head

        prober = S3Prober(session=session, timeout=5, check_listing=True)

        resultado = run_async(prober._check_path_style("test-bucket-public"))

        assert resultado is not None
        assert resultado.status == "LISTING"
        assert resultado.severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Test integración 2: S3 retorna 403 AccessDenied → PRIVATE
# ---------------------------------------------------------------------------

class TestS3AccessDenied:
    """S3Prober marca bucket privado (403 AccessDenied) como PRIVATE."""

    def test_s3_403_access_denied_genera_private(self, s3_denied_xml):
        """Respuesta S3 con 403 y cuerpo AccessDenied → status=PRIVATE."""
        session = _mock_session("get", 403, s3_denied_xml)
        session.head = _mock_session("head", 403, s3_denied_xml).head

        prober = S3Prober(session=session, timeout=5, check_listing=False)

        resultado = run_async(prober._check_path_style("test-private-bucket"))

        assert resultado is not None
        assert resultado.status == "PRIVATE"
        assert resultado.severity in ("LOW", "MEDIUM")


# ---------------------------------------------------------------------------
# Test integración 3: S3 retorna 404 NoSuchBucket → None
# ---------------------------------------------------------------------------

class TestS3NoSuchBucket:
    """S3Prober devuelve None cuando el bucket no existe (NoSuchBucket)."""

    def test_s3_nosuchbucket_retorna_none(self, s3_no_such_bucket_xml):
        """Respuesta S3 404 con NoSuchBucket en cuerpo → probe devuelve None."""
        session = _mock_session("get", 403, s3_no_such_bucket_xml)
        # Simular body NoSuchBucket en respuesta 403 path-style
        session.head = _mock_session("head", 404, s3_no_such_bucket_xml).head

        prober = S3Prober(session=session, timeout=5, check_listing=False)

        # _check_path_style con 403 y NoSuchBucket en body devuelve None
        resultado = run_async(prober._check_path_style("bucket-inexistente-xyz-12345"))
        assert resultado is None


# ---------------------------------------------------------------------------
# Test integración 4: Pipeline completo — normalizar → generar → clasificar
# ---------------------------------------------------------------------------

class TestPipelineCompleto:
    """Verifica el pipeline completo: normalización → candidatos → severidad."""

    def test_pipeline_dominio_a_candidatos_con_severidad(self):
        """
        Pipeline: 'vampsecurestudios.com' → candidatos → verificar severidad
        de un candidato con nombre sensible.
        """
        # Paso 1: normalizar
        nombre_norm = _normalize_name("vampsecurestudios.com")
        assert nombre_norm == "vampsecurestudios-com"

        # Paso 2: generar candidatos
        candidatos = generate_bucket_candidates(["vampsecurestudios.com"])
        nombres = {c[0] for c in candidatos}

        # Paso 3: verificar que el candidato backup genera CRITICAL si está en LISTING
        candidato_backup = f"{nombre_norm}-backup"
        assert candidato_backup in nombres

        sev_listing = _bucket_severity(candidato_backup, "LISTING")
        assert sev_listing == "CRITICAL"

        sev_public_sensible = _bucket_severity(candidato_backup, "PUBLIC")
        assert sev_public_sensible == "CRITICAL"

        sev_private_sensible = _bucket_severity(candidato_backup, "PRIVATE")
        assert sev_private_sensible == "MEDIUM"


# ---------------------------------------------------------------------------
# Test integración 5: Detección de keywords sensibles en candidatos S3/GCP
# ---------------------------------------------------------------------------

class TestSensitiveKeywordsEnCandidatos:
    """Verifica que los candidatos con nombres sensibles existen y son CRITICAL/MEDIUM."""

    def test_candidatos_sensibles_generan_severidades_correctas(self):
        """Para cada keyword sensible debe existir candidato y severidad correcta."""
        keywords_criticas = {"backup", "secrets", "private", "config"}

        candidatos = generate_bucket_candidates(["empresa"])
        nombres = {c[0] for c in candidatos}

        for kw in keywords_criticas:
            candidato = f"empresa-{kw}"
            assert candidato in nombres, f"Candidato '{candidato}' no generado"

            # PUBLIC con nombre sensible → CRITICAL
            assert _bucket_severity(candidato, "PUBLIC") == "CRITICAL", (
                f"'{candidato}' PUBLIC no es CRITICAL"
            )
            # PRIVATE con nombre sensible → MEDIUM
            assert _bucket_severity(candidato, "PRIVATE") == "MEDIUM", (
                f"'{candidato}' PRIVATE no es MEDIUM"
            )
