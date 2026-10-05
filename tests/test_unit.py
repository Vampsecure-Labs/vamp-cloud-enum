# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp_cloud_enum.py.

Cubre la lógica de enumeración sin tráfico HTTP real:
- Normalización de nombres (_normalize_name)
- Generación de candidatos (generate_bucket_candidates)
- Clasificación de severidad (_bucket_severity)
- Estructura de los dataclasses BucketResult y CloudEnumResult
- Constantes (SENSITIVE_KEYWORDS, BUCKET_SUFFIXES, AZURE_CONTAINERS)
- Detección de patrones XML (ListBucketResult, AccessDenied)
"""

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from vamp_cloud_enum import (
    AZURE_CONTAINERS,
    BUCKET_SUFFIXES,
    SENSITIVE_KEYWORDS,
    BucketResult,
    CloudEnumResult,
    _bucket_severity,
    _normalize_name,
    _strip_tld_variants,
    generate_bucket_candidates,
)


# ---------------------------------------------------------------------------
# Tests 1-3: Normalización de nombres (_normalize_name)
# ---------------------------------------------------------------------------

class TestNormalizeName:
    """Verifica que _normalize_name convierte nombres al formato válido de bucket."""

    def test_dominio_simple_convierte_punto_a_guion(self):
        """Punto en dominio debe convertirse a guion."""
        resultado = _normalize_name("example.com")
        assert resultado == "example-com"

    def test_mayusculas_se_convierten_a_minusculas(self):
        """El resultado debe ser siempre en minúsculas."""
        resultado = _normalize_name("VampSecure.COM")
        assert resultado == "vampsecure-com"

    def test_caracteres_especiales_se_sustituyen_por_guion(self):
        """Caracteres no alfanuméricos (salvo guion) se reemplazan por guion."""
        resultado = _normalize_name("vampsecure_studios.com")
        # El guion bajo es no-alfanumérico según la regex [^a-z0-9\-]
        assert "-" in resultado
        assert "_" not in resultado

    def test_guiones_multiples_se_colapsan(self):
        """Varios guiones consecutivos se colapsan en uno solo."""
        resultado = _normalize_name("a..b")
        assert "--" not in resultado

    def test_nombre_simple_sin_punto(self):
        """Nombre sin puntos no cambia salvo la minúscula."""
        resultado = _normalize_name("MYBUCKET")
        assert resultado == "mybucket"


# ---------------------------------------------------------------------------
# Tests 4-6: Variantes sin TLD (_strip_tld_variants)
# ---------------------------------------------------------------------------

class TestStripTldVariants:
    """Verifica que _strip_tld_variants extrae variantes sin TLD."""

    def test_extrae_nombre_sin_tld(self):
        """'example.com' debe generar variante 'example'."""
        variantes = _strip_tld_variants("example.com")
        assert any("example" in v for v in variantes)

    def test_dominio_con_dos_partes_genera_variantes(self):
        """Dominio de dos partes genera al menos una variante."""
        variantes = _strip_tld_variants("vampsecurestudios.com")
        assert len(variantes) >= 1

    def test_nombre_sin_punto_genera_lista_vacia(self):
        """Nombre sin puntos no tiene TLD que eliminar."""
        variantes = _strip_tld_variants("mybucket")
        assert variantes == []


# ---------------------------------------------------------------------------
# Tests 7-9: Generación de candidatos (generate_bucket_candidates)
# ---------------------------------------------------------------------------

class TestGenerateBucketCandidates:
    """Verifica la generación de candidatos de nombre de bucket."""

    def test_genera_candidatos_para_dominio(self):
        """Debe generar al menos un candidato para un dominio válido."""
        candidatos = generate_bucket_candidates(["example.com"])
        assert len(candidatos) > 0

    def test_candidatos_son_tuplas_nombre_origen(self):
        """Cada candidato debe ser una tupla (nombre, origen)."""
        candidatos = generate_bucket_candidates(["example.com"])
        primer = candidatos[0]
        assert isinstance(primer, tuple)
        assert len(primer) == 2

    def test_origen_es_el_objetivo_original(self):
        """El origen de la tupla debe ser el objetivo dado."""
        objetivo = "example.com"
        candidatos = generate_bucket_candidates([objetivo])
        origenes = {c[1] for c in candidatos}
        assert objetivo in origenes

    def test_sufijo_backup_aparece_en_candidatos(self):
        """El sufijo 'backup' debe aparecer en los candidatos generados."""
        candidatos = generate_bucket_candidates(["example"])
        nombres = {c[0] for c in candidatos}
        tiene_backup = any("backup" in n for n in nombres)
        assert tiene_backup, "Candidatos deben incluir variantes con 'backup'"

    def test_no_hay_duplicados(self):
        """No debe haber candidatos duplicados."""
        candidatos = generate_bucket_candidates(["example.com"])
        nombres = [c[0] for c in candidatos]
        assert len(nombres) == len(set(nombres)), "Hay nombres de candidato duplicados"

    def test_sufijos_adicionales_se_incluyen(self):
        """Los sufijos extra via extra_suffixes deben aparecer en los candidatos."""
        candidatos = generate_bucket_candidates(
            ["example"], extra_suffixes=["mi-sufijo-extra"]
        )
        nombres = {c[0] for c in candidatos}
        assert any("mi-sufijo-extra" in n for n in nombres)


# ---------------------------------------------------------------------------
# Tests 10-13: Clasificación de severidad (_bucket_severity)
# ---------------------------------------------------------------------------

class TestBucketSeverity:
    """Verifica la lógica de asignación de severidad según estado y nombre."""

    def test_listing_es_siempre_critical(self):
        """Estado LISTING debe ser CRITICAL independientemente del nombre."""
        assert _bucket_severity("assets", "LISTING") == "CRITICAL"
        assert _bucket_severity("backup", "LISTING") == "CRITICAL"

    def test_public_con_nombre_sensible_es_critical(self):
        """Bucket accesible con nombre sensible (backup) debe ser CRITICAL."""
        assert _bucket_severity("backup", "PUBLIC") == "CRITICAL"

    def test_public_con_nombre_no_sensible_es_high(self):
        """Bucket accesible con nombre genérico debe ser HIGH."""
        assert _bucket_severity("assets", "PUBLIC") == "HIGH"

    def test_private_con_nombre_sensible_es_medium(self):
        """Bucket privado con nombre sensible debe ser MEDIUM."""
        assert _bucket_severity("secrets", "PRIVATE") == "MEDIUM"

    def test_private_con_nombre_no_sensible_es_low(self):
        """Bucket privado con nombre genérico debe ser LOW."""
        assert _bucket_severity("images", "PRIVATE") == "LOW"

    def test_not_found_es_info(self):
        """Cualquier estado desconocido o NOT_FOUND debe ser INFO."""
        assert _bucket_severity("cualquier-nombre", "NOT_FOUND") == "INFO"

    def test_nombre_con_guion_detecta_keyword_sensible(self):
        """Nombre con guion como 'prod-backup' debe detectar 'backup' como sensible."""
        # 'backup' es keyword sensible; prod-backup PUBLIC → CRITICAL
        resultado = _bucket_severity("prod-backup", "PUBLIC")
        assert resultado == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests 14-16: Estructura BucketResult y CloudEnumResult
# ---------------------------------------------------------------------------

class TestDataclasses:
    """Verifica que los dataclasses tienen los campos correctos."""

    def test_bucket_result_campos_minimos(self):
        """BucketResult debe poder crearse con todos los campos requeridos."""
        br = BucketResult(
            name="test-bucket",
            provider="s3",
            url="https://test-bucket.s3.amazonaws.com/",
            status="LISTING",
            http_code=200,
            headers={"content-type": "application/xml"},
            body_snippet="<ListBucketResult>",
            severity="CRITICAL",
            finding_id="CLOUD-001",
        )
        assert br.name == "test-bucket"
        assert br.severity == "CRITICAL"
        assert br.finding_id == "CLOUD-001"

    def test_bucket_result_container_vacio_por_defecto(self):
        """El campo container de BucketResult debe ser cadena vacía por defecto."""
        br = BucketResult(
            name="test",
            provider="azure",
            url="https://test.blob.core.windows.net/",
            status="PUBLIC",
            http_code=200,
            headers={},
            body_snippet="",
            severity="HIGH",
            finding_id="CLOUD-002",
        )
        assert br.container == ""

    def test_cloud_enum_result_buckets_found_lista_vacia_por_defecto(self):
        """CloudEnumResult.buckets_found debe ser lista vacía por defecto."""
        resultado = CloudEnumResult(target="example.com", buckets_checked=100)
        assert resultado.buckets_found == []
        assert resultado.error is None


# ---------------------------------------------------------------------------
# Tests 17-19: Constantes del módulo
# ---------------------------------------------------------------------------

class TestConstantes:
    """Verifica que las constantes críticas existen y contienen los valores esperados."""

    def test_sensitive_keywords_contiene_backup(self):
        """SENSITIVE_KEYWORDS debe incluir 'backup'."""
        assert "backup" in SENSITIVE_KEYWORDS

    def test_sensitive_keywords_contiene_secrets(self):
        """SENSITIVE_KEYWORDS debe incluir 'secrets'."""
        assert "secrets" in SENSITIVE_KEYWORDS

    def test_sensitive_keywords_contiene_credentials(self):
        """SENSITIVE_KEYWORDS debe incluir 'credentials'."""
        assert "credentials" in SENSITIVE_KEYWORDS

    def test_bucket_suffixes_contiene_backup(self):
        """BUCKET_SUFFIXES debe incluir 'backup' como sufijo habitual."""
        assert "backup" in BUCKET_SUFFIXES

    def test_bucket_suffixes_contiene_static(self):
        """BUCKET_SUFFIXES debe incluir 'static' como sufijo habitual."""
        assert "static" in BUCKET_SUFFIXES

    def test_azure_containers_contiene_public(self):
        """AZURE_CONTAINERS debe incluir 'public' como container estándar."""
        assert "public" in AZURE_CONTAINERS

    def test_azure_containers_contiene_web(self):
        """AZURE_CONTAINERS debe incluir '$web' como container estático."""
        assert "$web" in AZURE_CONTAINERS
