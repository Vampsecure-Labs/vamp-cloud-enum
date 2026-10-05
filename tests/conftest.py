# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para la suite de test de vamp-cloud-enum.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Fixtures de respuestas HTTP simuladas
# ---------------------------------------------------------------------------

@pytest.fixture
def s3_listing_xml() -> str:
    """Respuesta XML de S3 con ListBucketResult (bucket con listado público)."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket-public</Name>
  <Prefix></Prefix>
  <Marker></Marker>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>confidential/data.csv</Key>
    <LastModified>2024-01-15T10:00:00.000Z</LastModified>
    <Size>1024</Size>
  </Contents>
  <Contents>
    <Key>backup/dump.sql</Key>
    <LastModified>2024-01-14T08:00:00.000Z</LastModified>
    <Size>204800</Size>
  </Contents>
</ListBucketResult>"""


@pytest.fixture
def s3_denied_xml() -> str:
    """Respuesta XML de S3 con AccessDenied (bucket privado pero existente)."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>ABC123</RequestId>
  <HostId>xyz</HostId>
</Error>"""


@pytest.fixture
def s3_no_such_bucket_xml() -> str:
    """Respuesta XML de S3 indicando que el bucket no existe."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchBucket</Code>
  <Message>The specified bucket does not exist</Message>
</Error>"""


@pytest.fixture
def azure_blob_listing_xml() -> str:
    """Respuesta XML de Azure Blob Storage con contenido de container público."""
    return """<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://stgtest.blob.core.windows.net/">
  <Blobs>
    <Blob>
      <Name>uploads/imagen.jpg</Name>
      <Properties>
        <Content-Length>204800</Content-Length>
        <Content-Type>image/jpeg</Content-Type>
      </Properties>
    </Blob>
  </Blobs>
  <NextMarker/>
</EnumerationResults>"""


@pytest.fixture
def gcp_bucket_listing_xml() -> str:
    """Respuesta XML de GCS con ListBucketResult (bucket público)."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
  <Name>gcp-test-bucket</Name>
  <Contents>
    <Key>private/report.pdf</Key>
    <Size>51200</Size>
  </Contents>
</ListBucketResult>"""


@pytest.fixture
def candidatos_ejemplo() -> list:
    """Lista de candidatos generados para 'example.com'."""
    from vamp_cloud_enum import generate_bucket_candidates
    return generate_bucket_candidates(["example.com"])
