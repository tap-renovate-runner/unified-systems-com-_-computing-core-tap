"""SBOM ingest: a pure CycloneDX parser and its mirror builder.

No Django is imported here or by anything below (``req-computing-core-sbom-parse-1``): a collector,
an action or any other pipeline can call these with bytes and mappings.
"""

from tap_plugin.computing_core.sbom.batch import EdgeRow, NodeRow, SbomBatch, SbomReport
from tap_plugin.computing_core.sbom.builder import build_cyclonedx
from tap_plugin.computing_core.sbom.parser import SbomParseError, parse_cyclonedx
from tap_plugin.computing_core.sbom.verification import Verification, record_document

__all__ = [
    "EdgeRow",
    "NodeRow",
    "SbomBatch",
    "SbomParseError",
    "SbomReport",
    "Verification",
    "build_cyclonedx",
    "parse_cyclonedx",
    "record_document",
]
