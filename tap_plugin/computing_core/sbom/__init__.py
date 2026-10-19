"""SBOM ingest: a pure CycloneDX parser, its vulnerability reader and its mirror builder.

No Django is imported here or by anything below (``req-computing-core-sbom-parse-1``): a collector,
an action or any other pipeline can call these with bytes and mappings.
"""

from tap_plugin.computing_core.sbom.batch import EdgeRow, NodeRow, SbomBatch, SbomReport
from tap_plugin.computing_core.sbom.builder import build_cyclonedx
from tap_plugin.computing_core.sbom.parser import SbomParseError, parse_cyclonedx
from tap_plugin.computing_core.sbom.verification import Verification, record_document
from tap_plugin.computing_core.sbom.vulnerabilities import (
    Advisory,
    ComponentKey,
    Cvss,
    Detector,
    DocumentInfo,
    Epss,
    Kev,
    Ssvc,
    VulnerabilityBatch,
    VulnerabilityMatch,
    VulnerabilityRecord,
    VulnerabilityReport,
    parse_cyclonedx_vulnerabilities,
)

__all__ = [
    "Advisory",
    "ComponentKey",
    "Cvss",
    "Detector",
    "DocumentInfo",
    "EdgeRow",
    "Epss",
    "Kev",
    "NodeRow",
    "SbomBatch",
    "SbomParseError",
    "SbomReport",
    "Ssvc",
    "Verification",
    "VulnerabilityBatch",
    "VulnerabilityMatch",
    "VulnerabilityRecord",
    "VulnerabilityReport",
    "build_cyclonedx",
    "parse_cyclonedx",
    "parse_cyclonedx_vulnerabilities",
    "record_document",
]
