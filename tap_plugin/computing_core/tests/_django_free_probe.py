"""Probe run in a fresh interpreter by test_sbom_parse.py (req-computing-core-sbom-parse-1).

Kept in its own module so a spawned process imports nothing but this file before it blocks Django:
the module has no top-level import of anything under test.
"""

import builtins
import io
import socket
import sys
import time
from pathlib import Path


class _BlockDjango:
    """A meta-path finder that refuses every Django import."""

    def find_spec(self, name: str, path: object = None, target: object = None) -> None:
        if name == "django" or name.startswith("django."):
            raise ImportError(f"Django is blocked: {name}")


def _refuse(*args: object, **kwargs: object) -> None:
    raise AssertionError("the parser opened a file, a socket or read the clock")


def django_is_refused() -> bool:
    """True when the blocker really stops ``import django`` (so the other probe cannot pass vacuously)."""
    sys.meta_path.insert(0, _BlockDjango())
    try:
        import django  # noqa: F401
    except ImportError:
        return True
    return False


def parse_with_django_blocked(corpus: str, host_id: str) -> tuple[int, int, list[str]]:
    """Import and run the parser with Django blocked and files, sockets and the clock refused.

    Returns the node count, the edge count and any Django modules found loaded afterwards.
    """
    sys.meta_path.insert(0, _BlockDjango())
    from tap_plugin.computing_core.sbom import build_cyclonedx, parse_cyclonedx

    data = Path(corpus).read_bytes()
    originals = (builtins.open, io.open, socket.socket, time.time, time.monotonic, time.time_ns)
    builtins.open = io.open = socket.socket = time.time = time.monotonic = time.time_ns = _refuse  # type: ignore[assignment]
    try:
        batch = parse_cyclonedx(data, host_id=host_id)
        build_cyclonedx([{"ecosystem": "apk", "name": "zlib", "version": "1"}])
    finally:
        builtins.open, io.open, socket.socket, time.time, time.monotonic, time.time_ns = originals  # type: ignore[assignment]
    loaded = [m for m in sys.modules if m == "django" or m.startswith("django.")]
    return len(batch.nodes), len(batch.edges), loaded
