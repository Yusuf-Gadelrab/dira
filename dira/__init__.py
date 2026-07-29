"""DIRA (درع, "shield") — security audit for startup codebases.

Zero runtime dependencies. Secrets, dependency CVEs, misconfigurations,
git-history leaks, live surface checks, and a startup security-readiness score.
"""

__version__ = "1.2.0"

from .core import Finding, ScanResult  # noqa: F401
from .engine import scan  # noqa: F401

__all__ = ["scan", "Finding", "ScanResult", "__version__"]
