"""Dependency-free, heuristic Solidity review detectors.

Detections are review leads, not proofs of exploitability or safety.
"""

from .finding import Finding

__all__ = ["Finding"]
