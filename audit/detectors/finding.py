"""Shared, versioned output schema for detector review leads."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class Finding:
    detector: str
    severity: str
    confidence: str
    title: str
    message: str
    file: str
    line: int
    contract: str

    def to_dict(self) -> dict[str, object]:
        """Return the stable JSON representation shared by all modules."""
        return {"schema_version": 1, **asdict(self)}
