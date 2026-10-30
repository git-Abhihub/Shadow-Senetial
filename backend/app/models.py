"""Canonical ShadowLens event and finding contracts.

Collectors report evidence and visibility; they do not decide whether activity is malicious.
"""
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class VisibilityTier(str, Enum):
    T1 = "T1"  # observed metadata
    T2 = "T2"  # inferred flow shape
    T3 = "T3"  # authorized plaintext inspection


class VisibilityLabel(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="allow")
    event_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "manual"
    tier: VisibilityTier = VisibilityTier.T1
    visibility: VisibilityLabel = VisibilityLabel.OBSERVED
    process: str = "unknown"
    destination: str = "unknown"
    action: str = "outbound_request"
    content_inspected: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow")
    finding_id: str | None = None
    type: str
    severity: Severity
    evidence: str
    tier: VisibilityTier = VisibilityTier.T1
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    raw_secret_persisted: bool = False
