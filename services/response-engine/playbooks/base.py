"""
Base classes for playbooks.

Every playbook implements:
  - `name`: unique identifier (used as playbook_name in DB)
  - `applies_to(ctx)`: should this playbook fire for this alert type?
  - `should_run(ctx)`: pre-check; e.g. is the IP already blocked?
  - `execute(ctx)`: do the actual work, return PlaybookResult
"""
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlaybookContext:
    """Everything a playbook needs to know about the triggering alert."""
    alert_id: str
    attack_type: str
    severity: str
    src_ip: str
    dst_ip: str
    confidence: float
    raw_features: dict


@dataclass
class PlaybookResult:
    """Result of running a playbook."""
    success: bool = True
    skipped: bool = False
    actions: list[dict[str, Any]] = field(default_factory=list)
    reason: str = ""
    error: str | None = None


class Playbook:
    """Base class — subclass and override the three lifecycle methods."""
    name: str = "base"

    def applies_to(self, ctx: PlaybookContext) -> bool:
        return True

    async def should_run(self, ctx: PlaybookContext) -> tuple[bool, str]:
        return True, "ok"

    async def execute(self, ctx: PlaybookContext) -> PlaybookResult:
        raise NotImplementedError
