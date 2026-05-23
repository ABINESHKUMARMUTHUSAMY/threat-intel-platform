"""
NoopPlaybook — applies only to DoS alerts, just to demonstrate that
playbooks can filter by attack type. Does no action.
"""
import logging
from .base import Playbook, PlaybookContext, PlaybookResult

log = logging.getLogger("playbook.noop")


class NoopPlaybook(Playbook):
    name = "noop_dos"

    def applies_to(self, ctx: PlaybookContext) -> bool:
        return ctx.attack_type == "DoS"

    async def execute(self, ctx: PlaybookContext) -> PlaybookResult:
        log.info(f"noop_dos: would isolate {ctx.dst_ip} (no-op stub for 8C)")
        return PlaybookResult(
            success=True,
            actions=[{"type": "noop", "target": ctx.dst_ip}],
        )
