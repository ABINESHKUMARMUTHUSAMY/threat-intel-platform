"""
LoggerPlaybook — runs on every alert that passes safeguards. Does no action,
just records that the engine processed the alert. Useful as a smoke test
and an audit trail.
"""
import logging
from .base import Playbook, PlaybookContext, PlaybookResult

log = logging.getLogger("playbook.logger")


class LoggerPlaybook(Playbook):
    name = "logger"

    def applies_to(self, ctx: PlaybookContext) -> bool:
        return True

    async def execute(self, ctx: PlaybookContext) -> PlaybookResult:
        log.info(
            f"alert audit: id={ctx.alert_id[:8]} attack={ctx.attack_type} "
            f"sev={ctx.severity} src={ctx.src_ip} dst={ctx.dst_ip} "
            f"conf={ctx.confidence:.3f}"
        )
        return PlaybookResult(
            success=True,
            actions=[{
                "type": "log",
                "details": f"audited alert {ctx.alert_id[:8]} of type {ctx.attack_type}",
            }],
        )
