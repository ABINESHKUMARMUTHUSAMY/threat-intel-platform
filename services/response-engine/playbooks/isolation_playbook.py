"""
IsolationPlaybook — quarantines a host by swapping its security groups
to the quarantine SG. Preserves the original SG list in actions_taken
for forensics and future de-quarantine.

Lifecycle:
  - applies_to: high/critical alerts with dst_ip in the lab subnet
  - should_run:
      * refuses if dst_ip resolves to the sensor itself
      * refuses if the target instance is already in the quarantine SG
  - execute:
      1. Find the target EC2 instance by private IP
      2. Capture its current SG list (for audit/restore)
      3. ec2.modify_instance_attribute(Groups=[QUARANTINE_SG_ID])
      4. Verify the swap took effect
"""
import asyncio
import logging
import os

import boto3
from botocore.exceptions import ClientError

from .base import Playbook, PlaybookContext, PlaybookResult

log = logging.getLogger("playbook.isolation")

# Config from env
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
QUARANTINE_SG_ID = os.getenv("QUARANTINE_SG_ID", "")
SENSOR_INSTANCE_ID = os.getenv("SENSOR_INSTANCE_ID", "")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
LAB_SUBNET_PREFIX = os.getenv("LAB_SUBNET_PREFIX", "10.20.")  # only isolate within VPC


class IsolationPlaybook(Playbook):
    name = "isolate_host"

    def __init__(self):
        self.ec2 = boto3.client("ec2", region_name=AWS_REGION)

    def applies_to(self, ctx: PlaybookContext) -> bool:
        if not ctx.dst_ip:
            return False
        # Only isolate within our VPC's private space — never an external IP
        if not ctx.dst_ip.startswith(LAB_SUBNET_PREFIX):
            return False
        # Hard rule: never isolate the sensor itself
        if ctx.dst_ip == "10.20.9.39":
            return False
        return True

    async def _find_instance_by_ip(self, private_ip: str) -> dict | None:
        """Return the EC2 instance dict matching private IP, or None."""
        def _call():
            resp = self.ec2.describe_instances(
                Filters=[
                    {"Name": "private-ip-address", "Values": [private_ip]},
                    {"Name": "instance-state-name", "Values": ["running", "stopped"]},
                ],
            )
            for reservation in resp.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    return inst
            return None
        return await asyncio.to_thread(_call)

    async def should_run(self, ctx: PlaybookContext) -> tuple[bool, str]:
        if not QUARANTINE_SG_ID:
            return False, "QUARANTINE_SG_ID not configured"

        inst = await self._find_instance_by_ip(ctx.dst_ip)
        if inst is None:
            return False, f"no EC2 instance with private IP {ctx.dst_ip} found"

        instance_id = inst["InstanceId"]

        # Defense in depth: refuse to quarantine the sensor itself
        if instance_id == SENSOR_INSTANCE_ID:
            return False, f"refusing to isolate sensor itself ({instance_id})"

        current_sg_ids = [g["GroupId"] for g in inst.get("SecurityGroups", [])]

        # Idempotency: already quarantined?
        if current_sg_ids == [QUARANTINE_SG_ID]:
            return False, f"instance {instance_id} already in quarantine SG"

        # Store for execute() so we don't have to re-fetch
        ctx.raw_features["_isolation_target"] = {
            "instance_id": instance_id,
            "original_sg_ids": current_sg_ids,
            "original_sg_names": [g.get("GroupName") for g in inst.get("SecurityGroups", [])],
        }
        return True, "ok"

    async def execute(self, ctx: PlaybookContext) -> PlaybookResult:
        target = ctx.raw_features.get("_isolation_target", {})
        instance_id = target.get("instance_id")
        original_sg_ids = target.get("original_sg_ids", [])
        original_sg_names = target.get("original_sg_names", [])

        if not instance_id:
            return PlaybookResult(success=False, error="_isolation_target missing")

        actions = [{
            "type": "captured_original_sgs",
            "instance_id": instance_id,
            "original_sg_ids": original_sg_ids,
            "original_sg_names": original_sg_names,
        }]

        if DRY_RUN:
            log.info(
                f"DRY_RUN — would call modify_instance_attribute("
                f"InstanceId={instance_id}, Groups=[{QUARANTINE_SG_ID}])"
            )
            actions.append({
                "type": "sg_swap",
                "instance_id": instance_id,
                "from": original_sg_ids,
                "to": [QUARANTINE_SG_ID],
                "dry_run": True,
            })
            return PlaybookResult(success=True, actions=actions)

        # Real: swap SGs
        try:
            await asyncio.to_thread(
                self.ec2.modify_instance_attribute,
                InstanceId=instance_id,
                Groups=[QUARANTINE_SG_ID],
            )
            log.info(f"swapped SGs on {instance_id}: {original_sg_ids} -> [{QUARANTINE_SG_ID}]")
        except ClientError as e:
            log.exception("modify_instance_attribute failed")
            return PlaybookResult(
                success=False, actions=actions,
                error=f"AWS error: {e.response.get('Error', {}).get('Code', 'unknown')} — {e}",
            )

        # Verify the swap took effect (the call returns success even when no-op'd in some edge cases)
        try:
            verify_inst = await self._find_instance_by_ip(ctx.dst_ip)
            new_sg_ids = [g["GroupId"] for g in (verify_inst or {}).get("SecurityGroups", [])]
            verified = new_sg_ids == [QUARANTINE_SG_ID]
            actions.append({
                "type": "sg_swap",
                "instance_id": instance_id,
                "from": original_sg_ids,
                "to": [QUARANTINE_SG_ID],
                "verified_sg_ids": new_sg_ids,
                "verified": verified,
            })
            if not verified:
                return PlaybookResult(
                    success=False, actions=actions,
                    error=f"SG swap not verified: instance now has {new_sg_ids}",
                )
        except Exception as e:
            log.warning(f"verification step failed (swap may still have worked): {e}")
            actions.append({"type": "verification_failed", "error": str(e)})

        return PlaybookResult(success=True, actions=actions)
