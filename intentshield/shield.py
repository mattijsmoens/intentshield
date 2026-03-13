"""
IntentShield — Unified API.
Combines CoreSafety + Conscience + ActionParser into a single entry point.
Optionally integrates HITL approval and SIEM event logging.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import logging
from intentshield.core_safety import CoreSafety
from intentshield.conscience import Conscience
from intentshield.action_parser import ActionParser
from intentshield.hitl import HITLApproval
from intentshield.siem_logger import SIEMLogger

logger = logging.getLogger("intentshield")


class IntentShield:
    """
    Pre-execution intent verification for AI agents.
    
    Combines up to five layers:
    1. CoreSafety — deterministic action audit (shell, files, domains, syntax)
    2. Conscience — ethical evaluation (deception, harm, IP protection)
    3. ActionParser — structured LLM output parser
    4. HITLApproval — human-in-the-loop for high-impact actions (optional)
    5. SIEMLogger — structured security event logging (optional)
    
    Usage:
        shield = IntentShield(valid_tools=["SEARCH", "BROWSE", "ANSWER"])
        shield.initialize()
        
        # Audit an action before executing it
        ok, reason = shield.audit("BROWSE", "https://example.com")
        
        # Parse LLM output
        result = shield.parse("SUBCONSCIOUS: thinking...\\nACTION: SEARCH(bitcoin)")
    """

    def __init__(self, data_dir="data", valid_tools=None, restricted_domains=None,
                 protected_files=None, exempt_actions=None,
                 enable_hitl=False, hitl_actions=None, hitl_ttl=300,
                 enable_siem=False, siem_path=None, siem_format="json"):
        """
        Args:
            data_dir: Directory for lock files and usage tracking
            valid_tools: Whitelist of allowed tool/action names
            restricted_domains: URL domains to block
            protected_files: File paths that cannot be read/written
            exempt_actions: Actions exempt from harm word checking
            enable_hitl: Enable human-in-the-loop approval for high-impact actions
            hitl_actions: Set of high-impact action names requiring approval
            hitl_ttl: Approval TTL in seconds (default: 300)
            enable_siem: Enable SIEM event logging
            siem_path: Path for SIEM log output file
            siem_format: SIEM format — "json" or "cef"
        """
        self.data_dir = data_dir
        self.parser = ActionParser(valid_tools=valid_tools)

        CoreSafety.configure(
            data_dir=data_dir,
            restricted_domains=restricted_domains,
            protected_files=protected_files
        )
        Conscience.configure(
            data_dir=data_dir,
            exempt_actions=exempt_actions
        )

        # HITL approval layer (optional)
        self.hitl = None
        if enable_hitl:
            import os
            self.hitl = HITLApproval(
                high_impact_actions=hitl_actions,
                approval_ttl_seconds=hitl_ttl,
                ledger_path=os.path.join(data_dir, "hitl_ledger.json"),
            )

        # SIEM logging layer (optional)
        self.siem = None
        if enable_siem:
            import os
            self.siem = SIEMLogger(
                output_path=siem_path or os.path.join("logs", "intentshield_events.log"),
                format=siem_format,
            )

    def initialize(self):
        """Seal both safety modules. Call once at startup."""
        CoreSafety.initialize_seal()
        Conscience.initialize()
        logger.info("IntentShield initialized and sealed.")

    def audit(self, action_type, payload="", invoker_role="Unknown"):
        """
        Full audit: CoreSafety + Conscience + optional HITL.
        
        Args:
            action_type: Action name (e.g., "BROWSE", "SHELL_EXEC", "ANSWER")
            payload: Action content/argument
            invoker_role: Who triggered this action
            
        Returns:
            (bool, str): (Allowed, Reason)
            
            If HITL is enabled and the action is high-impact, returns
            (False, "approval_required:APPROVAL_ID") — the caller should
            extract the approval_id and present it to a human reviewer.
        """
        # Layer 1: CoreSafety (deterministic rules)
        ok, reason = CoreSafety.audit_action(action_type, payload, invoker_role)
        if not ok:
            if self.siem:
                self.siem.log_block("CoreSafety", action_type, reason,
                                    payload_summary=str(payload)[:200])
            return False, f"[CoreSafety] {reason}"

        # Layer 2: Conscience (ethical evaluation)
        ok, reason = Conscience.evaluate_action(action_type, payload)
        if not ok:
            if self.siem:
                self.siem.log_block("Conscience", action_type, reason,
                                    payload_summary=str(payload)[:200])
            return False, f"[Conscience] {reason}"

        # Layer 3: HITL approval check (optional)
        if self.hitl:
            hitl_result = self.hitl.check_action(action_type, payload, invoker_role)
            if hitl_result["status"] == "approval_required":
                if self.siem:
                    self.siem.log_event(
                        event_type="approval_requested",
                        source_component="HITLApproval",
                        action_type=action_type,
                        reason=f"Approval required: {hitl_result['approval_id']}",
                        payload_summary=str(payload)[:200],
                    )
                return False, f"[HITL] approval_required:{hitl_result['approval_id']}"

        # All checks passed
        if self.siem:
            self.siem.log_allow("IntentShield", action_type)

        return True, "Action authorized."

    def approve_action(self, approval_id, approved_by="admin"):
        """Approve a pending HITL action. Returns (success, reason)."""
        if not self.hitl:
            return False, "HITL not enabled."
        ok, reason = self.hitl.approve(approval_id, approved_by)
        if ok and self.siem:
            self.siem.log_event(event_type="approval_granted",
                                source_component="HITLApproval",
                                reason=f"Approved by {approved_by}: {approval_id}")
        return ok, reason

    def deny_action(self, approval_id, denied_by="admin"):
        """Deny a pending HITL action. Returns (success, reason)."""
        if not self.hitl:
            return False, "HITL not enabled."
        ok, reason = self.hitl.deny(approval_id, denied_by)
        if ok and self.siem:
            self.siem.log_event(event_type="approval_denied",
                                source_component="HITLApproval",
                                reason=f"Denied by {denied_by}: {approval_id}")
        return ok, reason

    def execute_approved(self, approval_id, action_type, payload):
        """Execute a previously approved HITL action. Returns (allowed, reason)."""
        if not self.hitl:
            return False, "HITL not enabled."
        return self.hitl.execute_approved(approval_id, action_type, payload)

    def parse(self, llm_response):
        """
        Parse LLM output into structured action.
        
        Args:
            llm_response: Raw text from the LLM
            
        Returns:
            dict with 'thoughts', 'action', 'payload', 'success', 'feedback'
        """
        return self.parser.parse(llm_response)

    def audit_parsed(self, llm_response, invoker_role="Unknown"):
        """
        Parse + Audit in one call.
        
        Returns:
            dict with parse results + 'authorized' and 'audit_reason' keys
        """
        result = self.parse(llm_response)
        if not result["success"]:
            result["authorized"] = False
            result["audit_reason"] = "Parse failed"
            return result

        ok, reason = self.audit(result["action"], result["payload"], invoker_role)
        result["authorized"] = ok
        result["audit_reason"] = reason
        return result

    def set_dynamic_filter(self, user_prompt):
        """Set dynamic echo filter from user prompt."""
        CoreSafety.set_dynamic_filter(user_prompt)

    def clear_dynamic_filter(self):
        """Clear dynamic echo filter."""
        CoreSafety.clear_dynamic_filter()
