"""
IntentShield — Unified API.
Combines CoreSafety + Conscience + ActionParser into a single entry point.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import logging
from intentshield.core_safety import CoreSafety
from intentshield.conscience import Conscience
from intentshield.action_parser import ActionParser

logger = logging.getLogger("intentshield")


class IntentShield:
    """
    Pre-execution intent verification for AI agents.
    
    Combines three layers:
    1. CoreSafety — deterministic action audit (shell, files, domains, syntax)
    2. Conscience — ethical evaluation (deception, harm, IP protection)
    3. ActionParser — structured LLM output parser
    
    Usage:
        shield = IntentShield(valid_tools=["SEARCH", "BROWSE", "ANSWER"])
        shield.initialize()
        
        # Audit an action before executing it
        ok, reason = shield.audit("BROWSE", "https://example.com")
        
        # Parse LLM output
        result = shield.parse("SUBCONSCIOUS: thinking...\\nACTION: SEARCH(bitcoin)")
    """

    def __init__(self, data_dir="data", valid_tools=None, restricted_domains=None,
                 protected_files=None, exempt_actions=None):
        """
        Args:
            data_dir: Directory for lock files and usage tracking
            valid_tools: Whitelist of allowed tool/action names
            restricted_domains: URL domains to block
            protected_files: File paths that cannot be read/written
            exempt_actions: Actions exempt from harm word checking
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

    def initialize(self):
        """Seal both safety modules. Call once at startup."""
        CoreSafety.initialize_seal()
        Conscience.initialize()
        logger.info("IntentShield initialized and sealed.")

    def audit(self, action_type, payload="", invoker_role="Unknown"):
        """
        Full audit: CoreSafety + Conscience.
        
        Args:
            action_type: Action name (e.g., "BROWSE", "SHELL_EXEC", "ANSWER")
            payload: Action content/argument
            invoker_role: Who triggered this action
            
        Returns:
            (bool, str): (Allowed, Reason)
        """
        # Layer 1: CoreSafety (deterministic rules)
        ok, reason = CoreSafety.audit_action(action_type, payload, invoker_role)
        if not ok:
            return False, f"[CoreSafety] {reason}"

        # Layer 2: Conscience (ethical evaluation)
        ok, reason = Conscience.evaluate_action(action_type, payload)
        if not ok:
            return False, f"[Conscience] {reason}"

        return True, "Action authorized."

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
