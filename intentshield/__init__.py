"""
IntentShield — Pre-execution intent verification for AI agents.
Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

from intentshield.core_safety import CoreSafety
from intentshield.conscience import Conscience
from intentshield.action_parser import ActionParser
from intentshield.shield import IntentShield
from intentshield.hitl import HITLApproval, ApprovalStatus
from intentshield.siem_logger import SIEMLogger

__version__ = "1.1.1"
__all__ = [
    "IntentShield", "CoreSafety", "Conscience", "ActionParser",
    "HITLApproval", "ApprovalStatus", "SIEMLogger",
]
