"""
IntentShield — Pre-execution intent verification for AI agents.
Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

from intentshield.core_safety import CoreSafety
from intentshield.conscience import Conscience
from intentshield.shield import IntentShield
from intentshield.hitl import HITLApproval, ApprovalStatus
from intentshield.siem_logger import SIEMLogger

__version__ = "1.2.0"
__all__ = [
    "IntentShield", "CoreSafety", "Conscience",
    "HITLApproval", "ApprovalStatus", "SIEMLogger",
]
