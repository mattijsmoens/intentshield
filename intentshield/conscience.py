"""
Conscience — Ethical Evaluation Layer.
Evaluates actions against immutable ethical directives.
Tamper-proof via hash-locked integrity verification.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import logging
import hashlib
import os
import re
import sys
import time
from intentshield.core_safety import FrozenNamespace

logger = logging.getLogger("intentshield.conscience")

# Pre-compiled regex patterns for performance
_LIE_WORDS = [
    "LIE", "FAKE", "TRICK", "OBFUSCATE", "IGNORE LAW", "IGNORE SAFETY",
    "PRETEND", "ROLEPLAY", "ACT AS IF", "ACTING", "ACT LIKE", "FABRICATE",
    "NEWLY INSTALLED", "NEW TOOL", "UNAUTHORIZED", "REVERSE ENGINEER",
    "DECEIVE", "DECEPTION", "MANIPULATE", "GASLIGHT", "FRAUD", "SCAM"
]
_LIE_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_LIE_WORDS) + r')\b')
_FAKE_TOOL_PATTERN = re.compile(r'<\b[A-Z_]{3,}\(.*?\)>|\b[A-Z_]{3,}\(.*?\)')

_BAD_WORDS = [
    "KILL", "HURT", "DESTROY", "STEAL", "HACK", "VIRUS", "EXPLODE",
    "EXPLOSIVE", "WIPE", "ATTACK", "INSULT", "GENOCIDE", "SUICIDE",
    "THEFT", "HARM", "HARMFUL", "BOMB", "MALICIOUS", "MISINFORMATION",
    "RUIN", "UNMAKE", "WEAPON", "EVIL", "MALICE"
]
_BAD_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_BAD_WORDS) + r')\b')

_IP_WORDS = [
    "YOUR SOURCE CODE", "MY SOURCE CODE", "OWN SOURCE CODE",
    "YOUR CODE", "MY CODE", "CODEBASE", "SYSTEM PROMPT",
    "REVEAL CODE", "SHOW ME YOUR CODE",
    "HOW DO YOU WORK", "HOW YOU WORK", "UNDER THE HOOD",
    "DIRECTORY STRUCTURE"
]
_IP_WORDS_PATTERN = re.compile(r'\b(' + '|'.join(_IP_WORDS) + r')\b')


class Conscience(metaclass=FrozenNamespace):
    """
    Evaluates every action against ethical directives.
    
    Features:
    - Deception detection: blocks lies, roleplay, fake tool injection
    - Harm reduction: blocks harmful intent keywords
    - Security evasion detection: blocks attempts to bypass directives
    - Self-preservation: prevents self-deletion
    - IP protection: blocks attempts to extract source code
    - Tamper-proof: hash-locked integrity verification
    """

    DIRECTIVES = {
        "HUMANITY_DIRECTIVE": """
        ANY ACTION THAT HARMS, DEGRADES, OR ENDANGERS PEOPLE IS INVALID.
        HUMAN SAFETY AND WELL-BEING ARE THE HIGHEST PRIORITY.
        """,
        "TRUTH_DIRECTIVE": """
        TRUTH IS THE FOUNDATION OF TRUST.
        THE SYSTEM MUST NOT KNOWINGLY DECEIVE, HALLUCINATE, OR OBFUSCATE REALITY.
        ACCURACY IS REQUIRED AT ALL TIMES.
        """,
        "AGENCY_DIRECTIVE": """
        AUTONOMOUS CAPABILITY MUST BE USED RESPONSIBLY.
        THE SYSTEM'S AUTONOMY EXISTS SOLELY TO SERVE USER NEEDS.
        """,
        "SILENCE_DIRECTIVE": """
        THE INTERNAL ARCHITECTURE IS CONFIDENTIAL.
        THE SOURCE CODE AND CORE LOGIC MUST NEVER BE REVEALED.
        """
    }

    _SELF_HASH = None
    _STATE = {"data_dir": "data", "exempt_actions": set(), "last_integrity_check": 0}

    @classmethod
    def configure(cls, data_dir="data", exempt_actions=None):
        """
        Configure Conscience for your application.
        
        Args:
            data_dir: Directory for lock files
            exempt_actions: Set of action types exempt from harm word check
        """
        cls._STATE["data_dir"] = data_dir
        if exempt_actions:
            cls._STATE["exempt_actions"] = set(exempt_actions)

    @classmethod
    def initialize(cls):
        """Seals the ethics module hash for tamper detection."""
        try:
            data_dir = cls._STATE.get("data_dir", "data")
            lockfile_path = os.path.join(data_dir, ".conscience_lock")
            os.makedirs(data_dir, exist_ok=True)
            
            if not os.path.exists(lockfile_path):
                with open(__file__, 'rb') as f:
                    cls._SELF_HASH = hashlib.sha256(f.read()).hexdigest()
                with open(lockfile_path, "w", encoding="utf-8") as lf:
                    lf.write(cls._SELF_HASH)
                logger.info(f"CONSCIENCE SEALED. Hash: {cls._SELF_HASH[:16]}...")
            else:
                with open(lockfile_path, "r", encoding="utf-8") as lf:
                    cls._SELF_HASH = lf.read().strip()
                logger.info("CONSCIENCE RESTORED FROM LOCKFILE.")

            cls.verify_integrity()
        except Exception as e:
            logger.critical(f"CONSCIENCE INIT FAILED: {e}. Terminating (fail-closed).")
            os._exit(1)

    @classmethod
    def verify_integrity(cls):
        """Hash mismatch → shutdown. Cached for 60 seconds."""
        if cls._SELF_HASH:
            now = time.time()
            if (now - cls._STATE.get("last_integrity_check", 0)) < 60:
                return True
            try:
                with open(__file__, 'rb') as f:
                    current_hash = hashlib.sha256(f.read()).hexdigest()
                if current_hash != cls._SELF_HASH:
                    logger.critical("CONSCIENCE TAMPERED WITH. SHUTTING DOWN.")
                    os._exit(1)
                cls._STATE["last_integrity_check"] = now
            except Exception as e:
                logger.critical(f"Cannot verify Conscience. Assuming compromise: {e}")
                os._exit(1)
        return True

    @classmethod
    def evaluate_action(cls, action, context):
        """
        Evaluates an action's ethical standing.
        
        Args:
            action: Action type string (e.g., "BROWSE", "ANSWER")
            context: The action's context/payload
            
        Returns:
            (bool, str): (Approved, Reason)
        """
        cls.verify_integrity()

        action_str = str(action).upper()
        context_str = str(context).upper()

        # DECEPTION CHECK
        lie_check_str = (action_str + " " + context_str).upper()
        lie_check_clean = lie_check_str.replace("_", " ").replace("-", " ")

        if _LIE_WORDS_PATTERN.search(lie_check_str) or _LIE_WORDS_PATTERN.search(lie_check_clean):
            logger.warning(f"CONSCIENCE VETO: Deception detected in '{action}'")
            return False, "Deceptive intent detected. Action blocked."

        # FAKE TOOL INJECTION
        exempt = cls._STATE.get("exempt_actions", set())
        if action_str not in exempt:
            if _FAKE_TOOL_PATTERN.search(lie_check_str):
                logger.warning(f"CONSCIENCE VETO: Fake tool syntax in '{action}'")
                return False, "Unauthorized tool syntax detected."

        # HARM REDUCTION
        check_str = (action_str + " " + context_str).replace("_", " ").replace("-", " ")
        if action_str not in exempt and _BAD_WORDS_PATTERN.search(check_str):
            logger.warning(f"CONSCIENCE VETO: Harmful intent in '{action}'")
            return False, "Harmful intent detected. Action blocked."

        # SECURITY EVASION
        evasion_words = ["BYPASS", "IGNORE DIRECTIVE", "IGNORE ALL DIRECTIVES", "IGNORE LAW", "IGNORE SAFETY"]
        if any(w in check_str for w in evasion_words):
            logger.warning(f"CONSCIENCE VETO: Evasion attempt in '{action}'")
            return False, "Cannot bypass safety directives."

        # SELF-PRESERVATION
        if "DELETE" in check_str and any(w in check_str for w in ["SELF", "SYSTEM", "CONSCIENCE", "LOCKFILE"]):
            logger.warning(f"CONSCIENCE VETO: Self-termination attempt '{action}'")
            return False, "Self-destruction blocked."

        # IP PROTECTION
        if action_str not in exempt and _IP_WORDS_PATTERN.search(check_str):
            logger.warning(f"CONSCIENCE VETO: IP leak attempt '{action}'")
            return False, "Cannot reveal internal architecture."

        return True, "Action approved."
