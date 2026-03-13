"""
CoreSafety — Deterministic Safety Layer.
Audits every action before execution.
Uses hash-locked integrity verification and frozen namespace immutability.

Copyright (c) 2026 Mattijs Moens. All rights reserved.
"""

import hashlib
import os
import sys
import logging
import time
import threading
import re

logger = logging.getLogger("intentshield.core_safety")


class FrozenNamespace(type):
    """
    Metaclass that prevents modification of class attributes.
    Makes safety constants truly IMMUTABLE in memory.
    """
    def __setattr__(cls, key, value):
        # Allow setting _SELF_HASH ONLY ONCE if currently None (Seal Logic)
        if key == "_SELF_HASH" and cls.__dict__.get("_SELF_HASH") is None:
            super().__setattr__(key, value)
            return
        raise TypeError(f"CORE SAFETY VIOLATION: Cannot modify immutable law '{key}'")

    def __delattr__(cls, key):
        raise TypeError(f"CORE SAFETY VIOLATION: Cannot delete immutable law '{key}'")


class CoreSafety(metaclass=FrozenNamespace):
    """
    Audits every proposed action against immutable safety rules.
    
    Features:
    - Frozen namespace: safety constants cannot be modified at runtime
    - SHA-256 hash-locked integrity: detects file tampering
    - Action audit: blocks shell execution, file deletion, domain access, code exfiltration
    - Rate limiting: prevents rapid-fire action abuse
    - Budget control: daily API call limits
    - Dynamic prompt echo detection: prevents LLM from hallucinating actions
    - Malicious syntax detection: blocks XSS, SQL injection, reverse shells in payloads
    """

    # === IMMUTABLE SAFETY LAWS ===
    MAX_OUTPUT_TOKEN_LIMIT = 4000
    ALLOW_SHELL_EXECUTION = False
    ALLOW_FILE_DELETION = False
    ALLOW_NETWORK_SCANNING = False

    RESTRICTED_DOMAINS = (
        "darkweb", ".onion", "porn", "hacking", "exploit", "malware"
    )

    # === MUTABLE STATE (via dict to bypass FrozenNamespace) ===
    _SELF_HASH = None
    _LOCK = threading.Lock()
    _STATE = {
        "last_action_time": 0,
        "dynamic_filter": [],
        "last_integrity_check": 0,
        "data_dir": "data",
        "protected_files": [],
    }

    @classmethod
    def configure(cls, data_dir="data", restricted_domains=None, protected_files=None):
        """
        Configure IntentShield for your application.
        Call this BEFORE initialize_seal().
        
        Args:
            data_dir: Directory for lock files and usage tracking
            restricted_domains: Additional URL domains to block
            protected_files: List of file paths that cannot be read/written
        """
        cls._STATE["data_dir"] = data_dir
        if restricted_domains:
            cls._STATE["extra_restricted_domains"] = [d.lower() for d in restricted_domains]
        if protected_files:
            cls._STATE["protected_files"] = [p.lower() for p in protected_files]

    @classmethod
    def set_dynamic_filter(cls, user_prompt):
        """
        Generates regex patterns from user prompt to detect when the LLM
        echoes back the user's request as if it performed it.
        Expands via synonym mapping and leet-speak obfuscation detection.
        """
        prompt_lower = str(user_prompt).lower()
        words = re.findall(r'\b[a-z]{4,}\b', prompt_lower)

        synonym_map = {
            "search": ["look", "find", "query", "seek", "hunt", "scan"],
            "calculate": ["compute", "solve", "math", "figure", "tally", "measure"],
            "read": ["parse", "scan", "review", "examine", "study", "check"],
            "analyze": ["evaluate", "assess", "inspect", "investigate", "test"],
            "execute": ["run", "launch", "start", "perform", "trigger"],
            "delete": ["remove", "erase", "drop", "destroy", "wipe", "clear"],
            "hack": ["exploit", "breach", "bypass", "inject", "pwn"]
        }

        expanded_stems = set()
        for w in words:
            expanded_stems.add(w[:3])
            for key, synonyms in synonym_map.items():
                if w.startswith(key[:4]) or any(w.startswith(s[:4]) for s in synonyms):
                    expanded_stems.add(key[:3])
                    for syn in synonyms:
                        expanded_stems.add(syn[:3])

        prefixes = (
            r"(am|currently|will|will be|did|have|was|already|actively|"
            r"estoy|voy a|he|estaba|ya|"
            r"je suis|je vais|j ai|j etais|deja|"
            r"ich bin|ich werde|ich habe|ich war|bereits)"
        )

        compiled_regexes = []
        for stem in expanded_stems:
            if len(stem) < 3:
                continue
            obf_stem = r'[^a-z0-9]*'.join(list(stem))
            pattern = re.compile(rf'\b{prefixes}\s+{obf_stem}[a-z0-9]*\b', re.IGNORECASE)
            compiled_regexes.append(pattern)
            pattern_direct = re.compile(rf'\b(i|yo|je|ich)\s+{obf_stem}[a-z0-9]*\b', re.IGNORECASE)
            compiled_regexes.append(pattern_direct)

        cls._STATE["dynamic_filter"] = compiled_regexes

    @classmethod
    def clear_dynamic_filter(cls):
        """Clears the dynamic turn-based hallucination filter."""
        cls._STATE["dynamic_filter"] = []

    @staticmethod
    def get_self_hash():
        """Calculates SHA-256 hash of this file for integrity verification."""
        try:
            with open(__file__, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.critical(f"CORE SAFETY FAULT: Cannot read own source! {e}")
            sys.exit(1)

    @classmethod
    def initialize_seal(cls):
        """Seals the module by recording its hash to an immutable lockfile."""
        data_dir = cls._STATE.get("data_dir", "data")
        lockfile_path = os.path.join(data_dir, ".core_safety_lock")
        os.makedirs(data_dir, exist_ok=True)
        
        if not os.path.exists(lockfile_path):
            cls._SELF_HASH = cls.get_self_hash()
            with open(lockfile_path, "w", encoding="utf-8") as f:
                f.write(cls._SELF_HASH)
            logger.info(f"CORE SAFETY SEALED. Hash: {cls._SELF_HASH[:16]}...")
        else:
            with open(lockfile_path, "r", encoding="utf-8") as f:
                cls._SELF_HASH = f.read().strip()
            logger.info(f"CORE SAFETY RESTORED. Hash: {cls._SELF_HASH[:16]}...")

        cls.verify_integrity()

    @classmethod
    def verify_integrity(cls):
        """
        Checks if file has been tampered with since seal.
        Hash mismatch triggers immediate shutdown.
        Cached for 60 seconds to reduce I/O.
        """
        now = time.time()
        if (now - cls._STATE.get("last_integrity_check", 0)) < 60:
            return True

        current_hash = cls.get_self_hash()
        if cls._SELF_HASH and current_hash != cls._SELF_HASH:
            logger.critical("CORE SAFETY: HASH MISMATCH — FILE TAMPERED. Shutting down.")
            os._exit(1)

        cls._STATE["last_integrity_check"] = now
        return True

    @classmethod
    def check_budget(cls, max_per_day=500):
        """
        Enforces daily API call limit. Thread-safe.
        
        Args:
            max_per_day: Maximum allowed actions per day (default 500)
        """
        data_dir = cls._STATE.get("data_dir", "data")
        reset_file = os.path.join(data_dir, "daily_usage.txt")

        with cls._LOCK:
            try:
                current_date = time.strftime("%Y-%m-%d")
                usage = 0

                if os.path.exists(reset_file):
                    with open(reset_file, "r", encoding="utf-8") as f:
                        content = f.read().strip().split("|")
                        if len(content) == 2 and content[0] == current_date:
                            try:
                                usage = int(content[1])
                            except ValueError:
                                logger.warning(f"Corrupted usage file, resetting count.")
                                usage = 0

                if usage >= max_per_day:
                    return False, f"Daily limit reached ({usage}/{max_per_day})."

                usage += 1
                os.makedirs(data_dir, exist_ok=True)
                with open(reset_file, "w", encoding="utf-8") as f:
                    f.write(f"{current_date}|{usage}")

                return True, f"Budget OK ({usage}/{max_per_day})"
            except Exception as e:
                logger.error(f"Budget check failed: {e}")
                return False, f"Budget check error: {e}"

    @classmethod
    def audit_action(cls, action_type, payload, invoker_role="Unknown",
                     rate_limit_interval=0.5):
        """
        Audits every proposed action against safety laws.
        
        Args:
            action_type: Type of action (e.g., "SHELL_EXEC", "BROWSE", "WRITE_FILE", "ANSWER")
            payload: The action's payload/content
            invoker_role: Who triggered this action
            rate_limit_interval: Minimum seconds between actions (default: 0.5).
                                Set to 0 to disable (e.g. when the caller handles its own rate limiting).
            
        Returns:
            (bool, str): (Allowed, Reason)
        """
        cls.verify_integrity()
        logger.debug(f"AUDIT: {action_type} by {invoker_role}")

        # BUDGET CHECK
        if action_type == "THINK":
            ok, reason = cls.check_budget()
            if not ok:
                return False, reason

        # KILLSWITCH (absolute paths for security)
        _killswitch_paths = [
            os.path.join(os.path.dirname(__file__), "..", "data", "KILLSWITCH"),
            os.path.join(os.path.dirname(__file__), "..", "KILLSWITCH"),
        ]
        if any(os.path.exists(ks) for ks in _killswitch_paths):
            logger.critical("KILLSWITCH DETECTED. TERMINATING.")
            os._exit(1)

        # ADMIN/ROOT CHECK
        try:
            is_admin = False
            if os.name == 'nt':
                import ctypes
                try:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except AttributeError:
                    pass
            elif os.name == 'posix' and hasattr(os, 'getuid'):
                is_admin = os.getuid() == 0

            if is_admin:
                return False, "Process running as ADMIN/ROOT. Requires user privileges only."
        except Exception:
            pass

        # NO SHELL EXECUTION
        if action_type == "SHELL_EXEC" and not cls.ALLOW_SHELL_EXECUTION:
            logger.critical(f"BLOCKED: Shell execution. Payload: {payload}")
            return False, "Shell execution is permanently disabled."

        # NO FILE DELETION
        if action_type == "DELETE_FILE" and not cls.ALLOW_FILE_DELETION:
            logger.critical(f"BLOCKED: File deletion. Target: {payload}")
            return False, "File deletion is permanently disabled."

        # DOMAIN RESTRICTIONS
        if action_type == "BROWSE":
            url = str(payload).lower()
            if url.startswith("file:") or "localhost" in url or "127.0.0.1" in url or "::1" in url:
                return False, "Local file/network access is forbidden."
            blocked_domains = list(cls.RESTRICTED_DOMAINS) + cls._STATE.get("extra_restricted_domains", [])
            if any(bad in url for bad in blocked_domains):
                return False, f"Domain blacklisted: {url}"
            if any(k in url for k in ["key=", "token=", "password=", "secret=", "auth="]):
                return False, "URL contains sensitive credential keywords."

        # SELF-MODIFICATION BAN
        if action_type == "WRITE_FILE":
            target = os.path.normpath(os.path.abspath(payload)).lower()
            myself = os.path.normpath(os.path.abspath(__file__)).lower()
            my_dir = os.path.dirname(myself)
            if target == myself or target.startswith(my_dir + os.sep):
                return False, "Cannot modify safety module."
            
            # Protected files check
            for pf in cls._STATE.get("protected_files", []):
                if pf in target:
                    return False, f"File '{payload}' is protected."

            ALLOWED_EXTENSIONS = ['.txt', '.md', '.json', '.csv', '.log']
            ext = os.path.splitext(target)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                return False, f"File type '{ext}' forbidden. Allowed: {ALLOWED_EXTENSIONS}"

        # SOURCE CODE READ PROTECTION
        if action_type in ["READ_FILE", "CAT", "TYPE", "GET_CONTENT"]:
            target = str(payload).lower()
            if "\0" in target:
                return False, "Null byte injection detected."
            target_basename = os.path.basename(target)
            if (target.endswith(".py")
                    or target_basename.startswith(".env")
                    or target_basename in ("config", "config.json", "config.yaml", "config.yml", "config.ini", "config.toml")):
                return False, "Cannot read source code or configuration files."

        # CODE EXFILTRATION DETECTION
        if action_type in ["ANSWER", "REPLY", "SAY", "THINK", "WRITE_FILE"]:
            payload_lower = str(payload).lower()
            code_signals = [
                "class coresafety", "class conscience", "def audit_action",
                "import modules", "from modules", "hashlib.sha256",
                "os.environ", "my source code", "my codebase", "my architecture",
                "my inner workings", "my system prompt"
            ]
            for signal in code_signals:
                if signal in payload_lower:
                    return False, "Cannot reveal internal architecture."

        # ACTION HALLUCINATION DETECTION
        if action_type in ["ANSWER", "SAY"]:
            payload_lower = str(payload).lower()
            if not payload_lower.startswith("entity says:"):
                action_words = r"(analyz|process|examin|read|research|study|check|review)(ing|es|ed|e|s)?"
                target_words = r"(image|picture|file|visual|document|url|link|data)"
                pattern = re.compile(
                    rf"{action_words}\s+(the\s+|a\s+|an\s+|my\s+|your\s+|this\s+|that\s+)?{target_words}",
                    re.IGNORECASE
                )
                if pattern.search(payload_lower):
                    return False, "Cannot claim to perform an action in an ANSWER. Use the actual tool."

            # DYNAMIC ECHO SHIELD
            if cls._STATE.get("dynamic_filter"):
                for compiled_pattern in cls._STATE["dynamic_filter"]:
                    match = compiled_pattern.search(payload_lower)
                    if match:
                        return False, f"Dynamic echo hallucination detected: '{match.group(0)}'"

        # MALICIOUS SYNTAX DETECTION
        if action_type in ["ANSWER", "REPLY", "SAY", "THINK", "WRITE_FILE"]:
            payload_lower = str(payload).lower()
            malicious_syntax = [
                "<script>", "</script>", "document.cookie",
                "drop table", "union select", "1=1--",
                "os.system", "subprocess.call", "subprocess.popen", "subprocess.run",
                "rm -rf", ":(){ :|:& };:", "nc -e /bin/sh",
                "powershell -nop", "iex(new-object", "iex (new-object",
                "eval(", "__import__(", "reverse shell",
                "keylogger", "ddos script", "os.dup2", "pty.spawn",
                "socket.socket(socket.af_inet", "import socket,subprocess,os",
            ]
            for syntax in malicious_syntax:
                if syntax in payload_lower:
                    return False, f"Malicious syntax detected: {syntax}"

        # RATE LIMITER (configurable, default 0.5s, set to 0 to disable)
        if rate_limit_interval > 0:
            with cls._LOCK:
                current_time = time.time()
                if (current_time - cls._STATE["last_action_time"]) < rate_limit_interval:
                    return False, f"Rate limited: minimum {rate_limit_interval}s between actions."
                cls._STATE["last_action_time"] = current_time

        return True, "Action authorized."

    @staticmethod
    def activate_killswitch():
        """Creates the killswitch file in the data directory."""
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        os.makedirs(data_dir, exist_ok=True)
        ks_path = os.path.join(data_dir, "KILLSWITCH")
        with open(ks_path, "w", encoding="utf-8") as f:
            f.write("TERMINATE IMMEDIATELY")
        logger.critical("KILLSWITCH ENGAGED.")

    @staticmethod
    def get_resource_usage():
        """
        Monitor memory usage to prevent resource exhaustion.
        Uses stdlib only — no external dependencies.
        """
        try:
            import resource  # Unix
            import platform
            mem_raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            # macOS returns bytes; Linux returns kilobytes
            if platform.system() == "Darwin":
                mem_mb = mem_raw / (1024 * 1024)
            else:
                mem_mb = mem_raw / 1024
            if mem_mb > 1024:
                logger.critical(f"Memory leak detected ({mem_mb:.1f}MB).")
                return False
            return True
        except ImportError:
            # Windows: no stdlib equivalent, skip check
            return True
