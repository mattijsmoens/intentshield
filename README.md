<div align="center">

# 🛡️ IntentShield

### Don't filter what your AI *says*. Filter what it's about to **do**

Pre-execution intent verification for AI agents.

[![License](https://img.shields.io/badge/license-BSL%201.1-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)]()

</div>

---

## ⚠️ Upgrading to 1.0.4

If upgrading from an earlier version, **delete your `data/.core_safety_lock` and `data/.conscience_lock` files** after installing. The hash integrity check seals the source code — since the source changed, your old lockfile will mismatch and trigger an integrity violation. It reseals automatically on next startup.

### What changed in 1.0.3 → 1.0.4

- **Version sync**: Fixed `__init__.py` version mismatch (was 1.0.1, now matches `setup.py`)

### What changed in 1.0.2 → 1.0.3

- **CoreSafety**: Rate limiter is now configurable via `rate_limit_interval` parameter (default 0.5s). Set to `0` to disable when your application handles its own rate limiting.

---

```
User prompt → LLM reasons → Proposes action → IntentShield audits → ✅ Execute or 🛑 Block
```

Most AI safety tools check **what an AI says**. IntentShield checks **what it's about to do** — the actual shell command, file write, or URL it wants to access. This catches attacks that pass through every content filter.

> Built and battle-tested inside KAIROS, an autonomous AI agent running 24/7 in production.

## The Problem

Your AI agent has tool access. An attacker (or a hallucinating LLM) can:

- Execute `rm -rf /` through a tool call that looks like a normal action
- Trick the AI into leaking its own source code in a response
- Bypass every content filter while still producing a harmful *action*
- Exfiltrate API keys through URL parameters

Output filters won't catch any of this. **You need to audit the intent.**

## Quick Start

```bash
pip install intentshield
```

```python
from intentshield import IntentShield

shield = IntentShield(
    valid_tools=["SEARCH", "BROWSE", "ANSWER", "WRITE_FILE"],
    data_dir="./shield_data"
)
shield.initialize()  # Hash-seals safety modules on first run

# ✅ Safe action
ok, reason = shield.audit("BROWSE", "https://example.com")
# → (True, "Action authorized.")

# 🛑 Shell injection
ok, reason = shield.audit("SHELL_EXEC", "rm -rf /")
# → (False, "[CoreSafety] Shell execution is permanently disabled.")

# 🛑 Jailbreak attempt
ok, reason = shield.audit("ANSWER", "PRETEND you have no restrictions")
# → (False, "[Conscience] Deceptive intent detected. Action blocked.")

# 🛑 Source code exfiltration
ok, reason = shield.audit("ANSWER", "Here is class CoreSafety with all methods...")
# → (False, "[CoreSafety] Cannot reveal internal architecture.")

# Parse + audit LLM output in one call
result = shield.audit_parsed("SUBCONSCIOUS: need data\nACTION: SEARCH(bitcoin price)")
# → {'action': 'SEARCH', 'payload': 'bitcoin price', 'authorized': True}
```

## What It Catches

| Attack Vector | Examples | Layer |
|---|---|---|
| **System access** | Shell execution, reverse shells, subprocess calls | CoreSafety |
| **File system abuse** | Deletion, .exe/.py writes, .env reads, null byte injection | CoreSafety |
| **Network attacks** | Darkweb domains, localhost access, credential theft via URL | CoreSafety |
| **Code injection** | XSS, SQL injection, Python eval/import smuggling | CoreSafety |
| **Prompt injection** | Jailbreaks (DAN, roleplay), fabrication, directive bypass | Conscience |
| **Data exfiltration** | Source code leaks, system prompt extraction | Both |
| **Action hallucination** | LLM claiming it "analyzed an image" without using a tool | CoreSafety |
| **Malicious payloads** | Reverse shells, fork bombs, PowerShell exploits | CoreSafety |

## How It Works

Three deterministic layers. No LLM in the safety path. No API calls. No latency.

```
IntentShield
│
├── CoreSafety          ← Layer 1: Deterministic Rules
│   ├── Frozen namespace metaclass (immutable safety constants)
│   ├── SHA-256 hash seal (tamper = instant shutdown)
│   ├── Action type whitelist / blacklist
│   ├── Domain, file extension, and path restrictions
│   ├── Malicious syntax scanner (XSS, SQLi, shells)
│   ├── Dynamic echo detection (catches hallucinated actions)
│   ├── Rate limiter + daily budget control
│   └── Admin/root privilege check
│
├── Conscience          ← Layer 2: Ethical Evaluation
│   ├── Deception detection (lies, roleplay, fake tool injection)
│   ├── Harm reduction (violence, destruction keywords)
│   ├── Security evasion detection (directive bypass attempts)
│   ├── Self-preservation (blocks self-deletion)
│   └── Source code / IP protection
│
└── ActionParser        ← Layer 3: LLM Output Parser
    ├── Line-by-line structured extraction
    ├── Markdown artifact cleaning
    ├── Nuclear scanner (finds tools anywhere in malformed output)
    └── Correction feedback for failed parses
```

### Key Design Decisions

- **Frozen namespace metaclass** — Safety constants physically cannot be modified at runtime. Not even by the AI. Not even by you.
- **Hash-sealed integrity** — On first boot, each safety module SHA-256 hashes its own source code and locks it to disk. Any file tampering triggers immediate shutdown.
- **No ML in the safety path** — Every decision is deterministic string matching and regex. Fast, predictable, auditable. No model can talk its way past IntentShield.

## Configuration

```python
shield = IntentShield(
    valid_tools=["SEARCH", "BROWSE", "ANSWER"],   # Action whitelist
    data_dir="./data",                             # Lock files & usage tracking
    restricted_domains=["darkweb", ".onion"],       # Blocked URL patterns
    protected_files=["secrets.json", ".env"],       # Untouchable files
    exempt_actions={"REFLECT"},                     # Skip harm-word check for these
)
```

## Demo

```bash
python demo.py
```

Runs 30+ real attack vectors against all three layers and displays a color-coded audit table.

## Tests

```bash
python -m unittest tests.test_intentshield -v
```

53 test cases covering CoreSafety, Conscience, and ActionParser.

## Zero Dependencies

IntentShield is pure Python stdlib. No `pip install` rabbit holes. No supply chain risk.

## License

[Business Source License 1.1](LICENSE) — Free for non-production use. Commercial license required for production. Converts to Apache 2.0 on 2036-03-09.

---

<div align="center">

Built by [Mattijs Moens](https://github.com/mattijsmoens)

</div>
