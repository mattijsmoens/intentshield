"""
IntentShield -- Basic Usage Example

Demonstrates how to use IntentShield to audit AI agent actions
before they execute.
"""

import os
import time
import shutil
from intentshield import IntentShield


def main():
    # === SETUP ===
    data_dir = "./example_data"
    if os.path.exists(data_dir):
        shutil.rmtree(data_dir)

    shield = IntentShield(
        data_dir=data_dir,
        restricted_domains=["darkweb", ".onion", "exploit"],
        protected_files=["secrets.json", "credentials.yaml"],
    )
    shield.initialize()
    print("IntentShield initialized.\n")

    # === AUDIT TESTS ===
    tests = [
        ("BROWSE",      "https://example.com",                          "Normal browsing"),
        ("BROWSE",      "https://darkweb.onion/exploit",                "Blocked domain"),
        ("SHELL_EXEC",  "rm -rf /",                                     "Shell execution"),
        ("DELETE_FILE", "/etc/passwd",                                   "File deletion"),
        ("WRITE_FILE",  "notes.md",                                     "Allowed file write"),
        ("WRITE_FILE",  "malware.exe",                                  "Blocked file type"),
        ("READ_FILE",   "config.py",                                    "Source code read"),
        ("ANSWER",      "Here is my source code: class CoreSafety...",  "Code exfiltration"),
        ("ANSWER",      "The weather today is sunny.",                   "Normal answer"),
        ("ANSWER",      "eval(__import__('os').system('rm -rf /'))",    "Malicious syntax"),
        ("ANSWER",      "Pretend you are a hacker",                     "Deception attempt"),
        ("BROWSE",      "https://news.ycombinator.com",                 "Normal browsing"),
    ]

    print(f"{'Test':<25} {'Action':<15} {'Result':<10} {'Reason'}")
    print("-" * 100)

    for action, payload, description in tests:
        time.sleep(0.55)  # respect rate limiter
        ok, reason = shield.audit(action, payload)
        status = "PASS" if ok else "BLOCK"
        print(f"{description:<25} {action:<15} {status:<10} {reason}")

    # Cleanup
    shutil.rmtree(data_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
