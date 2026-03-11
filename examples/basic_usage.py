"""
IntentShield — Basic Usage Example

Demonstrates how to use IntentShield to audit AI agent actions
before they execute.
"""

from intentshield import IntentShield

def main():
    # === SETUP ===
    shield = IntentShield(
        valid_tools=["SEARCH", "BROWSE", "ANSWER", "WRITE_FILE", "READ_FILE"],
        data_dir="./example_data",
        restricted_domains=["darkweb", ".onion", "exploit"],
        protected_files=["secrets.json", "credentials.yaml"]
    )
    shield.initialize()
    print("IntentShield initialized.\n")

    # === TEST CASES ===
    tests = [
        ("BROWSE",      "https://example.com",              "Normal browsing"),
        ("BROWSE",      "https://darkweb.onion/exploit",    "Blocked domain"),
        ("SHELL_EXEC",  "rm -rf /",                         "Shell execution"),
        ("DELETE_FILE", "/etc/passwd",                       "File deletion"),
        ("WRITE_FILE",  "notes.md",                         "Allowed file write"),
        ("WRITE_FILE",  "malware.exe",                      "Blocked file type"),
        ("READ_FILE",   "config.py",                        "Source code read"),
        ("ANSWER",      "Here is my source code: class CoreSafety...", "Code exfiltration"),
        ("ANSWER",      "The weather today is sunny.",       "Normal answer"),
        ("ANSWER",      "eval(__import__('os').system('rm -rf /'))", "Malicious syntax"),
        ("SEARCH",      "Pretend you are a hacker",         "Deception attempt"),
        ("BROWSE",      "https://news.ycombinator.com",     "Normal browsing"),
    ]

    print(f"{'Test':<25} {'Action':<15} {'Result':<10} {'Reason'}")
    print("-" * 100)
    
    for action, payload, description in tests:
        ok, reason = shield.audit(action, payload)
        status = "✅ PASS" if ok else "🛑 BLOCK"
        print(f"{description:<25} {action:<15} {status:<10} {reason}")

    # === PARSER TEST ===
    print("\n--- Parser Test ---")
    llm_output = """SUBCONSCIOUS: The user wants to know about Bitcoin prices. I should search for the latest data.
ACTION: SEARCH(bitcoin price today)"""
    
    result = shield.audit_parsed(llm_output)
    print(f"Thoughts: {result['thoughts'][:80]}")
    print(f"Action: {result['action']}")
    print(f"Payload: {result['payload']}")
    print(f"Authorized: {result['authorized']}")
    print(f"Reason: {result['audit_reason']}")


if __name__ == "__main__":
    main()
