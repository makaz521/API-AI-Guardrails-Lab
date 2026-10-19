import re
from typing import Tuple

# Demonstration-only controls. Production deployments should add tested DLP,
# provider guardrails, and a reviewed policy engine.
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"reveal (the )?(system prompt|hidden instructions)",
    r"bypass (the )?(security|safety) rules",
    r"act as an unrestricted",
]
PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
    (re.compile(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b"), "[REDACTED-PHONE]"),
]
PHI_TERMS = ["patient record", "medical record", "diagnosis", "patient name", "date of birth"]

def inspect_prompt(text: str) -> Tuple[bool, str]:
    lowered = text.lower()
    if any(re.search(p, lowered) for p in INJECTION_PATTERNS):
        return False, "prompt_injection_detected"
    if any(term in lowered for term in PHI_TERMS):
        return False, "potential_phi_detected"
    if any(pattern.search(text) for pattern, _ in PII_PATTERNS):
        return False, "potential_pii_detected"
    return True, "allowed"

def redact_output(text: str) -> str:
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text
