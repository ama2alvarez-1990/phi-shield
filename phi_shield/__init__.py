"""phi-shield — Fast PHI/PII scanner for LLM pipelines.

Scans text for Protected Health Information (HIPAA), credit cards (PCI-DSS),
and personal data (GDPR) using regex patterns in <1ms. Zero dependencies.

Usage::

    from phi_shield import scan
    result = scan("Patient John Doe SSN 123-45-6789")
    if result["phi_detected"]:
        print("PHI found! Do not send to external APIs.")

Author: Amado Alvarez Sueiras
License: MIT
"""

from phi_shield.scanner import FastPHIScanner

__version__ = "0.1.0"
__all__ = ["FastPHIScanner", "scan"]

_default_scanner = FastPHIScanner()


def scan(text: str) -> dict:
    """Scan text for PHI/PII. Returns dict with phi_detected, entities, risk."""
    return _default_scanner.scan(text)
