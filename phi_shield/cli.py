#!/usr/bin/env python3
"""PHI-Shield CLI — Scan text for PHI/PII from the command line."""
import argparse
import json
import sys

from .scanner import FastPHIScanner, _PATTERN_SPECS


def main() -> None:
    """Entry point for the phi-shield CLI."""
    parser = argparse.ArgumentParser(
        prog="phi-shield",
        description="Fast PHI/PII scanner for LLM pipelines",
    )
    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_p = subparsers.add_parser("scan", help="Scan text for PHI/PII")
    scan_p.add_argument("text", nargs="?", help="Text to scan (or pipe via stdin)")
    scan_p.add_argument("--json", action="store_true", help="Output as JSON")

    # redact command
    redact_p = subparsers.add_parser("redact", help="Redact PHI/PII from text")
    redact_p.add_argument("text", nargs="?", help="Text to redact (or pipe via stdin)")
    redact_p.add_argument(
        "--preset",
        choices=["ems", "billing", "radiology", "dialysis"],
        default=None,
        help="Use redaction preset (default: redact all patterns)",
    )

    # patterns command
    subparsers.add_parser("patterns", help="List all detection patterns")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    scanner = FastPHIScanner()

    if args.command == "scan":
        text = args.text if args.text is not None else sys.stdin.read()
        result = scanner.scan(text)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            if not result["phi_detected"]:
                print("No PHI/PII detected.")
            else:
                entities = result["entities"]
                print(f"Found {len(entities)} PHI/PII match(es):\n")
                for entity in entities:
                    # Look up risk for this entity type
                    spec = _PATTERN_SPECS.get(entity["type"])
                    risk = spec[2] if spec else "unknown"
                    print(f"  [{risk.upper():8s}] {entity['type']}: {entity['value']}")
                print(f"\nOverall risk: {result['risk'].upper()} | Regulation: {result['regulation']}")
        sys.exit(1 if result["phi_detected"] else 0)

    elif args.command == "redact":
        text = args.text if args.text is not None else sys.stdin.read()
        preset = args.preset
        if preset == "ems":
            redacted = scanner.redact_ems(text)
        elif preset == "billing":
            redacted = scanner.redact_billing(text)
        elif preset == "radiology":
            redacted = scanner.redact_radiology(text)
        elif preset == "dialysis":
            redacted = scanner.redact_dialysis(text)
        else:
            redacted = scanner.redact(text)
        print(redacted)

    elif args.command == "patterns":
        for name, spec in _PATTERN_SPECS.items():
            risk = spec[2]
            regulation = spec[3]
            print(f"  [{risk.upper():8s}] [{regulation:8s}] {name}")


if __name__ == "__main__":
    main()
