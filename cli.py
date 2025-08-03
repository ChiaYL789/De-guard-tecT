import argparse
import sys
from typing import List
from rules import apply_rules, apply_benign_rules
from ml_models import classify_url, classify_cmd
from logger import get_logger
from security_utils import validate_url, validate_cmd, sanitize_text

logger = get_logger()

# -------------------------------------------------------------------
# utilities
# -------------------------------------------------------------------
def log_and_print(kind: str, label: str, extra: str = "") -> None:
    prefix = f"{kind} → "
    print(f"{prefix}{label}" + (f" ({extra})" if extra else ""))
    logger.info("%s => %s%s", kind, label, f" ({extra})" if extra else "")

# -------------------------------------------------------------------
# handlers
# -------------------------------------------------------------------
def handle_url(url: str) -> None:
    if not url:
        log_and_print("URL", "ERROR: missing URL")
        sys.exit(1)

    if not validate_url(url):
        log_and_print("URL", "ERROR: invalid syntax")
        sys.exit(1)

    label = classify_url(url)
    log_and_print("URL", label)

def handle_cmd(cmd_parts: List[str]) -> None:
 
    import sys

    cmd = " ".join(cmd_parts).strip()

    try:
        from security_utils import sanitize_text
        cmd = sanitize_text(cmd)
    except Exception:
        pass

    if not cmd:
        log_and_print("CMD", "ERROR: no command provided")
        sys.exit(1)

    allow_unsafe = ("--unsafe" in sys.argv)

    if not allow_unsafe and not validate_cmd(cmd):
        log_and_print("CMD", "ERROR: unsafe characters")
        sys.exit(1)

    
    try:
        from rules import apply_benign_rules  
        safe_hits = apply_benign_rules(cmd)
    except Exception:
        safe_hits = []
    if safe_hits:
        if "-v" in sys.argv or "--verbose" in sys.argv:
            print(f"[debug] benign pattern: {', '.join(safe_hits)}")
        
        log_and_print("CMD", "benign", extra=", ".join(safe_hits))
        return

    rule_hits = apply_rules(cmd)
    if rule_hits:
        if "-v" in sys.argv or "--verbose" in sys.argv:
            print(f"[debug] rule hits: {', '.join(rule_hits)}")
        log_and_print("CMD", "Malicious", extra=", ".join(rule_hits))
        logger.warning("RuleOverride – hits: %s", ", ".join(rule_hits))
        return

    if "-v" in sys.argv or "--verbose" in sys.argv:
        try:
            from nlp_features import meta_tokens
            print(f"[debug] nlp: {meta_tokens(cmd)}")
        except Exception:
            pass

    label = classify_cmd(cmd)
    log_and_print("CMD", label)


def handle_rule(text: str) -> None:
    """Run only the regex rule engine and print the outcome."""
    if not text:
        log_and_print("RULE", "ERROR: missing text")
        sys.exit(1)

    hits = apply_rules(text)
    if hits:
        log_and_print("RULE", "Suspicious", extra=", ".join(hits))
    else:
        log_and_print("RULE", "Legitimate")


def main() -> None:
    import logging  

    parser = argparse.ArgumentParser(
        prog="MalCommandGuard",
        description="Classify URLs and command strings using rules and ML.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose mode (may print extra debug info from handlers)"
    )
    sub = parser.add_subparsers(dest="subcmd")

    # classify-url
    p_url = sub.add_parser("classify-url", help="Classify a URL")
    p_url.add_argument("url", help="The URL to classify")

    # classify-cmd 
    p_cmd = sub.add_parser("classify-cmd", help="Classify a command string")
    p_cmd.add_argument(
        "cmd_parts",
        nargs=argparse.REMAINDER,
        help='Entire command string to classify, e.g.  classify-cmd powershell -Command "..."',
    )

    # rule-check
    p_rule = sub.add_parser("rule-check", help="Run regex rule engine only")
    p_rule.add_argument("string", help="Arbitrary text/command to check against rules")

    args = parser.parse_args()

    if args.verbose:
        try:
            logger.setLevel(logging.DEBUG)
        except Exception:
            pass

    try:
        if args.subcmd == "classify-url":
            handle_url(args.url)
        elif args.subcmd == "classify-cmd":
            handle_cmd(args.cmd_parts)
        elif args.subcmd == "rule-check":
            handle_rule(args.string)
        else:
            parser.print_help()
            sys.exit(1)
    except SystemExit:
        raise
    except Exception:
        logger.exception("Fatal error")
        print("❌ Unexpected error – see log for details.")
        sys.exit(1)


if __name__ == "__main__":
    main()
