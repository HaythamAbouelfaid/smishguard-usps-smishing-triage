from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .analyzers import triage_sms


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="SmishGuard - quick SMS phishing triage")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", help="SMS text to analyze")
    g.add_argument("--file", help="Path to a text file containing the SMS")
    p.add_argument("--from", dest="from_number", help="Sender phone number (optional)")
    p.add_argument("--attachment", help="Attachment filename if present (optional)")
    p.add_argument("--json", dest="json_out", action="store_true", help="Output JSON only")
    args = p.parse_args(argv)

    if args.file:
        msg = Path(args.file).read_text(encoding="utf-8", errors="ignore").strip()
    else:
        msg = args.text.strip()

    res = triage_sms(msg, from_number=args.from_number, attachment=args.attachment)

    if args.json_out:
        print(json.dumps(res.to_dict(), indent=2))
        return 0

    c = Console()
    c.print(f"[bold]Risk:[/bold] {res.risk}  [bold]Score:[/bold] {res.score}/100\n")

    t = Table(title="Indicators (IOCs)")
    t.add_column("Type", style="bold")
    t.add_column("Value")

    if res.from_number:
        t.add_row("phone(sender)", res.from_number)
    for pnum in res.extracted_phones:
        t.add_row("phone", pnum)
    for u in res.urls:
        t.add_row("url", u)
    for d in res.domains:
        t.add_row("domain", d)
    if res.attachment:
        t.add_row("attachment", res.attachment)

    c.print(t)

    r = Table(title="Why it was flagged")
    r.add_column("#", style="bold")
    r.add_column("Reason")
    for i, reason in enumerate(res.reasons, start=1):
        r.add_row(str(i), reason)
    c.print(r)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
