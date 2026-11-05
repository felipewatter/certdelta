"""Read-only CLI: explicit paths, deterministic statuses and no network requests."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from certdelta.drift import diff
from certdelta.inspector import scan
from certdelta.loader import InputError
from certdelta.model import SEVERITIES
from certdelta.report import render


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="certdelta", description="Offline PKI trust and certificate identity drift gate",
    )
    parser.add_argument("--version", action="version", version="CertDelta 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("scan", "diff"):
        p = commands.add_parser(name, help=("Audit a certificate manifest" if name == "scan" else
                                            "Compare two certificate manifests"))
        if name == "scan":
            p.add_argument("manifest")
        else:
            p.add_argument("--before", required=True)
            p.add_argument("--after", required=True)
        p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
        p.add_argument("--output", help="Write report atomically to a local file")
        p.add_argument("--fail-on", choices=("none", *SEVERITIES), default="high")
        p.add_argument("--at", help="Evaluation instant (UTC ISO-8601); for reproducible audits")
    opts = parser.parse_args(argv)
    try:
        now = None
        if opts.at:
            now = datetime.fromisoformat(opts.at.replace("Z", "+00:00"))
            if now.tzinfo is None:
                raise InputError("--at requires an explicit timezone, e.g. 2026-11-05T12:00:00Z")
            now = now.astimezone(timezone.utc)
        result = scan(opts.manifest, now) if opts.command == "scan" else diff(
            opts.before, opts.after, now,
        )
        content = render(result, opts.format)
        if opts.output:
            target = Path(opts.output)
            if target.is_symlink():
                raise InputError("Output target may not be a symbolic link")
            import os
            import tempfile

            # Atomic write in the target directory. New reports inherit private permissions.
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=target.parent, prefix=".certdelta-",
                delete=False,
            ) as handle:
                temporary = Path(handle.name)
                handle.write(content)
            try:
                os.replace(temporary, target)
            finally:
                temporary.unlink(missing_ok=True)
            print(f"Report written to {target}", file=sys.stderr)
        else:
            print(content, end="")
        return 1 if result.fails(opts.fail_on) else 0
    except (InputError, OSError, ValueError) as exc:
        print(f"certdelta: input error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
