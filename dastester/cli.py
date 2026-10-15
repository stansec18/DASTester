"""DASTester command-line interface."""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

from .__version__ import __version__
from .core.config import ScanConfig
from .core.scanner import Scanner
from .core.updater import update as do_update
from .reporting import build_reports

BANNER = r"""
  ____    _    ____ _____         _
 |  _ \  / \  / ___|_   _|__  ___| |_ ___ _ __
 | | | |/ _ \ \___ \ | |/ _ \/ __| __/ _ \ '__|
 | |_| / ___ \ ___) || |  __/\__ \ ||  __/ |
 |____/_/   \_\____/ |_|\___||___/\__\___|_|
          DAST scanner  v%s
""" % __version__

AUTH_NOTICE = (
    "DASTester performs active security testing. Only scan systems you own or\n"
    "are explicitly authorised to test. Unauthorised scanning may be illegal."
)


def _log(msg):
    print(f"[dastester] {msg}", file=sys.stderr)


def _normalise_target(t: str) -> str:
    if not urlparse(t).scheme:
        t = "https://" + t
    return t


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dastester",
        description="DASTester — DAST scanner with OWASP Top 10 & STRIDE reporting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=AUTH_NOTICE,
    )
    p.add_argument("targets", nargs="*", help="Target URL(s), e.g. https://example.com")
    p.add_argument("--update", action="store_true",
                   help="Update DASTester from GitHub and exit.")
    p.add_argument("--version", action="version",
                   version=f"dastester {__version__}")

    scan = p.add_argument_group("scan options")
    scan.add_argument("-I", "--i-am-authorized", action="store_true",
                      help="Confirm you are authorised to test the target(s). "
                           "Required to enable active checks.")
    scan.add_argument("--passive-only", action="store_true",
                      help="Run only passive checks (no requests beyond crawl).")
    scan.add_argument("--aggressive", action="store_true",
                      help="Enable high-risk checks (HTTP request smuggling, "
                           "aggressive SSRF) that may disrupt live traffic. "
                           "Requires -I. Use only with explicit permission.")
    scan.add_argument("--depth", type=int, default=2, help="Max crawl depth (default 2).")
    scan.add_argument("--max-pages", type=int, default=200,
                      help="Max pages to crawl (default 200).")
    scan.add_argument("--include-subdomains", action="store_true",
                      help="Treat subdomains of the target as in scope.")
    scan.add_argument("--scope", action="append", default=[],
                      help="Additional in-scope host (repeatable).")
    scan.add_argument("--rate", type=float, default=5.0,
                      help="Max requests per second (default 5).")
    scan.add_argument("--timeout", type=float, default=15.0,
                      help="Per-request timeout seconds (default 15).")
    scan.add_argument("--header", action="append", default=[],
                      metavar="K:V", help="Extra request header (repeatable).")
    scan.add_argument("--cookie", action="append", default=[],
                      metavar="K=V", help="Request cookie (repeatable).")
    scan.add_argument("--insecure", action="store_true",
                      help="Do not verify TLS certs (issues are still reported).")

    out = p.add_argument_group("output options")
    out.add_argument("-o", "--output-dir", default="reports",
                     help="Directory for reports (default ./reports).")
    out.add_argument("-n", "--name", default="dastester-report",
                     help="Report base filename (default dastester-report).")
    out.add_argument("-f", "--format", default="html,pdf",
                     help="Comma list: html,pdf,json (default html,pdf).")
    return p


def _parse_kv(items, sep):
    out = {}
    for it in items:
        if sep in it:
            k, v = it.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.update:
        print(BANNER)
        return do_update(logger=print)

    if not args.targets:
        build_parser().print_help()
        return 1

    print(BANNER, file=sys.stderr)

    active = not args.passive_only
    authorized = args.i_am_authorized
    if active and not authorized:
        _log("NOTE: active checks require --i-am-authorized (-I). "
             "Running in passive-only mode.")
        _log(AUTH_NOTICE.replace("\n", " "))

    targets = [_normalise_target(t) for t in args.targets]
    formats = [f.strip() for f in args.format.split(",") if f.strip()]

    config = ScanConfig(
        targets=targets,
        authorized=authorized,
        active=active,
        aggressive=args.aggressive,
        max_depth=args.depth,
        max_pages=args.max_pages,
        include_subdomains=args.include_subdomains,
        extra_scope_hosts=set(args.scope),
        rate_limit=args.rate,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        headers=_parse_kv(args.header, ":"),
        cookies=_parse_kv(args.cookie, "="),
        output_dir=args.output_dir,
        report_name=args.name,
        formats=formats,
    )

    scanner = Scanner(config, logger=_log)
    result = scanner.run()

    counts = result.by_severity()
    _log("Severity summary: " + ", ".join(
        f"{k}={v}" for k, v in counts.items() if v))

    written = build_reports(result, logger=_log)
    for path in written:
        _log(f"Report written: {path}")
    if not written:
        _log("No reports written (check --format).")

    # Exit code reflects worst severity for CI pipelines.
    worst = max((int(f.severity) for f in result.findings), default=0)
    return 0 if worst < 3 else 2  # non-zero if High/Critical present


if __name__ == "__main__":
    sys.exit(main())
