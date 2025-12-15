import argparse
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import urllib.error


def _http_get_json(url: str, timeout_s: int = 30, debug: bool = False) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "nsip-2025-shodan-stats"})
    if debug:
        print(f"[debug] GET {url}", file=sys.stderr)
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        data = resp.read()
    return json.loads(data.decode("utf-8"))


def shodan_count(
    api_key: str,
    query: str,
    facets: str | None = None,
    retries: int = 3,
    timeout_s: int = 30,
    debug: bool = False,
) -> dict:
    params = {"key": api_key, "query": query}
    if facets:
        params["facets"] = facets

    url = "https://api.shodan.io/shodan/host/count?" + urllib.parse.urlencode(params)

    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            return _http_get_json(url, timeout_s=timeout_s, debug=debug)
        except urllib.error.HTTPError as e:
            last_err = e
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            # Shodan occasionally returns 500s for transient issues or query parser hiccups.
            # Make the error actionable.
            msg = f"HTTP {getattr(e, 'code', '?')} {getattr(e, 'reason', '')}".strip()
            if body:
                msg += f" | body={body[:500]}"
            if debug:
                print(f"[debug] Shodan error for query={query!r}: {msg}", file=sys.stderr)
            # Backoff and retry.
            time.sleep(2.0 * (attempt + 1))
        except Exception as e:
            last_err = e
            time.sleep(2.0 * (attempt + 1))

    raise RuntimeError(f"Shodan request failed after {retries} retries: {last_err}")


def pct(part: int, whole: int) -> str:
    if whole <= 0:
        return "n/a"
    return f"{(100.0 * part / whole):.2f}%"


def _csv_list(v: str | None) -> list[str]:
    if not v:
        return []
    return [x.strip() for x in v.split(",") if x.strip()]


def build_checks(profile: str, smtp_products: list[str], imap_products: list[str], pop3_products: list[str]) -> list[dict]:
    """Build Shodan count queries.

    Profiles:
      - loose: only port-based counts (maximum coverage, more noise)
      - protocol: add banner/protocol keyword constraints (higher precision)
      - product: restrict to known mail server products; runs per-product queries (highest precision)

    Note: Shodan query language differs by dataset; these are best-effort filters.
    """

    if profile not in {"loose", "protocol", "product"}:
        raise ValueError(f"Unknown profile: {profile}")

    # Base queries per protocol.
    if profile == "protocol":
        smtp587_base = 'port:587 ("ESMTP" OR "EHLO" OR "250-")'
        imap143_base = 'port:143 ("IMAP4rev1" OR "CAPABILITY")'
        pop3110_base = 'port:110 ("+OK" AND ("POP3" OR "CAPA"))'
    else:
        smtp587_base = "port:587"
        imap143_base = "port:143"
        pop3110_base = "port:110"

    checks: list[dict] = []

    if profile == "product":
        # Run per-product counts to avoid expensive OR unions.
        for p in smtp_products:
            checks.append({
                "name": f"SMTP total (port 587) [{p}]",
                "query": f"port:587 product:{p}",
                "kind": "total",
            })
            checks.append({
                "name": f"SMTP: AUTH advertised on 587 (potentially pre-TLS) [{p}]",
                "query": f"port:587 product:{p} (\"250-AUTH\" OR \"AUTH\") (PLAIN OR LOGIN)",
                "kind": "indicator",
                "denom": f"SMTP total (port 587) [{p}]",
            })

        for p in imap_products:
            checks.append({
                "name": f"IMAP total (port 143) [{p}]",
                "query": f"port:143 product:{p}",
                "kind": "total",
            })
            checks.append({
                "name": f"IMAP: AUTH=PLAIN/LOGIN on 143 without LOGINDISABLED (indicator) [{p}]",
                "query": f"port:143 product:{p} (\"AUTH=PLAIN\" OR \"AUTH=LOGIN\") -LOGINDISABLED",
                "kind": "indicator",
                "denom": f"IMAP total (port 143) [{p}]",
            })

        for p in pop3_products:
            checks.append({
                "name": f"POP3 total (port 110) [{p}]",
                "query": f"port:110 product:{p}",
                "kind": "total",
            })
            checks.append({
                "name": f"POP3: USER/PASS keywords on 110 (weak indicator) [{p}]",
                "query": f"port:110 product:{p} (\"USER\" OR \"PASS\")",
                "kind": "indicator",
                "denom": f"POP3 total (port 110) [{p}]",
            })

        # Implicit TLS ports as separate totals.
        checks.extend([
            {"name": "SMTPS total (port 465)", "query": "port:465", "kind": "total"},
            {"name": "IMAPS total (port 993)", "query": "port:993", "kind": "total"},
            {"name": "POP3S total (port 995)", "query": "port:995", "kind": "total"},
        ])
        return checks

    # loose / protocol profiles
    checks.extend([
        {
            "name": "SMTP total (port 587)",
            "query": smtp587_base,
            "kind": "total",
        },
        {
            "name": "SMTP: AUTH advertised on 587 (potentially pre-TLS)",
            "query": f"{smtp587_base} (\"250-AUTH\" OR \"AUTH\") (PLAIN OR LOGIN)",
            "kind": "indicator",
            "denom": "SMTP total (port 587)",
        },
        {
            "name": "IMAP total (port 143)",
            "query": imap143_base,
            "kind": "total",
        },
        {
            "name": "IMAP: AUTH=PLAIN/LOGIN on 143 without LOGINDISABLED (indicator)",
            "query": f"{imap143_base} (\"AUTH=PLAIN\" OR \"AUTH=LOGIN\") -LOGINDISABLED",
            "kind": "indicator",
            "denom": "IMAP total (port 143)",
        },
        {
            "name": "POP3 total (port 110)",
            "query": pop3110_base,
            "kind": "total",
        },
        {
            "name": "POP3: USER/PASS keywords on 110 (weak indicator)",
            "query": f"{pop3110_base} (\"USER\" OR \"PASS\")",
            "kind": "indicator",
            "denom": "POP3 total (port 110)",
        },
        {"name": "SMTPS total (port 465)", "query": "port:465", "kind": "total"},
        {"name": "IMAPS total (port 993)", "query": "port:993", "kind": "total"},
        {"name": "POP3S total (port 995)", "query": "port:995", "kind": "total"},
    ])
    return checks


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", dest="api_key", default=os.environ.get("SHODAN_API_KEY"))
    ap.add_argument(
        "--facets",
        default=None,
        help='Optional Shodan facets, e.g. "country:10,org:10,product:10"',
    )
    ap.add_argument("--out", default=None, help="Write full JSON results to this file")
    ap.add_argument(
        "--sleep",
        type=float,
        default=1.0,
        help="Seconds to sleep between API calls (rate limit friendly)",
    )
    ap.add_argument(
        "--only",
        default=None,
        help="Run only checks whose name contains this substring (case-insensitive)",
    )
    ap.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue even if a query fails (failed checks will show an error)",
    )
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument(
        "--profile",
        choices=["loose", "protocol", "product"],
        default="loose",
        help="Query profile: loose=ports only, protocol=ports+protocol keywords, product=restrict to known mail products",
    )
    ap.add_argument(
        "--smtp-products",
        default="Postfix,Exim",
        help="Comma-separated Shodan product names for SMTP product profile",
    )
    ap.add_argument(
        "--imap-products",
        default="Dovecot,Cyrus IMAPd",
        help="Comma-separated Shodan product names for IMAP product profile",
    )
    ap.add_argument(
        "--pop3-products",
        default="Dovecot",
        help="Comma-separated Shodan product names for POP3 product profile",
    )

    args = ap.parse_args()

    if not args.api_key:
        print("Missing API key. Set SHODAN_API_KEY or pass --key.", file=sys.stderr)
        return 2

    smtp_products = _csv_list(args.smtp_products)
    imap_products = _csv_list(args.imap_products)
    pop3_products = _csv_list(args.pop3_products)

    checks = build_checks(args.profile, smtp_products, imap_products, pop3_products)

    if args.only:
        needle = args.only.lower()
        checks = [c for c in checks if needle in c["name"].lower()]
        if not checks:
            print(f"No checks matched --only={args.only!r}", file=sys.stderr)
            return 2

    results: dict[str, dict] = {}

    for c in checks:
        name = c["name"]
        try:
            res = shodan_count(
                args.api_key,
                c["query"],
                facets=args.facets,
                retries=max(1, args.retries),
                timeout_s=max(5, args.timeout),
                debug=args.debug,
            )
            results[name] = {
                "query": c["query"],
                "total": int(res.get("total", 0)),
            }
            if "facets" in res:
                results[name]["facets"] = res["facets"]
        except Exception as e:
            if not args.continue_on_error:
                raise
            results[name] = {
                "query": c["query"],
                "total": 0,
                "error": str(e),
            }
        time.sleep(max(0.0, args.sleep))

    totals = {name: r["total"] for name, r in results.items()}

    print(f"Shodan-based mail ecosystem indicators (no active scanning) | profile={args.profile}")
    print("NOTE: These are banner-based indicators, not a proof of plaintext auth acceptance.")
    print("")

    for c in checks:
        name = c["name"]
        total = results[name]["total"]
        if "error" in results[name]:
            print(f"- {name}: ERROR: {results[name]['error']}")
            continue
        if c.get("kind") == "indicator" and c.get("denom"):
            denom_total = totals.get(c["denom"], 0)
            print(f"- {name}: {total} / {denom_total} ({pct(total, denom_total)})")
        else:
            print(f"- {name}: {total}")

    if args.out:
        payload = {
            "generated_at_unix": int(time.time()),
            "profile": args.profile,
            "checks": checks,
            "results": results,
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        print(f"\nWrote JSON to: {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
