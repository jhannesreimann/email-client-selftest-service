import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from math import isfinite
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _require_matplotlib() -> tuple[Any, Any, Any]:
    try:
        import matplotlib  # type: ignore

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # type: ignore
        from matplotlib.patches import Patch  # type: ignore
        from matplotlib.ticker import PercentFormatter  # type: ignore

        return plt, PercentFormatter, Patch
    except Exception as e:
        raise RuntimeError(
            "matplotlib is required to render plots. Install it (e.g. pip install matplotlib) and retry."
        ) from e


@dataclass(frozen=True)
class Row:
    name: str
    query: str
    total: int
    error: str | None


def _load_rows(payload: dict) -> dict[str, Row]:
    results = payload.get("results", {})
    out: dict[str, Row] = {}
    for name, r in results.items():
        out[name] = Row(
            name=name,
            query=str(r.get("query", "")),
            total=int(r.get("total", 0)),
            error=(str(r.get("error")) if "error" in r else None),
        )
    return out


def _strip_product(name: str) -> tuple[str, str | None]:
    m = re.match(r"^(.*)\s\[(.+)\]$", name)
    if not m:
        return name, None
    return m.group(1), m.group(2)


def _safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _savefig(plt: Any, outdir: Path, stem: str, formats: list[str]) -> list[Path]:
    paths: list[Path] = []
    for fmt in formats:
        path = outdir / f"{stem}.{fmt}"
        plt.savefig(path, bbox_inches="tight", dpi=200)
        paths.append(path)
    return paths


def _pct(part: int, whole: int) -> float | None:
    if whole <= 0:
        return None
    return part / whole


def _human_int(n: int) -> str:
    absn = abs(int(n))
    if absn >= 1_000_000_000:
        return f"{n/1_000_000_000:.2f}B"
    if absn >= 1_000_000:
        return f"{n/1_000_000:.2f}M"
    if absn >= 1_000:
        return f"{n/1_000:.2f}K"
    return str(n)


def _fmt_int(n: int) -> str:
    return f"{int(n):,}"


def _annotate_bars(ax: Any, bars: Any, *, fmt: str = "int", fontsize: int = 9) -> None:
    for b in bars:
        try:
            h = float(b.get_height())
        except Exception:
            continue
        if not isfinite(h):
            continue
        if fmt == "int":
            txt = _fmt_int(int(round(h)))
        elif fmt == "human":
            txt = _human_int(int(round(h)))
        else:
            txt = str(h)
        ax.text(
            b.get_x() + b.get_width() / 2,
            h,
            txt,
            ha="center",
            va="bottom",
            fontsize=fontsize,
            rotation=0,
        )


def _add_caption(fig: Any, text: str, *, x: float = 0.01, y: float = 0.01) -> None:
    fig.text(
        x,
        y,
        text,
        ha="left",
        va="bottom",
        fontsize=9,
        bbox={
            "boxstyle": "round,pad=0.35",
            "facecolor": "#f7f7f7",
            "edgecolor": "#d0d0d0",
            "alpha": 0.95,
        },
    )


def _wrap_label(s: str, width: int = 24) -> str:
    return "\n".join(textwrap.wrap(str(s), width=width, break_long_words=False, break_on_hyphens=False))


def _sum_product_totals(rows: dict[str, Row], base_name: str) -> int | None:
    total = 0
    found = False
    prefix = f"{base_name} ["
    for name, row in rows.items():
        if not name.startswith(prefix):
            continue
        if row.error:
            continue
        found = True
        total += row.total
    return total if found else None


def _get_total(rows: dict[str, Row], base_name: str) -> int | None:
    if base_name in rows and not rows[base_name].error:
        return rows[base_name].total
    return _sum_product_totals(rows, base_name)


def _get_ratio(rows: dict[str, Row], num_base: str, den_base: str) -> tuple[float | None, int | None, int | None]:
    num = _get_total(rows, num_base)
    den = _get_total(rows, den_base)
    if num is None or den is None:
        return None, num, den
    return _pct(num, den), num, den


def _plot_totals_overview(
    plt: Any,
    Patch: Any,
    outdir: Path,
    rows: dict[str, Row],
    title_prefix: str,
    formats: list[str],
    profile: str | None,
) -> list[Path]:
    # Prefer non-product totals if present.
    wanted = [
        "SMTP total (port 587)",
        "IMAP total (port 143)",
        "POP3 total (port 110)",
        "SMTPS total (port 465)",
        "IMAPS total (port 993)",
        "POP3S total (port 995)",
    ]

    label_map = {
        "SMTP total (port 587)": "SMTP Submission (587)\nSTARTTLS",
        "IMAP total (port 143)": "IMAP (143)\nSTARTTLS",
        "POP3 total (port 110)": "POP3 (110)\nSTARTTLS",
        "SMTPS total (port 465)": "SMTPS (465)\nImplicit TLS",
        "IMAPS total (port 993)": "IMAPS (993)\nImplicit TLS",
        "POP3S total (port 995)": "POP3S (995)\nImplicit TLS",
    }

    starttls_color = "#f39c12"
    implicit_color = "#27ae60"

    starttls_names = ["SMTP total (port 587)", "IMAP total (port 143)", "POP3 total (port 110)"]
    implicit_names = ["SMTPS total (port 465)", "IMAPS total (port 993)", "POP3S total (port 995)"]

    starttls_labels: list[str] = []
    starttls_values: list[int] = []
    for name in starttls_names:
        v = _get_total(rows, name)
        if v is None:
            continue
        starttls_labels.append(label_map.get(name, name))
        starttls_values.append(v)

    implicit_labels: list[str] = []
    implicit_values: list[int] = []
    for name in implicit_names:
        v = _get_total(rows, name)
        if v is None:
            continue
        implicit_labels.append(label_map.get(name, name))
        implicit_values.append(v)

    if not starttls_labels and not implicit_labels:
        return []

    fig = plt.figure(figsize=(12.5, 5.0))
    ax1 = fig.add_subplot(1, 2, 1)
    ax2 = fig.add_subplot(1, 2, 2)

    subtitle = f" (profile={profile})" if profile else ""
    fig.suptitle(f"{title_prefix}Mail services observed by Shodan (totals){subtitle}", x=0.5)

    if starttls_labels:
        b1 = ax1.bar(range(len(starttls_values)), starttls_values, color=starttls_color)
        ax1.set_xticks(range(len(starttls_labels)))
        ax1.set_xticklabels(starttls_labels, rotation=0)
        ax1.set_title("STARTTLS ports")
        ax1.set_ylabel("Count (Shodan dataset)")
        ax1.grid(axis="y", alpha=0.25)
        _annotate_bars(ax1, b1, fmt="int", fontsize=8)

    if implicit_labels:
        b2 = ax2.bar(range(len(implicit_values)), implicit_values, color=implicit_color)
        ax2.set_xticks(range(len(implicit_labels)))
        ax2.set_xticklabels(implicit_labels, rotation=0)
        ax2.set_title("Implicit TLS ports")
        ax2.grid(axis="y", alpha=0.25)
        _annotate_bars(ax2, b2, fmt="int", fontsize=8)

    fig.legend(
        handles=[
            Patch(facecolor=starttls_color, label="STARTTLS ports (downgrade-relevant)"),
            Patch(facecolor=implicit_color, label="Implicit TLS ports (baseline)"),
        ],
        loc="lower center",
        bbox_to_anchor=(0.5, 0.08),
        borderaxespad=0,
        frameon=True,
        ncol=2,
    )

    _add_caption(
        fig,
        "Totals are counts of Shodan-observed services (not unique organizations).",
        y=0.015,
    )

    fig.tight_layout(rect=[0.0, 0.22, 1.0, 0.92])

    return _savefig(plt, outdir, "totals_overview", formats)


def _plot_indicators_overview(
    plt: Any,
    PercentFormatter: Any,
    Patch: Any,
    outdir: Path,
    rows: dict[str, Row],
    title_prefix: str,
    formats: list[str],
    profile: str | None,
) -> list[Path]:
    # Compute ratios for the non-product overview.
    pairs = [
        (
            "SMTP: AUTH advertised on 587 (potentially pre-TLS)",
            "SMTP total (port 587)",
            "SMTP 587: AUTH advertised",
        ),
        (
            "IMAP: AUTH=PLAIN/LOGIN on 143 without LOGINDISABLED (indicator)",
            "IMAP total (port 143)",
            "IMAP 143: AUTH without LOGINDISABLED",
        ),
        (
            "POP3: USER/PASS keywords on 110 (weak indicator)",
            "POP3 total (port 110)",
            "POP3 110: USER/PASS keyword",
        ),
    ]

    labels: list[str] = []
    ratios: list[float] = []
    numerators: list[int] = []
    denominators: list[int] = []

    for num_name, den_name, label in pairs:
        ratio, num, den = _get_ratio(rows, num_name, den_name)
        if ratio is None or num is None or den is None:
            continue
        labels.append(label)
        ratios.append(ratio)
        numerators.append(num)
        denominators.append(den)

    if not labels:
        return []

    fig = plt.figure(figsize=(12.5, 5.2))
    ax = fig.add_subplot(1, 1, 1)
    risk_color = "#c0392b"
    ok_color = "#2ecc71"

    risk = ratios
    ok = [max(0.0, 1.0 - r) for r in ratios]

    x = list(range(len(labels)))
    b1 = ax.bar(x, risk, color=risk_color, label="Indicator present")
    b2 = ax.bar(x, ok, bottom=risk, color=ok_color, label="Indicator not present")
    ax.set_xticks(range(len(labels)))
    wrapped = [_wrap_label(l, width=22) for l in labels]
    ax.set_xticklabels(wrapped, rotation=0, ha="center")
    ax.set_ylim(0, 1)
    ax.yaxis.set_major_formatter(PercentFormatter(1.0))
    ax.set_ylabel("Share")
    subtitle = f" (profile={profile})" if profile else ""
    ax.set_title(f"{title_prefix}Banner-based indicators (share of services){subtitle}")
    ax.grid(axis="y", alpha=0.25)
    ax.margins(x=0.08)

    for i, _ in enumerate(labels):
        ax.text(
            i,
            min(0.98, risk[i] + 0.015),
            f"{risk[i]*100:.1f}%\n({_fmt_int(numerators[i])}/{_fmt_int(denominators[i])})",
            ha="center",
            va="bottom",
            fontsize=9,
            color=risk_color,
        )

    fig.legend(
        handles=[
            Patch(
                facecolor=risk_color,
                label="Indicator present (banner suggests plaintext-capable auth on STARTTLS port)",
            ),
            Patch(facecolor=ok_color, label="Indicator absent"),
        ],
        loc="lower center",
        bbox_to_anchor=(0.5, 0.08),
        borderaxespad=0,
        frameon=True,
        ncol=1,
    )

    _add_caption(fig, "Indicator = passive banner-based heuristic (not a proof of credential acceptance).", y=0.015)

    fig.tight_layout(rect=[0.0, 0.26, 1.0, 0.92])

    return _savefig(plt, outdir, "indicators_overview", formats)


def _plot_product_breakdown(
    plt: Any,
    PercentFormatter: Any,
    Patch: Any,
    outdir: Path,
    rows: dict[str, Row],
    title_prefix: str,
    formats: list[str],
    profile: str | None,
) -> list[Path]:
    # If there are no product-suffixed rows, skip.
    has_products = any(_strip_product(n)[1] is not None for n in rows.keys())
    if not has_products:
        return []

    # Map by (base_name, product)
    by_base: dict[str, dict[str, Row]] = {}
    for name, row in rows.items():
        base, product = _strip_product(name)
        if product is None:
            continue
        by_base.setdefault(base, {})[product] = row

    plots: list[Path] = []

    risk_color = "#c0392b"
    ok_color = "#2ecc71"
    total_color = "#34495e"

    # SMTP breakdown
    smtp_total_base = "SMTP total (port 587)"
    smtp_ind_base = "SMTP: AUTH advertised on 587 (potentially pre-TLS)"
    if smtp_total_base in by_base and smtp_ind_base in by_base:
        products = sorted(set(by_base[smtp_total_base].keys()) & set(by_base[smtp_ind_base].keys()))
        totals = [by_base[smtp_total_base][p].total for p in products]
        nums = [by_base[smtp_ind_base][p].total for p in products]
        ratios = []
        for p in products:
            num = by_base[smtp_ind_base][p].total
            den = by_base[smtp_total_base][p].total
            r = _pct(num, den)
            ratios.append(0.0 if r is None else r)

        fig = plt.figure(figsize=(11.5, 4.8))
        ax1 = fig.add_subplot(1, 2, 1)
        bars1 = ax1.bar(range(len(products)), totals, color=total_color)
        ax1.set_xticks(range(len(products)))
        ax1.set_xticklabels(products, rotation=45, ha="right")
        ax1.set_title("SMTP Submission (587) totals")
        ax1.grid(axis="y", alpha=0.25)

        _annotate_bars(ax1, bars1, fmt="int", fontsize=8)

        ax2 = fig.add_subplot(1, 2, 2)
        ok = [max(0.0, 1.0 - r) for r in ratios]
        x = list(range(len(products)))
        ax2.bar(x, ratios, color=risk_color)
        ax2.bar(x, ok, bottom=ratios, color=ok_color)
        ax2.set_xticks(range(len(products)))
        ax2.set_xticklabels(products, rotation=45, ha="right")
        ax2.set_ylim(0, 1)
        ax2.yaxis.set_major_formatter(PercentFormatter(1.0))
        ax2.set_title("Indicator share (AUTH visible)")
        ax2.grid(axis="y", alpha=0.25)

        for i, p in enumerate(products):
            ax2.text(
                i,
                min(0.98, ratios[i] + 0.02),
                f"{ratios[i]*100:.1f}%\n({_fmt_int(nums[i])}/{_fmt_int(totals[i])})",
                ha="center",
                va="bottom",
                fontsize=8,
                color=risk_color,
            )

        fig.legend(
            handles=[
                Patch(facecolor=risk_color, label="Indicator present"),
                Patch(facecolor=ok_color, label="Indicator absent"),
            ],
            loc="lower center",
            bbox_to_anchor=(0.5, 0.08),
            borderaxespad=0,
            frameon=True,
            ncol=2,
        )

        subtitle = f" (profile={profile})" if profile else ""
        fig.suptitle(f"{title_prefix}SMTP Submission (587) by product{subtitle}", x=0.5)
        _add_caption(
            fig,
            "Indicator is a passive banner-based heuristic (not a proof of plaintext credential acceptance).",
            y=0.015,
        )
        fig.tight_layout(rect=[0.0, 0.26, 1.0, 0.92])
        plots += _savefig(plt, outdir, "smtp587_by_product", formats)

    # IMAP breakdown
    imap_total_base = "IMAP total (port 143)"
    imap_ind_base = "IMAP: AUTH=PLAIN/LOGIN on 143 without LOGINDISABLED (indicator)"
    if imap_total_base in by_base and imap_ind_base in by_base:
        products = sorted(set(by_base[imap_total_base].keys()) & set(by_base[imap_ind_base].keys()))
        totals = [by_base[imap_total_base][p].total for p in products]
        nums = [by_base[imap_ind_base][p].total for p in products]
        ratios = []
        for p in products:
            num = by_base[imap_ind_base][p].total
            den = by_base[imap_total_base][p].total
            r = _pct(num, den)
            ratios.append(0.0 if r is None else r)

        fig = plt.figure(figsize=(11.5, 4.8))
        ax1 = fig.add_subplot(1, 2, 1)
        bars1 = ax1.bar(range(len(products)), totals, color=total_color)
        ax1.set_xticks(range(len(products)))
        ax1.set_xticklabels(products, rotation=45, ha="right")
        ax1.set_title("IMAP (143) totals")
        ax1.grid(axis="y", alpha=0.25)

        _annotate_bars(ax1, bars1, fmt="int", fontsize=8)

        ax2 = fig.add_subplot(1, 2, 2)
        ok = [max(0.0, 1.0 - r) for r in ratios]
        x = list(range(len(products)))
        ax2.bar(x, ratios, color=risk_color)
        ax2.bar(x, ok, bottom=ratios, color=ok_color)
        ax2.set_xticks(range(len(products)))
        ax2.set_xticklabels(products, rotation=45, ha="right")
        ax2.set_ylim(0, 1)
        ax2.yaxis.set_major_formatter(PercentFormatter(1.0))
        ax2.set_title("Indicator share (AUTH without LOGINDISABLED)")
        ax2.grid(axis="y", alpha=0.25)

        for i, p in enumerate(products):
            ax2.text(
                i,
                min(0.98, ratios[i] + 0.02),
                f"{ratios[i]*100:.1f}%\n({_fmt_int(nums[i])}/{_fmt_int(totals[i])})",
                ha="center",
                va="bottom",
                fontsize=8,
                color=risk_color,
            )

        fig.legend(
            handles=[
                Patch(facecolor=risk_color, label="Indicator present"),
                Patch(facecolor=ok_color, label="Indicator absent"),
            ],
            loc="lower center",
            bbox_to_anchor=(0.5, 0.08),
            borderaxespad=0,
            frameon=True,
            ncol=2,
        )

        subtitle = f" (profile={profile})" if profile else ""
        fig.suptitle(f"{title_prefix}IMAP (143) by product{subtitle}", x=0.5)
        _add_caption(
            fig,
            "Indicator is a passive banner-based heuristic (not a proof of plaintext credential acceptance).",
            y=0.015,
        )
        fig.tight_layout(rect=[0.0, 0.26, 1.0, 0.92])
        plots += _savefig(plt, outdir, "imap143_by_product", formats)

    return plots


def _run_stats_script(stats_script: Path, args: list[str]) -> Path:
    out_json = Path(args[args.index("--out") + 1]) if "--out" in args else None
    if out_json is None:
        raise ValueError("--out is required when using --run")

    cmd = [sys.executable, str(stats_script), *args]
    proc = subprocess.run(cmd, stdout=sys.stdout, stderr=sys.stderr)
    if proc.returncode != 0:
        raise RuntimeError(f"Stats script failed with exit code {proc.returncode}")
    return out_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--input",
        default=None,
        help="Path to JSON created by shodan_mail_tls_stats.py --out ...",
    )
    ap.add_argument(
        "--outdir",
        default="./shodan-plots",
        help="Output directory for plots",
    )
    ap.add_argument(
        "--formats",
        default="png,pdf",
        help="Comma-separated output formats (e.g. png,pdf)",
    )
    ap.add_argument(
        "--title-prefix",
        default="",
        help="Optional prefix for plot titles (e.g. 'NSIP 2025 – ')",
    )

    ap.add_argument(
        "--run",
        action="store_true",
        help="Run shodan_mail_tls_stats.py first (requires --stats-script and --stats-args)",
    )
    ap.add_argument(
        "--stats-script",
        default=str(Path(__file__).with_name("shodan_mail_tls_stats.py")),
        help="Path to shodan_mail_tls_stats.py",
    )
    ap.add_argument(
        "--stats-args",
        default=None,
        help="Quoted arguments passed to shodan_mail_tls_stats.py (must include --out FILE)",
    )
    ap.add_argument(
        "--compare-input",
        action="append",
        default=[],
        help="Additional JSON files (from other profiles) to generate a profile comparison plot",
    )

    args = ap.parse_args()

    outdir = Path(args.outdir)
    _safe_mkdir(outdir)

    formats = [x.strip() for x in str(args.formats).split(",") if x.strip()]

    input_path: Path | None = Path(args.input) if args.input else None

    if args.run:
        if not args.stats_args:
            print("--stats-args is required with --run", file=sys.stderr)
            return 2
        # Split respecting simple quoting
        stats_args = args.stats_args.split()
        stats_script = Path(args.stats_script)
        input_path = _run_stats_script(stats_script, stats_args)

    if not input_path:
        print("Provide --input JSON or use --run.", file=sys.stderr)
        return 2

    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    rows = _load_rows(payload)
    profile = payload.get("profile") if isinstance(payload, dict) else None

    plt, PercentFormatter, Patch = _require_matplotlib()

    written: list[Path] = []
    written += _plot_totals_overview(plt, Patch, outdir, rows, str(args.title_prefix), formats, profile)
    written += _plot_indicators_overview(plt, PercentFormatter, Patch, outdir, rows, str(args.title_prefix), formats, profile)
    written += _plot_product_breakdown(plt, PercentFormatter, Patch, outdir, rows, str(args.title_prefix), formats, profile)

    # Optional: profile comparison (expects multiple JSONs produced with different profiles).
    compare_paths = [Path(p) for p in args.compare_input]
    if compare_paths:
        compare_payloads = [payload]
        for p in compare_paths:
            compare_payloads.append(json.loads(p.read_text(encoding="utf-8")))

        # Build comparison for three key metrics.
        profiles: list[str] = []
        smtp_shares: list[float] = []
        imap_shares: list[float] = []
        smtp_totals: list[int] = []
        imap_totals: list[int] = []

        for pl in compare_payloads:
            pr = pl.get("profile") if isinstance(pl, dict) else None
            pr = str(pr) if pr else "unknown"
            rr = _load_rows(pl)

            s_ratio, s_num, s_den = _get_ratio(rr, "SMTP: AUTH advertised on 587 (potentially pre-TLS)", "SMTP total (port 587)")
            i_ratio, i_num, i_den = _get_ratio(rr, "IMAP: AUTH=PLAIN/LOGIN on 143 without LOGINDISABLED (indicator)", "IMAP total (port 143)")

            s_total = _get_total(rr, "SMTP total (port 587)")
            i_total = _get_total(rr, "IMAP total (port 143)")

            if s_ratio is None or i_ratio is None or s_total is None or i_total is None:
                continue

            profiles.append(pr)
            smtp_shares.append(s_ratio)
            imap_shares.append(i_ratio)
            smtp_totals.append(s_total)
            imap_totals.append(i_total)

        if profiles:
            fig = plt.figure(figsize=(11.5, 5.6))
            ax1 = fig.add_subplot(1, 2, 1)
            x = list(range(len(profiles)))
            w = 0.35
            b1 = ax1.bar([i - w / 2 for i in x], smtp_totals, width=w, color="#f39c12", label="SMTP 587 total")
            b2 = ax1.bar([i + w / 2 for i in x], imap_totals, width=w, color="#3498db", label="IMAP 143 total")
            ax1.set_xticks(x)
            ax1.set_xticklabels(profiles)
            ax1.set_title("Totals by profile")
            ax1.set_ylabel("Count (Shodan)")
            ax1.grid(axis="y", alpha=0.25)
            _annotate_bars(ax1, b1, fmt="int", fontsize=8)
            _annotate_bars(ax1, b2, fmt="int", fontsize=8)

            ax2 = fig.add_subplot(1, 2, 2)
            b3 = ax2.bar([i - w / 2 for i in x], smtp_shares, width=w, color="#c0392b", label="SMTP indicator share")
            b4 = ax2.bar([i + w / 2 for i in x], imap_shares, width=w, color="#8e44ad", label="IMAP indicator share")
            ax2.set_xticks(x)
            ax2.set_xticklabels(profiles)
            ax2.set_ylim(0, 1)
            ax2.yaxis.set_major_formatter(PercentFormatter(1.0))
            ax2.set_title("Indicator shares by profile")
            ax2.grid(axis="y", alpha=0.25)
            for i in range(len(profiles)):
                ax2.text(i - w / 2, min(0.98, smtp_shares[i] + 0.02), f"{smtp_shares[i]*100:.1f}%", ha="center", va="bottom", fontsize=8)
                ax2.text(i + w / 2, min(0.98, imap_shares[i] + 0.02), f"{imap_shares[i]*100:.1f}%", ha="center", va="bottom", fontsize=8)

            fig.suptitle(f"{args.title_prefix}Effect of Shodan query profiles", x=0.5)
            ax1.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), borderaxespad=0, frameon=True, ncol=2)
            ax2.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), borderaxespad=0, frameon=True, ncol=2)
            fig.tight_layout(rect=[0.0, 0.18, 1.0, 0.92])
            written += _savefig(plt, outdir, "profiles_comparison", formats)

    if not written:
        print("No plots were generated (input JSON may not contain expected checks).", file=sys.stderr)
        return 1

    print("Wrote plots:")
    for p in written:
        print(f"- {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
