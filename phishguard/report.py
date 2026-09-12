"""Rendu terminal des analyses."""

from __future__ import annotations

import os
import sys

from .analyzer import Analysis
from .util import truncate

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
ORANGE = "\033[93m"
YELLOW = "\033[33m"
GREEN = "\033[92m"
BLUE = "\033[94m"
GREY = "\033[90m"

_COLOR_ENABLED = True


def setup_output(no_color: bool = False) -> None:
    """Active les séquences ANSI sous Windows et fixe l'encodage de sortie."""
    global _COLOR_ENABLED
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    _COLOR_ENABLED = not no_color and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if _COLOR_ENABLED and os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            _COLOR_ENABLED = False


def c(text: str, color: str) -> str:
    return f"{color}{text}{RESET}" if _COLOR_ENABLED else text


def verdict_color(score: int) -> str:
    if score >= 70:
        return RED
    if score >= 45:
        return ORANGE
    if score >= 22:
        return YELLOW
    return GREEN


def severity_marker(severity: str) -> str:
    return {
        "haute": c("[!!]", RED),
        "moyenne": c("[! ]", ORANGE),
        "basse": c("[. ]", YELLOW),
        "ok": c("[ok]", GREEN),
    }.get(severity, "[  ]")


def score_bar(score: int, width: int = 30) -> str:
    filled = round(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    return c(bar, verdict_color(score))


def render(analysis: Analysis, *, verbose: bool = False) -> str:
    mail = analysis.email
    color = verdict_color(analysis.score)
    lines: list[str] = []

    lines.append(c("─" * 78, GREY))
    header = f"{analysis.score:>3}/100  {analysis.verdict}"
    lines.append(f"{c(header, color + BOLD)}  {score_bar(analysis.score)}")

    sender = f"{mail.from_name} <{mail.from_addr}>" if mail.from_name else mail.from_addr
    lines.append(f"  {c('De     ', GREY)} {truncate(sender or '(inconnu)', 70)}")
    lines.append(f"  {c('Objet  ', GREY)} {truncate(mail.subject or '(sans objet)', 70)}")
    if mail.date:
        lines.append(f"  {c('Date   ', GREY)} {truncate(mail.date, 70)}")
    if mail.uid:
        lines.append(f"  {c('UID    ', GREY)} {mail.uid}  {c(mail.source, GREY)}")
    elif mail.source:
        lines.append(f"  {c('Source ', GREY)} {truncate(mail.source, 70)}")

    risky = analysis.risky_signals
    if risky:
        lines.append("")
        lines.append(f"  {c('Indices relevés', BOLD)}")
        grouped: dict[str, list] = {}
        for signal in risky:
            grouped.setdefault(signal.category, []).append(signal)
        # Catégories les plus chargées en premier, indices les plus lourds en tête.
        for category in sorted(grouped, key=lambda k: -max(s.weight for s in grouped[k])):
            lines.append(f"  {c(category.upper(), BLUE)}")
            for signal in sorted(grouped[category], key=lambda s: -s.weight):
                lines.append(f"    {severity_marker(signal.severity)} "
                             f"{signal.title} {c(f'(+{signal.weight})', GREY)}")
                if signal.detail:
                    lines.append(f"         {c(signal.detail, DIM if _COLOR_ENABLED else '')}")

    reassuring = analysis.reassuring_signals
    if reassuring and (verbose or not risky):
        lines.append("")
        lines.append(f"  {c('Éléments rassurants', BOLD)}")
        for signal in reassuring:
            weight = f" ({signal.weight})" if signal.weight else ""
            lines.append(f"    {severity_marker('ok')} {signal.title}{c(weight, GREY)}")
            if signal.detail:
                lines.append(f"         {c(signal.detail, DIM if _COLOR_ENABLED else '')}")

    if analysis.dampened:
        lines.append("")
        lines.append(c("  DMARC valide et aligné : les indices d'usurpation ont été "
                       "pondérés à la baisse.", GREY))

    if verbose:
        domains = sorted({l.domain for l in mail.links if l.domain})
        if domains:
            lines.append("")
            lines.append(f"  {c('Domaines des liens', BOLD)} : {', '.join(domains[:12])}")
        if mail.attachments:
            files = ", ".join(f"{a.filename} ({a.size // 1024} Ko)" for a in mail.attachments)
            lines.append(f"  {c('Pièces jointes', BOLD)} : {truncate(files, 200)}")

    lines.append("")
    lines.append(f"  {c('→ ' + analysis.advice, color)}")
    return "\n".join(lines)


def render_summary(analyses: list[Analysis]) -> str:
    if not analyses:
        return c("Aucun message analysé.", GREY)

    buckets = {"PHISHING": 0, "TRÈS SUSPECT": 0, "SUSPECT": 0, "PROBABLEMENT LÉGITIME": 0}
    for analysis in analyses:
        buckets[analysis.verdict] = buckets.get(analysis.verdict, 0) + 1

    lines = [c("═" * 78, GREY), c(f"  BILAN — {len(analyses)} message(s) analysé(s)", BOLD)]
    for verdict, count in buckets.items():
        if not count:
            continue
        color = {"PHISHING": RED, "TRÈS SUSPECT": ORANGE,
                 "SUSPECT": YELLOW}.get(verdict, GREEN)
        lines.append(f"    {c(f'{count:>3}', color + BOLD)}  {verdict}")

    worst = sorted(analyses, key=lambda a: -a.score)[:5]
    flagged = [a for a in worst if a.score >= 22]
    if flagged:
        lines.append("")
        lines.append(c("  À traiter en priorité", BOLD))
        for analysis in flagged:
            mail = analysis.email
            lines.append(f"    {c(f'{analysis.score:>3}', verdict_color(analysis.score))}  "
                         f"{truncate(mail.from_addr, 32):<34} "
                         f"{truncate(mail.subject or '(sans objet)', 36)}")
    lines.append(c("═" * 78, GREY))
    return "\n".join(lines)
