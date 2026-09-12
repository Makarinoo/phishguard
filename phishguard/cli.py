"""Interface en ligne de commande de PhishGuard."""

from __future__ import annotations

import argparse
import getpass
import glob
import json
import os
import sys
from pathlib import Path

from .analyzer import Analysis, analyze
from .imap_client import ImapError, ImapSession, build_criteria, guess_server
from .parser import parse_message
from .report import GREY, RED, c, render, render_summary, setup_output

PASSWORD_ENV = "PHISHGUARD_PASSWORD"

# Valeurs par défaut des options communes. Celles-ci utilisent argparse.SUPPRESS
# pour rester acceptées aussi bien avant qu'après la sous-commande, sans que la
# seconde position n'écrase la première.
COMMON_DEFAULTS = {"json": None, "min_score": 0, "verbose": False, "no_color": False}


def build_common() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", metavar="FICHIER", nargs="?", const="-",
                        default=argparse.SUPPRESS,
                        help="Écrit le résultat en JSON (« - » pour la sortie standard).")
    common.add_argument("--min-score", type=int, metavar="N", default=argparse.SUPPRESS,
                        help="N'affiche que les messages dont le score atteint N.")
    common.add_argument("--verbose", "-v", action="store_true", default=argparse.SUPPRESS,
                        help="Affiche aussi les éléments rassurants et le détail technique.")
    common.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="Désactive la couleur.")
    return common


def build_parser() -> argparse.ArgumentParser:
    common = build_common()
    parser = argparse.ArgumentParser(
        prog="phishguard",
        parents=[common],
        description="Analyse des mails reçus et estime la probabilité de phishing.",
        epilog="Exemple : phishguard scan --user moi@exemple.fr --since 7 --limit 50",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", parents=[common],
                          help="Analyse les messages d'une boîte IMAP (lecture seule).")
    scan.add_argument("--user", "-u", required=True, help="Adresse / identifiant IMAP.")
    scan.add_argument("--host", help="Serveur IMAP (déduit du domaine si omis).")
    scan.add_argument("--port", type=int, default=993, help="Port IMAP (993 par défaut).")
    scan.add_argument("--no-ssl", action="store_true",
                      help="Connexion en clair puis STARTTLS (port 143).")
    scan.add_argument("--folder", "-f", default="INBOX", help="Dossier à analyser.")
    scan.add_argument("--limit", "-n", type=int, default=25,
                      help="Nombre de messages les plus récents à analyser (25 par défaut).")
    scan.add_argument("--unseen", action="store_true", help="Seulement les messages non lus.")
    scan.add_argument("--since", type=int, metavar="JOURS",
                      help="Seulement les messages reçus depuis N jours.")
    scan.add_argument("--from", dest="sender", help="Filtre sur l'expéditeur.")
    scan.add_argument("--query", help="Critères IMAP bruts supplémentaires.")

    files = sub.add_parser("file", parents=[common],
                           help="Analyse des fichiers .eml locaux.")
    files.add_argument("paths", nargs="+", help="Fichiers ou motifs (.eml, .msg brut).")

    folders = sub.add_parser("folders", parents=[common],
                             help="Liste les dossiers de la boîte IMAP.")
    folders.add_argument("--user", "-u", required=True)
    folders.add_argument("--host")
    folders.add_argument("--port", type=int, default=993)
    folders.add_argument("--no-ssl", action="store_true")

    return parser


def resolve_server(args) -> tuple[str, int]:
    if args.host:
        return args.host, args.port
    guessed = guess_server(args.user)
    if not guessed:
        raise SystemExit(
            f"Serveur IMAP inconnu pour {args.user}. Précisez-le avec --host.")
    host, port = guessed
    return host, args.port if args.port != 993 else port


def get_password(user: str) -> str:
    password = os.environ.get(PASSWORD_ENV)
    if password:
        return password
    print(c(f"Astuce : définissez {PASSWORD_ENV} pour éviter cette invite. "
            "Gmail/Outlook/Yahoo exigent un mot de passe d'application.", GREY))
    return getpass.getpass(f"Mot de passe IMAP pour {user} : ")


def cmd_scan(args) -> list[Analysis]:
    host, port = resolve_server(args)
    password = get_password(args.user)
    criteria = build_criteria(unseen=args.unseen, since_days=args.since,
                              sender=args.sender, extra=args.query)

    print(c(f"Connexion à {host}:{port} — dossier {args.folder} — "
            f"critères {' '.join(criteria)}", GREY))

    analyses: list[Analysis] = []
    with ImapSession(host, port, use_ssl=not args.no_ssl) as session:
        session.login(args.user, password)
        for message in session.fetch(args.folder, criteria, limit=args.limit):
            parsed = parse_message(message.raw, source=f"IMAP {message.folder}",
                                   uid=message.uid)
            analyses.append(analyze(parsed))
    return analyses


def cmd_folders(args) -> None:
    host, port = resolve_server(args)
    password = get_password(args.user)
    with ImapSession(host, port, use_ssl=not args.no_ssl) as session:
        session.login(args.user, password)
        for name in session.folders():
            print(f"  {name}")


def cmd_file(args) -> list[Analysis]:
    paths: list[Path] = []
    for pattern in args.paths:
        expanded = [Path(p) for p in glob.glob(pattern)] or [Path(pattern)]
        for path in expanded:
            if path.is_dir():
                paths.extend(sorted(path.rglob("*.eml")))
            else:
                paths.append(path)

    analyses: list[Analysis] = []
    for path in paths:
        if not path.is_file():
            print(c(f"Fichier introuvable : {path}", RED), file=sys.stderr)
            continue
        parsed = parse_message(path.read_bytes(), source=str(path))
        analyses.append(analyze(parsed))
    return analyses


def emit(analyses: list[Analysis], args) -> int:
    shown = [a for a in analyses if a.score >= args.min_score]

    if args.json:
        payload = json.dumps([a.to_dict() for a in shown], ensure_ascii=False, indent=2)
        if args.json == "-":
            print(payload)
        else:
            Path(args.json).write_text(payload, encoding="utf-8")
            print(c(f"Rapport JSON écrit dans {args.json}", GREY))
    else:
        for analysis in sorted(shown, key=lambda a: -a.score):
            print(render(analysis, verbose=args.verbose))
        print()
        print(render_summary(analyses))

    worst = max((a.score for a in analyses), default=0)
    return 1 if worst >= 45 else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for key, value in COMMON_DEFAULTS.items():
        if not hasattr(args, key):
            setattr(args, key, value)
    setup_output(args.no_color)

    try:
        if args.command == "folders":
            cmd_folders(args)
            return 0
        analyses = cmd_scan(args) if args.command == "scan" else cmd_file(args)
    except ImapError as exc:
        print(c(str(exc), RED), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(c("\nInterrompu.", GREY), file=sys.stderr)
        return 130

    if not analyses:
        print(c("Aucun message ne correspond aux critères.", GREY))
        return 0

    return emit(analyses, args)


if __name__ == "__main__":
    raise SystemExit(main())
