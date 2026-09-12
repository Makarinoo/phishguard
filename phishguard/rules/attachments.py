"""Règles sur les pièces jointes."""

from __future__ import annotations

from ..data import (
    ARCHIVE_EXTENSIONS,
    CONTAINER_EXTENSIONS,
    DECOY_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    MACRO_EXTENSIONS,
)
from ..parser import ParsedEmail
from ..util import truncate
from .base import ATTACHMENTS, Signal, rule

_RTL_OVERRIDE = "‮"


def _names(items) -> str:
    return ", ".join(truncate(n, 45) for n in items[:4])


@rule
def check_attachment_types(parsed: ParsedEmail):
    if not parsed.attachments:
        return

    executables, containers, macros, html_files, archives, doubles, rtl = [], [], [], [], [], [], []

    for att in parsed.attachments:
        exts = att.extensions
        ext = att.extension
        if _RTL_OVERRIDE in att.filename:
            rtl.append(att.filename.replace(_RTL_OVERRIDE, "[RLO]"))
        if ext in EXECUTABLE_EXTENSIONS:
            executables.append(att.filename)
        elif ext in CONTAINER_EXTENSIONS:
            containers.append(att.filename)
        elif ext in MACRO_EXTENSIONS:
            macros.append(att.filename)
        elif ext in {"html", "htm", "shtml", "xhtml"}:
            html_files.append(att.filename)
        elif ext in ARCHIVE_EXTENSIONS:
            archives.append(att.filename)
        if len(exts) >= 2 and exts[-2] in DECOY_EXTENSIONS and ext not in DECOY_EXTENSIONS:
            doubles.append(att.filename)

    if executables:
        yield Signal("att.executable", ATTACHMENTS, "Pièce jointe exécutable",
                     f"Ouvrir ce fichier exécute du code : {_names(executables)}", 42,
                     dampenable=False)
    if doubles:
        yield Signal("att.double_extension", ATTACHMENTS, "Double extension trompeuse",
                     f"Le fichier se fait passer pour un document : {_names(doubles)}", 36,
                     dampenable=False)
    if rtl:
        yield Signal("att.rtl_override", ATTACHMENTS, "Nom de fichier retourné (RLO)",
                     f"Un caractère d'inversion cache la vraie extension : {_names(rtl)}", 40,
                     dampenable=False)
    if containers:
        yield Signal("att.container", ATTACHMENTS, "Conteneur disque (ISO/IMG)",
                     f"Format utilisé pour contourner les protections Windows : "
                     f"{_names(containers)}", 34, dampenable=False)
    if macros:
        yield Signal("att.macro_office", ATTACHMENTS, "Document Office à macros",
                     f"Format pouvant embarquer du code : {_names(macros)}", 24)
    if html_files:
        yield Signal("att.html_file", ATTACHMENTS, "Pièce jointe HTML",
                     f"Page de phishing embarquée, elle s'ouvre hors ligne dans le "
                     f"navigateur : {_names(html_files)}", 30)
    if archives:
        body = parsed.searchable
        if any(term in body for term in ("mot de passe", "password", "code d'accès", "passcode")):
            yield Signal("att.encrypted_archive", ATTACHMENTS,
                         "Archive protégée par mot de passe",
                         f"Le mot de passe fourni dans le corps rend l'analyse antivirus "
                         f"impossible : {_names(archives)}", 28, dampenable=False)
        else:
            yield Signal("att.archive", ATTACHMENTS, "Archive compressée",
                         f"Contenu non analysable sans extraction : {_names(archives)}", 10)


@rule
def check_attachment_context(parsed: ParsedEmail):
    if not parsed.attachments:
        return
    if len(parsed.attachments) > 5:
        yield Signal("att.many", ATTACHMENTS, "Nombre inhabituel de pièces jointes",
                     f"{len(parsed.attachments)} fichiers joints.", 6)
    unnamed = [a for a in parsed.attachments if a.filename == "(sans nom)"]
    if unnamed:
        yield Signal("att.unnamed", ATTACHMENTS, "Pièce jointe sans nom",
                     f"{len(unnamed)} fichier(s) sans nom déclaré.", 8)
