"""Règles sur le contenu rédactionnel et la structure du corps du message."""

from __future__ import annotations

import re

from ..data import (
    CREDENTIAL_REQUEST_TERMS,
    GENERIC_GREETINGS,
    MONEY_LURE_TERMS,
    URGENCY_TERMS,
)
from ..parser import ParsedEmail, count_zero_width, html_to_text
from ..util import truncate
from .base import CONTENT, Signal, find_terms, rule


def _quote(terms: list[str], limit: int = 4) -> str:
    shown = ", ".join(f"« {t} »" for t in terms[:limit])
    if len(terms) > limit:
        shown += f" (+{len(terms) - limit})"
    return shown


@rule
def check_urgency(parsed: ParsedEmail):
    found = find_terms(parsed.searchable, URGENCY_TERMS)
    if not found:
        return
    weight = min(8 + 5 * (len(found) - 1), 22)
    yield Signal("content.urgency", CONTENT, "Pression temporelle / menace",
                 f"Le message joue sur l'urgence : {_quote(found)}.", weight)


@rule
def check_credential_request(parsed: ParsedEmail):
    found = find_terms(parsed.searchable, CREDENTIAL_REQUEST_TERMS)
    if not found:
        return
    weight = min(16 + 6 * (len(found) - 1), 30)
    yield Signal("content.credential_request", CONTENT,
                 "Demande d'identifiants ou de données sensibles",
                 f"Formulations relevées : {_quote(found)}.", weight)


@rule
def check_money_lure(parsed: ParsedEmail):
    found = find_terms(parsed.searchable, MONEY_LURE_TERMS)
    if not found:
        return
    weight = min(10 + 5 * (len(found) - 1), 22)
    yield Signal("content.money_lure", CONTENT, "Appât financier",
                 f"Remboursement, gain ou impayé mis en avant : {_quote(found)}.", weight)


@rule
def check_generic_greeting(parsed: ParsedEmail):
    found = find_terms(parsed.searchable[:1500], GENERIC_GREETINGS)
    if found:
        yield Signal("content.generic_greeting", CONTENT, "Formule d'appel impersonnelle",
                     f"{_quote(found)} : aucun élément prouvant que l'expéditeur "
                     "connaît le destinataire.", 7)


@rule
def check_hidden_text(parsed: ParsedEmail):
    zw = count_zero_width(parsed.html_body) + count_zero_width(parsed.text_body)
    if zw >= 5:
        yield Signal("content.zero_width", CONTENT, "Caractères invisibles insérés",
                     f"{zw} caractères de largeur nulle dans le corps : technique de "
                     "contournement des filtres antispam.", 18)

    if parsed.html_body:
        hidden = len(re.findall(
            r"(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|"
            r"color\s*:\s*#?f{3,6}\b[^;]*background[^;]*#?f{3,6})",
            parsed.html_body, re.IGNORECASE))
        if hidden >= 3:
            yield Signal("content.hidden_html", CONTENT, "Texte masqué dans le HTML",
                         f"{hidden} blocs rendus invisibles : du texte anodin est caché "
                         "pour diluer les mots-clés suspects.", 15)


@rule
def check_body_shape(parsed: ParsedEmail):
    visible = html_to_text(parsed.html_body).strip() or parsed.text_body.strip()
    visible_len = len(" ".join(visible.split()))

    if parsed.inline_image_count and visible_len < 200:
        yield Signal("content.image_only", CONTENT, "Message quasiment sans texte",
                     f"{parsed.inline_image_count} image(s) pour {visible_len} caractères "
                     "visibles : le contenu est dans l'image pour échapper à l'analyse.",
                     14)

    if not visible_len and not parsed.attachments:
        yield Signal("content.empty", CONTENT, "Corps de message vide", "", 8)

    if parsed.html_body and not parsed.text_body.strip():
        yield Signal("content.html_only", CONTENT, "HTML sans version texte",
                     "Les envois automatisés légitimes fournissent presque toujours "
                     "une alternative en texte brut.", 5)


@rule
def check_subject_shape(parsed: ParsedEmail):
    subject = parsed.subject.strip()
    if not subject:
        yield Signal("content.no_subject", CONTENT, "Objet vide", "", 6)
        return
    letters = [c for c in subject if c.isalpha()]
    if len(letters) >= 8 and sum(c.isupper() for c in letters) / len(letters) > 0.7:
        yield Signal("content.shouting_subject", CONTENT, "Objet tout en majuscules",
                     f"« {truncate(subject, 60)} »", 7)
    if subject.count("!") >= 2 or "‼" in subject:
        yield Signal("content.exclamations", CONTENT, "Ponctuation alarmiste dans l'objet",
                     f"« {truncate(subject, 60)} »", 5)


@rule
def check_no_payload(parsed: ParsedEmail):
    """Signal rassurant : rien sur quoi cliquer, rien à ouvrir."""
    clickable = [l for l in parsed.links if l.source in {"html", "text", "form"}]
    if not clickable and not parsed.attachments:
        yield Signal("content.no_payload", CONTENT, "Ni lien ni pièce jointe",
                     "Le message ne propose aucune action exploitable.", -12,
                     dampenable=False)
