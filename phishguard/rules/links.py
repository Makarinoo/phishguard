"""Règles sur les URL contenues dans le message."""

from __future__ import annotations

import re

from ..data import (
    BRANDS,
    CREDENTIAL_PATH_TOKENS,
    FREE_HOSTING,
    RISKY_TLDS,
    URL_SHORTENERS,
)
from ..parser import Link, ParsedEmail
from ..util import (
    confusable_normalize,
    has_mixed_scripts,
    has_punycode,
    is_ip_literal,
    levenshtein,
    public_suffix,
    registrable_domain,
    truncate,
)
from .base import LINKS, Signal, rule

_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.IGNORECASE
)


def clickable_links(parsed: ParsedEmail) -> list[Link]:
    """Liens sur lesquels un utilisateur peut réellement cliquer."""
    return [l for l in parsed.links if l.source in {"html", "text", "form"}]


def _sample(values, limit: int = 3) -> str:
    values = list(dict.fromkeys(values))
    shown = ", ".join(truncate(v, 70) for v in values[:limit])
    if len(values) > limit:
        shown += f" (+{len(values) - limit} autre(s))"
    return shown


@rule
def check_link_hosts(parsed: ParsedEmail):
    links = clickable_links(parsed)
    if not links:
        return

    ip_links, punycode_hosts, userinfo_links = [], [], []
    shorteners, free_hosts, risky = [], [], []

    for link in links:
        host = link.host
        if not host:
            continue
        if is_ip_literal(host):
            ip_links.append(link.href)
        if has_punycode(host) or has_mixed_scripts(host):
            punycode_hosts.append(host)
        if link.userinfo:
            userinfo_links.append(link.href)

        domain = registrable_domain(host)
        if domain in URL_SHORTENERS:
            shorteners.append(domain)
        if domain in FREE_HOSTING or any(host.endswith("." + f) for f in FREE_HOSTING):
            free_hosts.append(host)
        tld = public_suffix(host).rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:
            risky.append(domain)

    if ip_links:
        yield Signal("links.ip_host", LINKS, "Lien vers une adresse IP brute",
                     f"Aucune organisation sérieuse n'envoie ce type de lien : {_sample(ip_links)}",
                     26)
    if userinfo_links:
        yield Signal("links.userinfo_trick", LINKS, "URL masquée par un « @ »",
                     f"Tout ce qui précède le @ est ignoré par le navigateur, la vraie "
                     f"destination est le domaine qui suit : {_sample(userinfo_links)}",
                     30)
    if punycode_hosts:
        yield Signal("links.punycode", LINKS, "Domaine de lien en punycode / alphabets mêlés",
                     f"Hôte encodé pour imiter un nom légitime : {_sample(punycode_hosts)}",
                     24)
    if shorteners:
        yield Signal("links.shortener", LINKS, "Raccourcisseur d'URL",
                     f"La destination réelle est masquée : {_sample(shorteners)}", 13)
    if free_hosts:
        yield Signal("links.free_hosting", LINKS, "Page hébergée sur une plateforme gratuite",
                     f"Hébergement fréquemment utilisé pour des kits de phishing : "
                     f"{_sample(free_hosts)}", 16)
    if risky:
        yield Signal("links.risky_tld", LINKS, "Lien vers une extension à fort taux d'abus",
                     f"{_sample(risky)}", 13)


@rule
def check_anchor_mismatch(parsed: ParsedEmail):
    """Le texte du lien annonce un domaine, le href pointe ailleurs."""
    mismatches = []
    for link in parsed.links:
        if link.source != "html" or not link.text.strip():
            continue
        match = _DOMAIN_IN_TEXT_RE.search(link.text.strip())
        if not match:
            continue
        displayed = registrable_domain(match.group(1))
        actual = link.domain
        if not displayed or not actual or displayed == actual:
            continue
        if "." not in displayed:
            continue
        mismatches.append(f"« {truncate(link.text, 40)} » → {actual}")

    if mismatches:
        yield Signal("links.anchor_mismatch", LINKS,
                     "Texte du lien différent de sa destination",
                     f"Le lien affiche un domaine et mène à un autre : {_sample(mismatches)}",
                     24)


@rule
def check_credential_paths(parsed: ParsedEmail):
    hits = []
    for link in clickable_links(parsed):
        path = link.path_and_query
        if not path or not link.host:
            continue
        tokens = {t for t in re.split(r"[^a-z0-9]+", path) if t}
        matched = tokens & CREDENTIAL_PATH_TOKENS
        if matched:
            hits.append(f"{link.host}{truncate(path, 40)}")
    if hits:
        yield Signal("links.credential_path", LINKS,
                     "URL orientée connexion / vérification de compte",
                     f"Chemins typiques d'une page de collecte d'identifiants : {_sample(hits)}",
                     13)


@rule
def check_dangerous_schemes(parsed: ParsedEmail):
    bad = [l.href for l in parsed.links if l.scheme in {"javascript", "data", "vbscript", "file"}]
    if bad:
        yield Signal("links.dangerous_scheme", LINKS, "Lien à schéma dangereux",
                     f"URI javascript:/data: utilisée pour exécuter du code ou ouvrir "
                     f"une fausse page locale : {_sample(bad)}", 28)


@rule
def check_link_brand_mismatch(parsed: ParsedEmail):
    """Une marque est citée dans le message, mais aucun lien ne mène chez elle."""
    links = clickable_links(parsed)
    if not links:
        return
    haystack = confusable_normalize(f"{parsed.subject} {parsed.from_name} {parsed.body[:4000]}")
    link_domains = {l.domain for l in links if l.domain}
    if not link_domains:
        return

    for brand, legit_domains in BRANDS.items():
        if confusable_normalize(brand) not in haystack:
            continue
        if any(d in legit_domains or any(d.endswith("." + g) for g in legit_domains)
               for d in link_domains):
            return  # au moins un lien va bien chez la marque
        # sosie parmi les domaines de liens ?
        for domain in link_domains:
            label = confusable_normalize(domain.split(".")[0])
            for legit in legit_domains:
                legit_label = confusable_normalize(legit.split(".")[0])
                if len(legit_label) < 5:
                    continue
                if legit_label in label and label != legit_label:
                    yield Signal("links.brand_lookalike", LINKS,
                                 f"Lien sosie de « {brand} »",
                                 f"{domain} imite {legit} sans lui appartenir.", 30)
                    return
                if levenshtein(label, legit_label, max_distance=2) == 1:
                    yield Signal("links.brand_lookalike", LINKS,
                                 f"Lien sosie de « {brand} »",
                                 f"{domain} ne diffère que d'un caractère de {legit}.", 30)
                    return
        yield Signal("links.brand_no_official_link", LINKS,
                     f"« {brand} » cité mais aucun lien officiel",
                     f"Le message parle de {brand} et renvoie vers : "
                     f"{_sample(sorted(link_domains))}", 18)
        return


@rule
def check_link_spread(parsed: ParsedEmail):
    links = clickable_links(parsed)
    if not links:
        return
    domains = {l.domain for l in links if l.domain}
    if parsed.from_registrable and domains and parsed.from_registrable not in domains:
        yield Signal("links.off_domain", LINKS,
                     "Aucun lien vers le domaine de l'expéditeur",
                     f"Expéditeur {parsed.from_registrable}, liens vers "
                     f"{_sample(sorted(domains))}.", 7)
    if len(domains) >= 6:
        yield Signal("links.many_domains", LINKS, "Grand nombre de domaines distincts",
                     f"{len(domains)} domaines différents dans un seul message.", 6)


@rule
def check_html_form(parsed: ParsedEmail):
    if parsed.has_html_form:
        yield Signal("links.html_form", LINKS, "Formulaire intégré au message",
                     "Le corps HTML contient un formulaire : saisie d'identifiants "
                     "directement dans le mail, pratique quasi exclusivement malveillante.",
                     28)
