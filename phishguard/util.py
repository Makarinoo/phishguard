"""Petits utilitaires sans dépendance externe : domaines, distances, confusables."""

from __future__ import annotations

import re
import unicodedata

# Sous-ensemble de la Public Suffix List : les suffixes à deux labels les plus
# courants. Suffisant pour extraire le domaine enregistrable dans 99 % des cas
# réels, sans embarquer la PSL complète.
_TWO_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "ltd.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.tw", "com.hk",
    "com.sg", "com.my", "com.ph", "com.vn", "com.sa", "com.eg", "com.ng",
    "co.za", "org.za", "gov.za",
    "co.kr", "or.kr", "go.kr",
    "com.ru", "org.ru", "net.ru",
    "gouv.fr", "asso.fr", "com.fr", "tm.fr", "nom.fr",
    "co.il", "org.il", "gov.il",
    "com.pl", "net.pl", "org.pl", "gov.pl",
    "co.th", "in.th", "go.th",
    "com.ua", "co.id", "web.id", "or.id", "com.pk", "com.bd",
    "com.es", "com.pt", "com.it", "com.de",
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize_host(host: str) -> str:
    """Minuscules, sans point final, sans port, sans crochets IPv6."""
    if not host:
        return ""
    host = host.strip().lower().rstrip(".")
    if host.startswith("["):  # IPv6 littéral
        return host
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def is_ip_literal(host: str) -> bool:
    host = normalize_host(host)
    if host.startswith("["):
        return True
    if _IPV4_RE.match(host):
        return all(0 <= int(p) <= 255 for p in host.split("."))
    return False


def registrable_domain(host: str) -> str:
    """Renvoie le domaine enregistrable (eTLD+1) : mail.free.fr -> free.fr."""
    host = normalize_host(host)
    if not host or is_ip_literal(host):
        return host
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_LABEL_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def public_suffix(host: str) -> str:
    reg = registrable_domain(host)
    return reg.split(".", 1)[1] if "." in reg else ""


def same_registrable(a: str, b: str) -> bool:
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb


def domain_of_address(addr: str) -> str:
    """Domaine d'une adresse mail, déjà normalisé."""
    if not addr or "@" not in addr:
        return ""
    return normalize_host(addr.rsplit("@", 1)[1])


def levenshtein(a: str, b: str, max_distance: int = 4) -> int:
    """Distance d'édition, avec sortie anticipée au-delà de `max_distance`."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,        # suppression
                current[j - 1] + 1,     # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        if min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


# Substitutions visuelles classiques du typosquatting.
_CONFUSABLE_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "g",
    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a", "|": "l",
})
_CONFUSABLE_PAIRS = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))


def confusable_normalize(text: str) -> str:
    """Rend comparables `paypa1`, `payp4l`, `rnicrosoft` et `microsoft`."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower().translate(_CONFUSABLE_MAP)
    for src, dst in _CONFUSABLE_PAIRS:
        text = text.replace(src, dst)
    return re.sub(r"[^a-z0-9]", "", text)


def has_punycode(host: str) -> bool:
    return any(label.startswith("xn--") for label in normalize_host(host).split("."))


def has_mixed_scripts(text: str) -> bool:
    """Détecte un mélange latin / cyrillique / grec dans un même mot."""
    scripts = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN"):
            if name.startswith(script):
                scripts.add(script)
                break
    return len(scripts) > 1


def truncate(text: str, limit: int = 90) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
