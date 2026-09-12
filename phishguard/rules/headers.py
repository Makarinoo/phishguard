"""Règles sur les en-têtes : authentification, alignement, usurpation d'expéditeur."""

from __future__ import annotations

import re

from ..data import BRANDS, FREEMAIL_DOMAINS, RISKY_TLDS
from ..parser import ParsedEmail
from ..util import (
    confusable_normalize,
    domain_of_address,
    has_mixed_scripts,
    has_punycode,
    levenshtein,
    public_suffix,
    registrable_domain,
    truncate,
)
from .base import AUTH, SENDER, Signal, rule

_EMAIL_IN_NAME_RE = re.compile(r"[\w.+-]+@[\w.-]+\.\w{2,}")


def auth_verdicts(parsed: ParsedEmail) -> dict[str, str]:
    """Extrait les verdicts spf / dkim / dmarc des en-têtes d'authentification."""
    blob = f"{parsed.auth_results} {parsed.received_spf}".lower()
    verdicts: dict[str, str] = {}
    for mech in ("spf", "dkim", "dmarc", "compauth"):
        # On garde le verdict le plus défavorable si le mécanisme apparaît
        # plusieurs fois (relais successifs).
        found = re.findall(rf"\b{mech}\s*=\s*([a-z]+)", blob)
        if found:
            ranking = ["fail", "softfail", "permerror", "temperror", "policy",
                       "neutral", "none", "bestguesspass", "pass"]
            found.sort(key=lambda v: ranking.index(v) if v in ranking else 99)
            verdicts[mech] = found[0]
    if "spf" not in verdicts and parsed.received_spf:
        first_word = parsed.received_spf.strip().split(" ", 1)[0].lower()
        if first_word in {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}:
            verdicts["spf"] = first_word
    return verdicts


def dmarc_aligned_pass(parsed: ParsedEmail) -> bool:
    """DMARC en `pass` et portant bien sur le domaine du champ From."""
    verdicts = auth_verdicts(parsed)
    if verdicts.get("dmarc") != "pass":
        return False
    match = re.search(r"header\.from\s*=\s*([\w.-]+)", parsed.auth_results.lower())
    if match:
        return registrable_domain(match.group(1)) == parsed.from_registrable
    return True


@rule
def check_authentication(parsed: ParsedEmail):
    verdicts = auth_verdicts(parsed)
    if not verdicts:
        yield Signal(
            id="auth.missing",
            category=AUTH,
            title="Aucun résultat d'authentification",
            detail="Ni Authentication-Results ni Received-SPF : impossible de "
                   "vérifier que l'expéditeur est autorisé à utiliser ce domaine.",
            weight=6,
            dampenable=False,
        )
        return

    spf = verdicts.get("spf")
    if spf == "fail":
        yield Signal("auth.spf_fail", AUTH, "SPF en échec",
                     f"Le serveur émetteur n'est pas autorisé par le SPF de "
                     f"{parsed.from_domain or 'l’expéditeur'}.", 22, dampenable=False)
    elif spf in {"softfail", "neutral"}:
        yield Signal("auth.spf_soft", AUTH, f"SPF {spf}",
                     "Le SPF ne valide pas franchement le serveur émetteur.", 9,
                     dampenable=False)
    elif spf in {"none", "permerror", "temperror"}:
        yield Signal("auth.spf_none", AUTH, f"SPF {spf}",
                     "Le domaine expéditeur ne publie pas de SPF exploitable.", 6,
                     dampenable=False)

    dkim = verdicts.get("dkim")
    if dkim == "fail":
        yield Signal("auth.dkim_fail", AUTH, "Signature DKIM invalide",
                     "La signature est absente ou altérée : le message a pu être "
                     "forgé ou modifié en transit.", 20, dampenable=False)
    elif dkim in {"none", "neutral"}:
        yield Signal("auth.dkim_none", AUTH, "Pas de signature DKIM",
                     "Aucune signature cryptographique de l'expéditeur.", 6,
                     dampenable=False)

    dmarc = verdicts.get("dmarc")
    if dmarc == "fail":
        yield Signal("auth.dmarc_fail", AUTH, "DMARC en échec",
                     f"Le domaine {parsed.from_domain} rejette ce type d'envoi : "
                     "usurpation d'expéditeur très probable.", 30, dampenable=False)
    elif dmarc == "pass" and dmarc_aligned_pass(parsed):
        if parsed.from_registrable in FREEMAIL_DOMAINS:
            # Prouve seulement que le compte gratuit existe : n'importe qui peut
            # en ouvrir un et passer DMARC.
            yield Signal("auth.dmarc_pass_freemail", AUTH,
                         "DMARC valide (messagerie gratuite)",
                         f"L'envoi vient bien d'un compte {parsed.from_registrable}, "
                         "ce qui ne dit rien de la légitimité de l'expéditeur.",
                         -8, dampenable=False)
        else:
            yield Signal("auth.dmarc_pass", AUTH, "DMARC valide et aligné",
                         f"L'envoi est bien autorisé par {parsed.from_registrable}.",
                         -25, dampenable=False)

    if verdicts.get("compauth") == "fail":
        yield Signal("auth.compauth_fail", AUTH, "Authentification composite en échec",
                     "Microsoft 365 considère l'expéditeur comme usurpé.", 18,
                     dampenable=False)


@rule
def check_return_path(parsed: ParsedEmail):
    if not parsed.return_path or not parsed.from_domain:
        return
    rp_domain = parsed.return_path_domain
    if registrable_domain(rp_domain) == parsed.from_registrable:
        return
    # Les routeurs légitimes (Mailchimp, Sendgrid…) désalignent aussi le
    # Return-Path ; le signal reste modéré et s'efface si DMARC passe.
    yield Signal(
        "sender.return_path_mismatch", SENDER,
        "Return-Path différent du From",
        f"Enveloppe : {parsed.return_path} — affiché : {parsed.from_addr}. "
        "Les réponses techniques partent vers un autre domaine.",
        11,
    )


@rule
def check_reply_to(parsed: ParsedEmail):
    if not parsed.reply_to or not parsed.from_domain:
        return
    for addr in parsed.reply_to:
        rt_domain = domain_of_address(addr)
        if registrable_domain(rt_domain) == parsed.from_registrable:
            continue
        weight = 18
        extra = ""
        if rt_domain in FREEMAIL_DOMAINS and parsed.from_registrable not in FREEMAIL_DOMAINS:
            weight = 26
            extra = " Il s'agit d'une messagerie gratuite : typique d'une arnaque au président ou à la facture."
        yield Signal(
            "sender.reply_to_mismatch", SENDER,
            "Reply-To vers un autre domaine",
            f"Une réponse partirait vers {addr}, pas vers {parsed.from_addr}.{extra}",
            weight,
        )
        break


@rule
def check_display_name(parsed: ParsedEmail):
    name = parsed.from_name.strip()
    if not name:
        return

    embedded = _EMAIL_IN_NAME_RE.search(name)
    if embedded and embedded.group(0).lower() != parsed.from_addr:
        yield Signal(
            "sender.name_contains_other_address", SENDER,
            "Le nom affiché contient une autre adresse",
            f"Affiché « {truncate(name, 60)} » mais l'adresse réelle est "
            f"{parsed.from_addr}. Technique classique pour tromper l'aperçu mobile.",
            24,
        )

    if has_mixed_scripts(name):
        yield Signal(
            "sender.name_mixed_scripts", SENDER,
            "Alphabets mélangés dans le nom affiché",
            f"« {truncate(name, 60)} » mélange plusieurs alphabets (latin/cyrillique) "
            "pour imiter visuellement un nom légitime.",
            20,
        )


@rule
def check_brand_impersonation(parsed: ParsedEmail):
    """Marque citée dans le nom affiché ou l'objet, mais domaine étranger à la marque."""
    if not parsed.from_registrable:
        return
    haystack = f"{parsed.from_name} {parsed.subject}".lower()
    haystack_norm = confusable_normalize(haystack)
    for brand, legit_domains in BRANDS.items():
        brand_norm = confusable_normalize(brand)
        if brand_norm not in haystack_norm:
            continue
        if any(parsed.from_registrable == d or parsed.from_domain.endswith("." + d)
               for d in legit_domains):
            return  # expéditeur légitime de la marque
        if parsed.from_registrable in FREEMAIL_DOMAINS:
            weight = 30
            detail = (f"Le message se présente au nom de « {brand} » mais part d'une "
                      f"messagerie gratuite ({parsed.from_registrable}).")
        else:
            weight = 22
            detail = (f"Le message se présente au nom de « {brand} » alors que le domaine "
                      f"expéditeur est {parsed.from_registrable}, qui n'appartient pas à "
                      "cette marque.")
        yield Signal("sender.brand_impersonation", SENDER,
                     f"Usurpation possible de « {brand} »", detail, weight)
        return


@rule
def check_lookalike_domain(parsed: ParsedEmail):
    """Domaine expéditeur proche d'un domaine de marque connu (typosquatting)."""
    domain = parsed.from_registrable
    if not domain or "." not in domain:
        return
    label = domain.split(".")[0]
    label_norm = confusable_normalize(label)
    if len(label_norm) < 4:
        return

    for brand, legit_domains in BRANDS.items():
        if domain in legit_domains:
            return
        for legit in legit_domains:
            legit_label = confusable_normalize(legit.split(".")[0])
            if len(legit_label) < 4:
                continue
            if label_norm == legit_label and domain not in legit_domains:
                yield Signal(
                    "sender.lookalike_exact", SENDER,
                    "Domaine sosie d'une marque",
                    f"{domain} se lit comme {legit} après normalisation des "
                    "caractères trompeurs (0/o, 1/l, rn/m…).",
                    30,
                )
                return
            distance = levenshtein(label_norm, legit_label, max_distance=2)
            if 0 < distance <= 1 and len(legit_label) >= 6:
                yield Signal(
                    "sender.lookalike_typo", SENDER,
                    "Domaine très proche d'une marque",
                    f"{domain} ne diffère que d'un caractère de {legit}.",
                    28,
                )
                return
            # marque insérée dans un domaine tiers : paypal-securite.xyz
            if legit_label in label_norm and label_norm != legit_label and len(legit_label) >= 5:
                yield Signal(
                    "sender.brand_in_domain", SENDER,
                    "Nom de marque inséré dans un autre domaine",
                    f"« {legit_label} » apparaît dans {domain}, qui n'appartient "
                    f"pas à {brand}.",
                    26,
                )
                return


@rule
def check_sender_domain_shape(parsed: ParsedEmail):
    domain = parsed.from_domain
    if not domain:
        yield Signal("sender.no_from", SENDER, "Expéditeur absent ou illisible",
                     "Le champ From ne contient pas d'adresse exploitable.", 20,
                     dampenable=False)
        return

    if has_punycode(domain):
        yield Signal("sender.punycode", SENDER, "Domaine expéditeur en punycode",
                     f"{domain} utilise un encodage IDN qui peut imiter un nom latin.",
                     22)

    tld = public_suffix(domain).rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        yield Signal("sender.risky_tld", SENDER, f"Extension .{tld} à fort taux d'abus",
                     f"Le domaine {registrable_domain(domain)} utilise une extension "
                     "rarement employée par les entreprises légitimes.", 12)

    if len(registrable_domain(domain).split(".")[0]) > 25:
        yield Signal("sender.long_domain", SENDER, "Domaine anormalement long",
                     f"{registrable_domain(domain)} : longueur typique d'un domaine "
                     "jetable généré automatiquement.", 8)


@rule
def check_message_id(parsed: ParsedEmail):
    if not parsed.message_id or "@" not in parsed.message_id or not parsed.from_domain:
        if not parsed.message_id:
            yield Signal("sender.no_message_id", SENDER, "Message-ID absent",
                         "Les clients de messagerie légitimes en génèrent toujours un.",
                         10)
        return
    mid_domain = parsed.message_id.rsplit("@", 1)[1].lower().strip(">")
    if not mid_domain or registrable_domain(mid_domain) == parsed.from_registrable:
        return
    yield Signal(
        "sender.message_id_mismatch", SENDER,
        "Message-ID d'un autre domaine",
        f"Généré par {registrable_domain(mid_domain)} alors que l'expéditeur "
        f"annoncé est {parsed.from_registrable}.",
        7,
    )
