"""Socle du moteur de règles : signaux, catégories et registre."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

from ..parser import ParsedEmail

AUTH = "authentification"
SENDER = "expéditeur"
LINKS = "liens"
CONTENT = "contenu"
ATTACHMENTS = "pièces jointes"


@dataclass(frozen=True)
class Signal:
    """Un indice relevé sur un message.

    `weight` est positif pour un indice à charge, négatif pour un indice
    rassurant (authentification alignée, message sans lien ni pièce jointe).
    """

    id: str
    category: str
    title: str
    detail: str
    weight: int
    dampenable: bool = True  # atténué de moitié si DMARC passe et est aligné

    @property
    def severity(self) -> str:
        if self.weight <= 0:
            return "ok"
        if self.weight >= 25:
            return "haute"
        if self.weight >= 12:
            return "moyenne"
        return "basse"


RuleFunc = Callable[[ParsedEmail], Iterable[Signal]]
_REGISTRY: list[RuleFunc] = []


def rule(func: RuleFunc) -> RuleFunc:
    """Enregistre une fonction de règle dans le moteur."""
    _REGISTRY.append(func)
    return func


def all_rules() -> list[RuleFunc]:
    return list(_REGISTRY)


def find_terms(haystack: str, terms: Iterable[str]) -> list[str]:
    """Termes présents dans `haystack` (déjà en minuscules), sans doublon."""
    found = []
    for term in terms:
        if term in haystack and term not in found:
            found.append(term)
    return found
