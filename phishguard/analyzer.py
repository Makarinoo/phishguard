"""Exécution du moteur de règles et calcul du score final."""

from __future__ import annotations

from dataclasses import dataclass, field

from .data import FREEMAIL_DOMAINS
from .parser import ParsedEmail
from .rules import Signal, all_rules
from .rules.headers import dmarc_aligned_pass

# Seuils de verdict, appliqués au score final borné à [0, 100].
VERDICTS = (
    (70, "PHISHING", "Ne pas cliquer, ne pas répondre. Signaler puis supprimer."),
    (45, "TRÈS SUSPECT", "Traiter comme malveillant tant qu'un contact direct n'a pas confirmé."),
    (22, "SUSPECT", "Vérifier l'expéditeur par un autre canal avant toute action."),
    (0, "PROBABLEMENT LÉGITIME", "Aucun indice fort relevé, rester attentif au contexte."),
)


@dataclass
class Analysis:
    email: ParsedEmail
    signals: list[Signal] = field(default_factory=list)
    score: int = 0
    verdict: str = ""
    advice: str = ""
    dampened: bool = False

    @property
    def risky_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.weight > 0]

    @property
    def reassuring_signals(self) -> list[Signal]:
        return [s for s in self.signals if s.weight <= 0]

    def to_dict(self) -> dict:
        return {
            "source": self.email.source,
            "uid": self.email.uid,
            "date": self.email.date,
            "from": self.email.from_addr,
            "from_name": self.email.from_name,
            "subject": self.email.subject,
            "score": self.score,
            "verdict": self.verdict,
            "advice": self.advice,
            "dmarc_aligned": self.dampened,
            "attachments": [a.filename for a in self.email.attachments],
            "link_domains": sorted({l.domain for l in self.email.links if l.domain}),
            "signals": [
                {
                    "id": s.id,
                    "category": s.category,
                    "title": s.title,
                    "detail": s.detail,
                    "weight": s.weight,
                    "severity": s.severity,
                }
                for s in self.signals
            ],
        }


def analyze(parsed: ParsedEmail) -> Analysis:
    """Applique toutes les règles à un message et en déduit un score 0-100."""
    signals: list[Signal] = []
    for rule_func in all_rules():
        try:
            signals.extend(rule_func(parsed) or [])
        except Exception as exc:  # une règle défaillante ne doit pas tuer l'analyse
            signals.append(Signal(
                id=f"error.{rule_func.__name__}",
                category="moteur",
                title="Règle en erreur",
                detail=f"{rule_func.__name__} : {exc}",
                weight=0,
                dampenable=False,
            ))

    # Un DMARC aligné sur une messagerie gratuite n'authentifie que le compte,
    # pas l'organisation dont le message se réclame : pas d'atténuation.
    aligned = dmarc_aligned_pass(parsed) and parsed.from_registrable not in FREEMAIL_DOMAINS
    if aligned:
        # Un DMARC valide et aligné prouve que le domaine From n'est pas usurpé :
        # les indices d'usurpation perdent la moitié de leur poids.
        signals = [
            s if not s.dampenable or s.weight <= 0
            else Signal(s.id, s.category, s.title, s.detail, round(s.weight / 2), s.dampenable)
            for s in signals
        ]

    signals.sort(key=lambda s: (-s.weight, s.category, s.id))
    raw = sum(s.weight for s in signals)
    score = max(0, min(100, raw))

    verdict, advice = next((v, a) for threshold, v, a in VERDICTS if score >= threshold)

    return Analysis(
        email=parsed,
        signals=signals,
        score=score,
        verdict=verdict,
        advice=advice,
        dampened=aligned,
    )
