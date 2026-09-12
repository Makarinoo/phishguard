"""Moteur de règles PhishGuard.

L'import de ce package enregistre toutes les règles dans le registre de `base`.
"""

from . import attachments, content, headers, links  # noqa: F401  (effet de bord : enregistrement)
from .base import (  # noqa: F401
    ATTACHMENTS,
    AUTH,
    CONTENT,
    LINKS,
    SENDER,
    Signal,
    all_rules,
)

__all__ = ["Signal", "all_rules", "AUTH", "SENDER", "LINKS", "CONTENT", "ATTACHMENTS"]
