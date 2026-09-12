"""PhishGuard — détection heuristique de phishing dans les mails reçus."""

from .analyzer import Analysis, analyze
from .parser import ParsedEmail, parse_message

__version__ = "1.0.0"
__all__ = ["Analysis", "analyze", "ParsedEmail", "parse_message", "__version__"]
