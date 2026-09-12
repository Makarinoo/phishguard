"""Récupération des messages par IMAP, en lecture seule."""

from __future__ import annotations

import imaplib
import re
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator

# La boîte est ouverte en lecture seule : aucun message n'est marqué comme lu,
# déplacé ni supprimé par l'outil.
READ_ONLY = True

imaplib._MAXLINE = 10_000_000  # certains messages dépassent la limite par défaut

# Serveurs IMAP courants, déduits du domaine de l'adresse.
KNOWN_SERVERS = {
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),
    "outlook.com": ("outlook.office365.com", 993),
    "outlook.fr": ("outlook.office365.com", 993),
    "hotmail.com": ("outlook.office365.com", 993),
    "hotmail.fr": ("outlook.office365.com", 993),
    "live.com": ("outlook.office365.com", 993),
    "live.fr": ("outlook.office365.com", 993),
    "msn.com": ("outlook.office365.com", 993),
    "yahoo.com": ("imap.mail.yahoo.com", 993),
    "yahoo.fr": ("imap.mail.yahoo.com", 993),
    "icloud.com": ("imap.mail.me.com", 993),
    "me.com": ("imap.mail.me.com", 993),
    "free.fr": ("imap.free.fr", 993),
    "orange.fr": ("imap.orange.fr", 993),
    "wanadoo.fr": ("imap.orange.fr", 993),
    "sfr.fr": ("imap.sfr.fr", 993),
    "neuf.fr": ("imap.sfr.fr", 993),
    "laposte.net": ("imap.laposte.net", 993),
    "gmx.com": ("imap.gmx.com", 993),
    "gmx.fr": ("imap.gmx.net", 993),
    "proton.me": ("127.0.0.1", 1143),  # via ProtonMail Bridge
    "protonmail.com": ("127.0.0.1", 1143),
    "zoho.com": ("imap.zoho.com", 993),
    "yandex.com": ("imap.yandex.com", 993),
}


class ImapError(RuntimeError):
    pass


@dataclass
class FetchedMessage:
    uid: str
    raw: bytes
    folder: str


def guess_server(address: str) -> tuple[str, int] | None:
    domain = address.rsplit("@", 1)[-1].lower() if "@" in address else ""
    return KNOWN_SERVERS.get(domain)


def _imap_date(days_ago: int) -> str:
    day = datetime.now() - timedelta(days=days_ago)
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    return f"{day.day:02d}-{months[day.month - 1]}-{day.year}"


def build_criteria(*, unseen: bool = False, since_days: int | None = None,
                   sender: str | None = None, extra: str | None = None) -> list[str]:
    criteria: list[str] = []
    if unseen:
        criteria.append("UNSEEN")
    if since_days:
        criteria += ["SINCE", _imap_date(since_days)]
    if sender:
        criteria += ["FROM", sender]
    if extra:
        criteria += extra.split()
    return criteria or ["ALL"]


class ImapSession:
    """Connexion IMAP en lecture seule, utilisable comme gestionnaire de contexte."""

    def __init__(self, host: str, port: int = 993, *, use_ssl: bool = True,
                 timeout: int = 30) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.conn: imaplib.IMAP4 | None = None

    def __enter__(self) -> "ImapSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                self.conn = imaplib.IMAP4_SSL(self.host, self.port,
                                              ssl_context=context, timeout=self.timeout)
            else:
                self.conn = imaplib.IMAP4(self.host, self.port, timeout=self.timeout)
                self.conn.starttls(ssl.create_default_context())
        except (OSError, socket.error, ssl.SSLError) as exc:
            raise ImapError(f"Connexion à {self.host}:{self.port} impossible : {exc}") from exc

    def login(self, user: str, password: str) -> None:
        if self.conn is None:
            self.connect()
        try:
            self.conn.login(user, password)
        except imaplib.IMAP4.error as exc:
            message = str(exc)
            hint = ""
            if "application-specific" in message.lower() or "invalid credentials" in message.lower():
                hint = ("\nGmail, Outlook et Yahoo refusent le mot de passe habituel : "
                        "créez un « mot de passe d'application » dans les paramètres de "
                        "sécurité du compte.")
            raise ImapError(f"Authentification refusée : {message}{hint}") from exc

    def folders(self) -> list[str]:
        status, data = self.conn.list()
        if status != "OK":
            return []
        names = []
        for raw in data:
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace")
            match = re.search(r'"?([^"]+)"?$', line.strip())
            if match:
                names.append(match.group(1).strip('"'))
        return names

    def fetch(self, folder: str, criteria: list[str], limit: int = 25) -> Iterator[FetchedMessage]:
        status, _ = self.conn.select(f'"{folder}"', readonly=READ_ONLY)
        if status != "OK":
            raise ImapError(f"Dossier introuvable : {folder}")

        status, data = self.conn.uid("SEARCH", None, *criteria)
        if status != "OK":
            raise ImapError(f"Recherche IMAP refusée ({' '.join(criteria)})")

        uids = (data[0] or b"").split()
        uids = uids[-limit:] if limit else uids  # les plus récents

        for uid in reversed(uids):
            status, payload = self.conn.uid("FETCH", uid, "(BODY.PEEK[])")
            if status != "OK" or not payload or not isinstance(payload[0], tuple):
                continue
            yield FetchedMessage(uid=uid.decode(), raw=payload[0][1], folder=folder)

    def close(self) -> None:
        if self.conn is None:
            return
        try:
            self.conn.close()
        except Exception:
            pass
        try:
            self.conn.logout()
        except Exception:
            pass
        self.conn = None
