"""Normalisation d'un message brut (RFC 822) en structure exploitable par les règles."""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

from .util import domain_of_address, normalize_host, registrable_domain

_URL_RE = re.compile(
    r"""(?xi)
    \b(
        (?:https?://|www\.)
        [^\s<>"'\)\]\},]+
    )
    """
)
_ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")


@dataclass
class Link:
    href: str
    text: str = ""
    source: str = "html"  # html | text | form | img

    @property
    def scheme(self) -> str:
        return urlsplit(self.href).scheme.lower()

    @property
    def host(self) -> str:
        try:
            netloc = urlsplit(self.href).netloc
        except ValueError:
            return ""
        if "@" in netloc:  # partie userinfo
            netloc = netloc.rsplit("@", 1)[1]
        return normalize_host(netloc)

    @property
    def userinfo(self) -> str:
        try:
            netloc = urlsplit(self.href).netloc
        except ValueError:
            return ""
        return netloc.rsplit("@", 1)[0] if "@" in netloc else ""

    @property
    def domain(self) -> str:
        return registrable_domain(self.host)

    @property
    def path_and_query(self) -> str:
        try:
            parts = urlsplit(self.href)
        except ValueError:
            return ""
        return unquote(f"{parts.path}?{parts.query}").lower()


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int

    @property
    def extensions(self) -> list[str]:
        """Toutes les extensions du nom, de gauche à droite (facture.pdf.exe)."""
        name = self.filename.strip().rstrip(". ")
        parts = [p for p in name.split(".")[1:] if p]
        return [p.lower() for p in parts if len(p) <= 12]

    @property
    def extension(self) -> str:
        exts = self.extensions
        return exts[-1] if exts else ""


@dataclass
class ParsedEmail:
    """Vue normalisée d'un message, indépendante de la source (IMAP ou fichier)."""

    source: str = ""
    uid: str = ""
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    to: list[str] = field(default_factory=list)
    return_path: str = ""
    date: str = ""
    message_id: str = ""
    auth_results: str = ""
    received_spf: str = ""
    received: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    has_html_form: bool = False
    inline_image_count: int = 0

    @property
    def from_domain(self) -> str:
        return domain_of_address(self.from_addr)

    @property
    def from_registrable(self) -> str:
        return registrable_domain(self.from_domain)

    @property
    def return_path_domain(self) -> str:
        return domain_of_address(self.return_path)

    @property
    def body(self) -> str:
        """Texte complet utilisé par les règles de contenu."""
        return f"{self.text_body}\n{html_to_text(self.html_body)}"

    @property
    def searchable(self) -> str:
        return f"{self.subject}\n{self.from_name}\n{self.body}".lower()


def decode_mime_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


class _HTMLCollector(HTMLParser):
    """Extrait liens, formulaires, images et texte visible d'un corps HTML."""

    _SKIP_TAGS = {"script", "style", "head", "title"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self.has_form = False
        self.image_count = 0
        self._skip_depth = 0
        self._open_anchor: Link | None = None

    def handle_starttag(self, tag, attrs):
        attrs_d = {k.lower(): (v or "") for k, v in attrs}
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "a" and attrs_d.get("href"):
            link = Link(href=attrs_d["href"].strip(), source="html")
            self.links.append(link)
            self._open_anchor = link
        elif tag == "form":
            self.has_form = True
            if attrs_d.get("action"):
                self.links.append(Link(href=attrs_d["action"].strip(), source="form"))
        elif tag == "img":
            self.image_count += 1
            src = attrs_d.get("src", "")
            if src.startswith("http"):
                self.links.append(Link(href=src.strip(), text="", source="img"))
        elif tag in {"br", "p", "div", "tr", "li"}:
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a":
            self._open_anchor = None

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._open_anchor is not None:
            self._open_anchor.text += data

    @property
    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "".join(self.text_parts))


def html_to_text(html: str) -> str:
    if not html:
        return ""
    collector = _HTMLCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    return collector.text


def _decode_payload(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    for candidate in (charset, "utf-8", "cp1252", "latin-1"):
        try:
            return payload.decode(candidate, errors="strict")
        except (LookupError, UnicodeDecodeError):
            continue
    return payload.decode("utf-8", errors="replace")


def _addresses(value: str) -> list[str]:
    return [addr.lower() for _, addr in getaddresses([value or ""]) if addr]


def parse_message(raw: bytes, *, source: str = "", uid: str = "") -> ParsedEmail:
    """Construit un `ParsedEmail` à partir des octets bruts du message."""
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    parsed = ParsedEmail(source=source, uid=uid)
    parsed.headers = {k.lower(): decode_mime_header(v) for k, v in msg.items()}
    parsed.subject = decode_mime_header(msg.get("Subject"))
    parsed.date = decode_mime_header(msg.get("Date"))
    parsed.message_id = decode_mime_header(msg.get("Message-ID")).strip("<> ")

    from_raw = decode_mime_header(msg.get("From"))
    from_pairs = getaddresses([msg.get("From") or ""])
    if from_pairs:
        name, addr = from_pairs[0]
        parsed.from_name = decode_mime_header(name)
        parsed.from_addr = addr.lower()
    if not parsed.from_addr and "@" in from_raw:
        parsed.from_addr = from_raw.strip().strip("<>").lower()

    parsed.reply_to = _addresses(msg.get("Reply-To"))
    parsed.to = _addresses(msg.get("To"))
    rp = _addresses(msg.get("Return-Path"))
    parsed.return_path = rp[0] if rp else ""

    parsed.auth_results = " ".join(
        decode_mime_header(v) for k, v in msg.items()
        if k.lower() in {"authentication-results", "arc-authentication-results",
                         "x-forefront-antispam-report", "x-ms-exchange-authentication-results"}
    )
    parsed.received_spf = " ".join(
        decode_mime_header(v) for k, v in msg.items() if k.lower() == "received-spf"
    )
    parsed.received = [decode_mime_header(v) for k, v in msg.items() if k.lower() == "received"]

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = (part.get_content_type() or "").lower()
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = decode_mime_header(part.get_filename())

        if filename or "attachment" in disposition:
            payload = part.get_payload(decode=True) or b""
            parsed.attachments.append(Attachment(
                filename=filename or "(sans nom)",
                content_type=ctype,
                size=len(payload),
            ))
            continue

        if ctype == "text/plain":
            parsed.text_body += _decode_payload(part) + "\n"
        elif ctype == "text/html":
            parsed.html_body += _decode_payload(part) + "\n"

    if parsed.html_body:
        collector = _HTMLCollector()
        try:
            collector.feed(parsed.html_body)
            collector.close()
        except Exception:
            pass
        parsed.links.extend(collector.links)
        parsed.has_html_form = collector.has_form
        parsed.inline_image_count = collector.image_count

    seen = {link.href for link in parsed.links}
    for match in _URL_RE.finditer(parsed.text_body):
        href = match.group(1).rstrip(".,;:!?")
        if href.lower().startswith("www."):
            href = "http://" + href
        if href not in seen:
            seen.add(href)
            parsed.links.append(Link(href=href, text=href, source="text"))

    return parsed


def strip_zero_width(text: str) -> str:
    return _ZERO_WIDTH_RE.sub("", text)


def count_zero_width(text: str) -> int:
    return len(_ZERO_WIDTH_RE.findall(text or ""))


def parsed_date(parsed: ParsedEmail):
    try:
        return parsedate_to_datetime(parsed.date)
    except Exception:
        return None
