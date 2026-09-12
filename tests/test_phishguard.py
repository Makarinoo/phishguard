"""Tests du moteur (stdlib uniquement : python -m unittest discover -s tests)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard.analyzer import analyze  # noqa: E402
from phishguard.imap_client import build_criteria, guess_server  # noqa: E402
from phishguard.parser import parse_message  # noqa: E402
from phishguard.rules.headers import auth_verdicts, dmarc_aligned_pass  # noqa: E402
from phishguard.util import (  # noqa: E402
    confusable_normalize,
    levenshtein,
    registrable_domain,
)

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def build_eml(*, headers: str, body: str) -> bytes:
    return (headers.strip() + "\n\n" + body).encode("utf-8")


def analyze_raw(headers: str, body: str):
    return analyze(parse_message(build_eml(headers=headers, body=body)))


def signal_ids(analysis) -> set[str]:
    return {s.id for s in analysis.signals}


class TestUtil(unittest.TestCase):
    def test_registrable_domain(self):
        self.assertEqual(registrable_domain("mail.free.fr"), "free.fr")
        self.assertEqual(registrable_domain("a.b.c.co.uk"), "c.co.uk")
        self.assertEqual(registrable_domain("IMPOTS.GOUV.FR"), "impots.gouv.fr")
        self.assertEqual(registrable_domain("192.168.1.1"), "192.168.1.1")

    def test_confusable_normalize(self):
        self.assertEqual(confusable_normalize("PayPa1"), "paypal")
        self.assertEqual(confusable_normalize("rnicrosoft"), "microsoft")
        self.assertEqual(confusable_normalize("amél1e"), "amelle")

    def test_levenshtein_cutoff(self):
        self.assertEqual(levenshtein("paypal", "paypa1"), 1)
        self.assertGreater(levenshtein("abc", "zzzzzzzzzz", max_distance=2), 2)


class TestAuthParsing(unittest.TestCase):
    HEADERS = (
        "From: a@exemple.fr\n"
        "Authentication-Results: mx; spf=pass smtp.mailfrom=exemple.fr; "
        "dkim=pass header.d=exemple.fr; dmarc=pass header.from=exemple.fr"
    )

    def test_verdicts(self):
        parsed = parse_message(build_eml(headers=self.HEADERS, body="ok"))
        self.assertEqual(auth_verdicts(parsed)["spf"], "pass")
        self.assertTrue(dmarc_aligned_pass(parsed))

    def test_worst_verdict_wins(self):
        headers = ("From: a@exemple.fr\n"
                   "Authentication-Results: mx1; spf=pass\n"
                   "Authentication-Results: mx2; spf=fail")
        parsed = parse_message(build_eml(headers=headers, body="ok"))
        self.assertEqual(auth_verdicts(parsed)["spf"], "fail")

    def test_dmarc_unaligned_is_not_a_pass(self):
        headers = ("From: a@victime.fr\n"
                   "Authentication-Results: mx; dmarc=pass header.from=autre.com")
        parsed = parse_message(build_eml(headers=headers, body="ok"))
        self.assertFalse(dmarc_aligned_pass(parsed))


class TestSenderRules(unittest.TestCase):
    def test_lookalike_domain(self):
        analysis = analyze_raw("From: Service <no-reply@paypa1.com>\nSubject: Test", "Bonjour")
        self.assertIn("sender.lookalike_exact", signal_ids(analysis))

    def test_brand_inserted_in_domain(self):
        analysis = analyze_raw(
            "From: Support <x@paypal-securite.xyz>\nSubject: Compte", "Bonjour")
        self.assertIn("sender.brand_in_domain", signal_ids(analysis))

    def test_legit_brand_domain_is_clean(self):
        analysis = analyze_raw(
            "From: PayPal <service@paypal.com>\nSubject: Votre recu PayPal", "Merci")
        ids = signal_ids(analysis)
        self.assertNotIn("sender.brand_impersonation", ids)
        self.assertNotIn("sender.lookalike_exact", ids)

    def test_display_name_hides_other_address(self):
        analysis = analyze_raw(
            'From: "service@ameli.fr" <pirate@random.top>\nSubject: Info', "Bonjour")
        self.assertIn("sender.name_contains_other_address", signal_ids(analysis))

    def test_reply_to_freemail(self):
        analysis = analyze_raw(
            "From: Compta <compta@entreprise-abc.fr>\n"
            "Reply-To: compta.direction@gmail.com\nSubject: Virement", "Bonjour")
        signals = {s.id: s for s in analysis.signals}
        self.assertIn("sender.reply_to_mismatch", signals)
        self.assertEqual(signals["sender.reply_to_mismatch"].weight, 26)


class TestLinkRules(unittest.TestCase):
    def test_userinfo_and_ip(self):
        body = '<a href="http://banque.fr@203.0.113.9/login">mon compte</a>'
        analysis = analyze_raw("From: a@exemple.fr\nContent-Type: text/html", body)
        ids = signal_ids(analysis)
        self.assertIn("links.userinfo_trick", ids)
        self.assertIn("links.ip_host", ids)

    def test_anchor_mismatch(self):
        body = '<a href="https://evil.top/x">https://www.impots.gouv.fr/compte</a>'
        analysis = analyze_raw("From: a@exemple.fr\nContent-Type: text/html", body)
        self.assertIn("links.anchor_mismatch", signal_ids(analysis))

    def test_matching_anchor_is_clean(self):
        body = '<a href="https://www.exemple.fr/compte">https://www.exemple.fr</a>'
        analysis = analyze_raw("From: a@exemple.fr\nContent-Type: text/html", body)
        self.assertNotIn("links.anchor_mismatch", signal_ids(analysis))

    def test_html_form_detected(self):
        body = '<form action="https://evil.top/collect"><input name="pwd"></form>'
        analysis = analyze_raw("From: a@exemple.fr\nContent-Type: text/html", body)
        self.assertIn("links.html_form", signal_ids(analysis))

    def test_plain_text_urls_are_extracted(self):
        analysis = analyze_raw("From: a@exemple.fr", "Voir http://bit.ly/abc pour la suite")
        self.assertIn("links.shortener", signal_ids(analysis))


class TestAttachmentRules(unittest.TestCase):
    MULTIPART = (
        "From: a@exemple.fr\n"
        "Subject: Document\n"
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="bd"'
    )

    def _with_attachment(self, filename: str, ctype: str = "application/octet-stream"):
        body = (
            "--bd\nContent-Type: text/plain\n\nBonjour\n\n"
            f"--bd\nContent-Type: {ctype}\n"
            f'Content-Disposition: attachment; filename="{filename}"\n\n'
            "AAAA\n--bd--\n"
        )
        return analyze_raw(self.MULTIPART, body)

    def test_executable(self):
        self.assertIn("att.executable", signal_ids(self._with_attachment("update.exe")))

    def test_double_extension(self):
        ids = signal_ids(self._with_attachment("facture.pdf.exe"))
        self.assertIn("att.double_extension", ids)
        self.assertIn("att.executable", ids)

    def test_html_attachment(self):
        self.assertIn("att.html_file",
                      signal_ids(self._with_attachment("connexion.html", "text/html")))

    def test_pdf_is_not_flagged(self):
        ids = signal_ids(self._with_attachment("rapport.pdf", "application/pdf"))
        self.assertNotIn("att.executable", ids)
        self.assertNotIn("att.double_extension", ids)


class TestContentRules(unittest.TestCase):
    def test_urgency_and_credentials(self):
        analysis = analyze_raw(
            "From: a@exemple.fr\nSubject: Action requise",
            "Votre compte sera suspendu. Merci de confirmer votre identité.")
        ids = signal_ids(analysis)
        self.assertIn("content.urgency", ids)
        self.assertIn("content.credential_request", ids)

    def test_neutral_message_scores_low(self):
        analysis = analyze_raw(
            "From: Jean <jean@exemple.fr>\nSubject: Compte rendu de reunion\n"
            "Message-ID: <1@exemple.fr>\n"
            "Authentication-Results: mx; spf=pass; dkim=pass; "
            "dmarc=pass header.from=exemple.fr",
            "Bonjour Marie,\n\nVoici le compte rendu de la reunion de mardi.\n\nJean")
        self.assertLess(analysis.score, 22)
        self.assertEqual(analysis.verdict, "PROBABLEMENT LÉGITIME")


class TestImapHelpers(unittest.TestCase):
    def test_guess_server(self):
        self.assertEqual(guess_server("moi@gmail.com"), ("imap.gmail.com", 993))
        self.assertIsNone(guess_server("moi@domaine-inconnu.fr"))

    def test_build_criteria(self):
        self.assertEqual(build_criteria(), ["ALL"])
        criteria = build_criteria(unseen=True, since_days=7, sender="a@b.fr")
        self.assertEqual(criteria[0], "UNSEEN")
        self.assertIn("SINCE", criteria)
        self.assertEqual(criteria[-2:], ["FROM", "a@b.fr"])


class TestSamples(unittest.TestCase):
    def _score(self, name: str) -> int:
        return analyze(parse_message((SAMPLES / name).read_bytes())).score

    def test_sample_verdicts(self):
        self.assertGreaterEqual(self._score("phishing_ameli.eml"), 70)
        self.assertGreaterEqual(self._score("malware_facture.eml"), 70)
        self.assertLess(self._score("legit_newsletter.eml"), 22)


if __name__ == "__main__":
    unittest.main(verbosity=2)
