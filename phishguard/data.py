"""Listes de référence : marques usurpées, TLD/hébergeurs à risque, lexiques FR/EN."""

from __future__ import annotations

# Marques les plus usurpées en phishing (contexte francophone inclus).
# clé = nom de marque cherché dans le nom affiché / l'objet
# valeur = domaines enregistrables légitimes connus
BRANDS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "sharepointonline.com", "azure.com"},
    "outlook": {"outlook.com", "microsoft.com", "live.com", "hotmail.com"},
    "office365": {"microsoft.com", "office.com", "microsoftonline.com"},
    "google": {"google.com", "google.fr", "gmail.com", "googlemail.com", "youtube.com"},
    "gmail": {"google.com", "gmail.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com", "itunes.com", "me.com"},
    "icloud": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.fr", "amazon.co.uk", "amazon.de", "amazonses.com",
               "amazon.es", "amazon.it", "primevideo.com"},
    "paypal": {"paypal.com", "paypal.fr", "paypal-communication.com", "paypal.me"},
    "netflix": {"netflix.com", "nflxext.com", "mailer.netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "fb.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com", "mail.instagram.com"},
    "whatsapp": {"whatsapp.com", "meta.com"},
    "linkedin": {"linkedin.com", "licdn.com"},
    "spotify": {"spotify.com", "spotifymail.com"},
    "adobe": {"adobe.com", "adobesign.com", "adobe.io"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "revolut": {"revolut.com"},
    "n26": {"n26.com"},
    # Logistique
    "dhl": {"dhl.com", "dhl.fr", "dhl.de"},
    "ups": {"ups.com"},
    "fedex": {"fedex.com"},
    "chronopost": {"chronopost.fr"},
    "colissimo": {"laposte.fr", "colissimo.fr"},
    "laposte": {"laposte.fr", "laposte.net"},
    "mondial relay": {"mondialrelay.fr", "mondialrelay.com"},
    "dpd": {"dpd.fr", "dpd.com"},
    "gls": {"gls-group.eu", "gls-group.com"},
    # Administration française
    "ameli": {"ameli.fr", "assurance-maladie.fr"},
    "impots": {"impots.gouv.fr", "dgfip.finances.gouv.fr", "finances.gouv.fr"},
    "caf": {"caf.fr"},
    "urssaf": {"urssaf.fr"},
    "pole emploi": {"pole-emploi.fr", "francetravail.fr"},
    "france travail": {"francetravail.fr", "pole-emploi.fr"},
    "antai": {"antai.gouv.fr"},
    "service-public": {"service-public.fr"},
    "cpam": {"ameli.fr", "assurance-maladie.fr"},
    # Énergie / télécom FR
    "edf": {"edf.fr"},
    "engie": {"engie.fr"},
    "orange": {"orange.fr", "orange.com"},
    "sfr": {"sfr.fr", "sfr.com"},
    "bouygues": {"bouyguestelecom.fr", "bouygues.com"},
    "free": {"free.fr", "iliad.fr"},
    "sosh": {"sosh.fr", "orange.fr"},
    # Banques FR
    "bnp": {"bnpparibas.com", "bnpparibas.net", "bnpparibas.fr", "mabanque.bnpparibas"},
    "societe generale": {"societegenerale.fr", "socgen.com"},
    "credit agricole": {"credit-agricole.fr", "ca-paris.fr", "credit-agricole.com"},
    "credit mutuel": {"creditmutuel.fr", "cmcic.fr"},
    "lcl": {"lcl.fr"},
    "caisse d'epargne": {"caisse-epargne.fr", "cyberplus.fr"},
    "banque postale": {"labanquepostale.fr"},
    "boursorama": {"boursorama.com", "boursobank.com"},
    "hello bank": {"hellobank.fr"},
    "axa": {"axa.fr", "axa.com"},
    # Divers
    "sncf": {"sncf.com", "sncf-connect.com", "sncf.fr"},
    "leboncoin": {"leboncoin.fr"},
    "vinted": {"vinted.fr", "vinted.com"},
    "cdiscount": {"cdiscount.com"},
    "fnac": {"fnac.com"},
    "ovh": {"ovh.com", "ovhcloud.com", "ovh.net"},
    "booking": {"booking.com"},
    "airbnb": {"airbnb.com", "airbnb.fr"},
    "steam": {"steampowered.com", "valvesoftware.com"},
}

# Domaines de raccourcisseurs d'URL : masquent la destination réelle.
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "bl.ink",
    "lnkd.in", "t.ly", "s.id", "v.gd", "shorte.st", "adf.ly", "bc.vc",
    "u.to", "clck.ru", "qr.ae", "surl.li", "short.io", "urlz.fr", "lc.cx",
}

# Hébergements gratuits / plateformes souvent utilisées pour héberger des kits.
FREE_HOSTING = {
    "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "r2.dev",
    "netlify.app", "vercel.app", "glitch.me", "repl.co", "replit.app",
    "github.io", "gitlab.io", "herokuapp.com", "ngrok.io", "ngrok-free.app",
    "trycloudflare.com", "sharepoint.com", "storage.googleapis.com",
    "duckdns.org", "serveo.net", "azurewebsites.net", "godaddysites.com",
    "mystrikingly.com", "webflow.io", "square.site", "yolasite.com",
    "typeform.com", "jotform.com", "forms.gle", "surveyheart.com",
}

# TLD au taux d'abus très élevé (rapports Spamhaus / Interisle).
RISKY_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click",
    "link", "work", "loan", "quest", "cam", "rest", "fit", "sbs", "cyou",
    "icu", "monster", "buzz", "bar", "casa", "surf", "beauty", "makeup",
    "skin", "hair", "bond", "cfd", "autos", "boats", "lol", "live",
}

# Fournisseurs de messagerie gratuits : suspects comme Reply-To d'une « entreprise ».
FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.fr", "ymail.com",
    "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com",
    "live.fr", "msn.com", "aol.com", "gmx.com", "gmx.fr", "gmx.net",
    "mail.com", "mail.ru", "yandex.com", "yandex.ru", "protonmail.com",
    "proton.me", "tutanota.com", "zoho.com", "icloud.com", "laposte.net",
    "orange.fr", "wanadoo.fr", "free.fr", "sfr.fr", "bbox.fr", "neuf.fr",
}

# Extensions de pièces jointes directement exécutables.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "msp", "cpl", "jar", "ps1", "psm1", "reg",
    "lnk", "scf", "inf", "gadget", "application", "appref-ms", "chm",
}

# Conteneurs servant à contourner Mark-of-the-Web / l'antivirus.
CONTAINER_EXTENSIONS = {"iso", "img", "vhd", "vhdx", "cab", "ace", "arj"}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz"}

# Documents Office avec macros.
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm", "xlam", "ppam", "xls", "doc"}

# Extensions inoffensives fréquemment utilisées en première partie d'un
# nom à double extension (facture.pdf.exe).
DECOY_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg",
    "png", "gif", "csv", "rtf", "htm", "html", "mp3", "mp4", "avi",
}

# Segments d'URL typiques d'une page de collecte d'identifiants.
CREDENTIAL_PATH_TOKENS = {
    "login", "signin", "sign-in", "logon", "auth", "authenticate", "verify",
    "verification", "validate", "confirm", "confirmation", "secure", "security",
    "account", "accounts", "update", "unlock", "recover", "recovery", "reset",
    "password", "passwd", "credential", "billing", "payment", "invoice",
    "webmail", "owa", "mfa", "otp", "2fa", "session", "wallet", "connexion",
    "identifiant", "motdepasse", "compte", "verifier", "securite", "paiement",
}

# Lexique d'urgence / menace (FR + EN).
URGENCY_TERMS = [
    "urgent", "immédiat", "immediate", "immediatement", "immédiatement",
    "dans les 24 heures", "sous 24h", "sous 48h", "within 24 hours",
    "dernier avertissement", "final warning", "last warning",
    "dernier rappel", "expire", "expiration", "expiré", "expired", "expiring",
    "suspendu", "suspension", "suspended", "sera suspendu", "will be suspended",
    "désactivé", "desactive", "deactivated", "disabled", "bloqué", "blocked",
    "verrouillé", "locked", "restreint", "restricted", "limité", "limited",
    "action requise", "action required", "action immédiate", "act now",
    "ne pas ignorer", "do not ignore", "attention requise",
    "résilié", "terminated", "fermeture de compte", "account closure",
    "avant la fermeture", "sans délai", "au plus vite", "asap",
    "supprimé définitivement", "permanently deleted",
]

# Lexique de demande d'identifiants / d'informations sensibles.
CREDENTIAL_REQUEST_TERMS = [
    "vérifier votre compte", "verifier votre compte", "verify your account",
    "confirmer votre identité", "confirm your identity", "confirmez votre identité",
    "mettre à jour vos informations", "update your information",
    "mettre à jour vos coordonnées bancaires", "update your billing",
    "saisir votre mot de passe", "enter your password", "votre mot de passe",
    "identifiants", "credentials", "numéro de carte", "card number",
    "code de sécurité", "security code", "code à 3 chiffres", "cvv",
    "code de vérification", "verification code", "code otp", "code sms",
    "reconfirmer", "re-confirm", "revalider", "réactiver votre compte",
    "reactivate your account", "confirmer vos informations de paiement",
    "cliquez ici pour vous connecter", "click here to log in",
    "connectez-vous à votre compte", "log in to your account",
    "numéro de sécurité sociale", "social security number", "numéro fiscal",
    "pièce d'identité", "carte d'identité", "rib", "iban",
]

# Appâts financiers.
MONEY_LURE_TERMS = [
    "remboursement", "refund", "vous avez gagné", "you have won", "winner",
    "loterie", "lottery", "héritage", "inheritance", "carte cadeau",
    "gift card", "bon d'achat", "voucher", "cashback", "prime",
    "bitcoin", "crypto", "usdt", "ethereum", "investissement garanti",
    "gains garantis", "guaranteed profit", "trop-perçu", "trop perçu",
    "crédit d'impôt", "remboursement fiscal", "tax refund",
    "colis en attente", "frais de douane", "frais de livraison",
    "customs fee", "delivery fee", "paiement en attente",
    "facture impayée", "unpaid invoice", "overdue payment", "mise en demeure",
]

# Formules de politesse génériques : pas de personnalisation = envoi de masse.
GENERIC_GREETINGS = [
    "cher client", "chère cliente", "cher utilisateur", "chère utilisatrice",
    "cher abonné", "cher membre", "cher adhérent", "bonjour cher",
    "dear customer", "dear user", "dear client", "dear member",
    "dear account holder", "dear sir/madam", "dear sir or madam",
    "dear valued customer", "attention utilisateur", "cher titulaire",
    "madame, monsieur,", "à qui de droit",
]
