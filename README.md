# 🛡️ PhishGuard

**Analysez vos mails et détectez le phishing, en local, sans dépendance.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Dépendances](https://img.shields.io/badge/d%C3%A9pendances-aucune-brightgreen)
![Tests](https://img.shields.io/badge/tests-25%20unittest-brightgreen)

PhishGuard se connecte à votre boîte mail en **IMAP lecture seule**, analyse chaque
message reçu avec 25 règles heuristiques, et lui attribue un **score de
phishing de 0 à 100** — accompagné de la liste des indices qui l'ont motivé.

Pas de modèle à entraîner, pas de clé d'API, **aucun contenu de mail n'est envoyé vers un
service tiers** : tout est analysé sur votre machine, avec la seule bibliothèque standard
de Python.

```
──────────────────────────────────────────────────────────────────────────────
100/100  PHISHING  ██████████████████████████████
  De      Ameli - Assurance Maladie <no-reply@ameli-assurance.top>
  Objet   URGENT : votre remboursement de 289,47 EUR expire sous 48h !!

  Indices relevés
  AUTHENTIFICATION
    [!!] DMARC en échec (+30)
         Le domaine ameli-assurance.top rejette ce type d'envoi : usurpation
         d'expéditeur très probable.
  LIENS
    [!!] URL masquée par un « @ » (+30)
         Tout ce qui précède le @ est ignoré par le navigateur, la vraie
         destination est le domaine qui suit :
         http://ameli-assurance.top@194.36.189.7/secure/login/verify.php?id=88…
    [! ] Texte du lien différent de sa destination (+24)
         « https://www.ameli.fr/compte/rembourseme… » → 194.36.189.7
  EXPÉDITEUR
    [!!] Nom de marque inséré dans un autre domaine (+26)
         « ameli » apparaît dans ameli-assurance.top, qui n'appartient pas à ameli.

  → Ne pas cliquer, ne pas répondre. Signaler puis supprimer.
```

---

## Sommaire

- [Ce que PhishGuard détecte](#ce-que-phishguard-détecte)
- [Installation](#installation)
- [Tutoriel](#tutoriel)
  - [Étape 1 — Première analyse en 30 secondes](#étape-1--première-analyse-en-30-secondes)
  - [Étape 2 — Lire un rapport](#étape-2--lire-un-rapport)
  - [Étape 3 — Brancher sa vraie boîte mail](#étape-3--brancher-sa-vraie-boîte-mail)
  - [Étape 4 — Chasser les faux positifs](#étape-4--chasser-les-faux-positifs)
  - [Étape 5 — Sortie JSON et automatisation](#étape-5--sortie-json-et-automatisation)
  - [Étape 6 — Adapter l'outil à votre contexte](#étape-6--adapter-loutil-à-votre-contexte)
  - [Étape 7 — Écrire votre propre règle](#étape-7--écrire-votre-propre-règle)
- [Référence des commandes](#référence-des-commandes)
- [Comment le score est calculé](#comment-le-score-est-calculé)
- [Limites à connaître](#limites-à-connaître)
- [Tests](#tests)
- [Structure du projet](#structure-du-projet)

---

## Ce que PhishGuard détecte

| Famille | Exemples de règles |
|---|---|
| **Authentification** | SPF / DKIM / DMARC en échec, alignement `header.from`, `compauth` Microsoft 365 |
| **Expéditeur** | Return-Path et Reply-To désalignés, adresse cachée dans le nom affiché, alphabets mélangés, usurpation de marque, domaines sosies (`paypa1.com`, `rnicrosoft.com`, `paypal-securite.xyz`), punycode, TLD à fort taux d'abus |
| **Liens** | Lien vers une IP brute, URL masquée par un `@`, texte du lien ≠ destination, raccourcisseurs, hébergements gratuits, chemins `/login` `/verify` `/securite`, schémas `javascript:` et `data:`, formulaire intégré au HTML |
| **Contenu** | Pression temporelle, demande d'identifiants ou d'IBAN, appâts financiers, formule d'appel impersonnelle, caractères invisibles, texte masqué en CSS, message réduit à une image |
| **Pièces jointes** | Exécutables, double extension (`facture.pdf.exe`), inversion RLO, conteneurs ISO/IMG, macros Office, pièce jointe HTML, archive dont le mot de passe est donné dans le corps |

Les lexiques sont **français et anglais**, et la liste de marques couvre le contexte
francophone : Ameli, impots.gouv, CAF, URSSAF, France Travail, La Poste, Chronopost, EDF,
Orange, SFR, les grandes banques françaises, SNCF Connect, Leboncoin, Vinted…

---

## Installation

**Prérequis :** Python 3.10 ou plus. Rien d'autre.

```bash
git clone https://github.com/<votre-compte>/phishguard.git
cd phishguard
```

Vous pouvez utiliser l'outil immédiatement, sans installation :

```bash
python -m phishguard --help
```

Pour disposer de la commande `phishguard` partout :

```bash
pip install -e .
```

> **Windows + Python du Microsoft Store :** le dossier `Scripts` n'est pas dans le `PATH`,
> la commande `phishguard` ne sera pas trouvée après l'installation. Utilisez
> `python -m phishguard`, ou ajoutez au `PATH` le dossier renvoyé par
> `python -c "import sysconfig;print(sysconfig.get_path('scripts','nt_user'))"`.

Dans la suite du tutoriel, `phishguard` et `python -m phishguard` sont interchangeables.

---

## Tutoriel

### Étape 1 — Première analyse en 30 secondes

Le dépôt contient trois messages d'exemple dans `samples/`. Aucune connexion réseau
n'est nécessaire, c'est le meilleur moyen de prendre l'outil en main.

```bash
python -m phishguard file samples/
```

Vous devriez obtenir trois verdicts :

| Fichier | Score | Verdict |
|---|---:|---|
| `phishing_ameli.eml` | 100 | PHISHING |
| `malware_facture.eml` | 100 | PHISHING |
| `legit_newsletter.eml` | 0 | PROBABLEMENT LÉGITIME |

Ajoutez `--verbose` pour voir en plus les éléments **rassurants**, les domaines de tous
les liens et le détail des pièces jointes :

```bash
python -m phishguard file samples/legit_newsletter.eml --verbose
```

### Étape 2 — Lire un rapport

Chaque message produit un bloc structuré ainsi :

```
 86/100  PHISHING  ██████████████████████████░░░░     ← score et verdict
  De      Microsoft Facturation <compta...@gmail.com> ← en-tête du message
  Objet   Facture impayee - mise en demeure

  Indices relevés
  PIÈCES JOINTES                                      ← famille de règles
    [!!] Pièce jointe exécutable (+42)                ← signal, gravité, poids
         Ouvrir ce fichier exécute du code : …        ← explication
```

Les marqueurs de gravité :

| Marqueur | Poids | Signification |
|---|---|---|
| `[!!]` | ≥ 25 | Indice fort, suffit souvent à lui seul |
| `[! ]` | 12–24 | Indice sérieux, à confirmer par un autre |
| `[. ]` | 1–11 | Indice faible, significatif seulement en nombre |
| `[ok]` | ≤ 0 | Élément **rassurant**, il fait baisser le score |

Le score est la somme des poids, bornée à `[0, 100]` :

| Score | Verdict | Conduite à tenir |
|------:|---|---|
| **≥ 70** | PHISHING | Ne pas cliquer, ne pas répondre. Signaler puis supprimer. |
| **45–69** | TRÈS SUSPECT | Traiter comme malveillant tant qu'un contact direct n'a pas confirmé. |
| **22–44** | SUSPECT | Vérifier l'expéditeur par un autre canal avant toute action. |
| **< 22** | PROBABLEMENT LÉGITIME | Aucun indice fort relevé. |

En bas de chaque exécution, un **bilan** récapitule les verdicts et liste les cinq
messages à traiter en priorité.

### Étape 3 — Brancher sa vraie boîte mail

#### 3.1 — Obtenir un mot de passe d'application

Gmail, Outlook et Yahoo **refusent le mot de passe habituel du compte** en IMAP. Il faut
créer un *mot de passe d'application* :

| Fournisseur | Où le créer |
|---|---|
| Gmail | https://myaccount.google.com/apppasswords (validation en deux étapes requise) |
| Outlook / Microsoft | https://account.live.com/proofs/AppPassword |
| Yahoo | Paramètres du compte → Sécurité → Générer un mot de passe d'application |
| iCloud | https://appleid.apple.com → Connexion et sécurité |
| Autres (OVH, Free, pro…) | Le mot de passe habituel suffit généralement |

#### 3.2 — Lister les dossiers

Le serveur IMAP est **deviné à partir du domaine** de votre adresse pour les
fournisseurs courants (Gmail, Outlook, Yahoo, iCloud, Free, Orange, SFR, La Poste, GMX,
Zoho, Yandex). Pour les autres, passez `--host imap.mondomaine.fr`.

```bash
python -m phishguard folders --user moi@exemple.fr
```

L'outil demande le mot de passe à l'invite. **La saisie n'est pas affichée, le mot de
passe n'est jamais écrit sur le disque ni envoyé ailleurs que vers votre serveur IMAP.**

Notez le nom exact du dossier de spam : selon le compte, `[Gmail]/Spam`,
`[Gmail]/Courrier indésirable`, `Junk`, `INBOX.Spam`…

#### 3.3 — Le vrai test : le dossier Spam

C'est là que se trouvent les vrais messages de phishing. Votre boîte de réception a déjà
été filtrée par votre fournisseur.

```bash
python -m phishguard scan --user moi@exemple.fr --folder "[Gmail]/Spam" --limit 20 --verbose
```

> **La boîte est ouverte en lecture seule** et les messages sont récupérés avec
> `BODY.PEEK[]` : rien n'est marqué comme lu, déplacé, ni supprimé.

#### 3.4 — Analyser la boîte de réception

```bash
python -m phishguard scan --user moi@exemple.fr --limit 50
```

Quelques filtres utiles, combinables :

```bash
# Seulement les messages non lus des 7 derniers jours
python -m phishguard scan --user moi@exemple.fr --unseen --since 7

# Seulement ce qui atteint le seuil « suspect »
python -m phishguard scan --user moi@exemple.fr --limit 100 --min-score 22

# Tous les messages d'un expéditeur donné
python -m phishguard scan --user moi@exemple.fr --from service@banque.fr

# Un autre dossier
python -m phishguard scan --user moi@exemple.fr --folder "Archives" --limit 30
```

#### 3.5 — Éviter de retaper le mot de passe

Pour une session de travail, définissez la variable d'environnement
`PHISHGUARD_PASSWORD` — l'invite est alors sautée :

```bash
# Linux / macOS
export PHISHGUARD_PASSWORD='votre-mot-de-passe-application'
```

```powershell
# Windows PowerShell
$env:PHISHGUARD_PASSWORD = 'votre-mot-de-passe-application'
```

La variable disparaît à la fermeture du terminal. Ne l'inscrivez pas en dur dans un
script versionné.

### Étape 4 — Chasser les faux positifs

C'est l'étape qui rend l'outil réellement utilisable au quotidien.

```bash
python -m phishguard scan --user moi@exemple.fr --limit 100 --min-score 22 --verbose
```

Tout ce qui remonte ici est **a priori un faux positif** : votre fournisseur a déjà
laissé passer ces messages. Deux causes typiques :

**Newsletters routées par un prestataire** (Mailchimp, Sendgrid, Brevo…) — elles
déclenchent normalement `Return-Path différent du From` et `Aucun lien vers le domaine de
l'expéditeur`. Ces signaux sont volontairement peu pondérés (11 et 7), mais ils
s'additionnent. Ajoutez les domaines concernés à vos listes (voir l'étape 6).

**Domaines internes de votre organisation** — si vos collègues écrivent depuis
`mon-entreprise.fr` et que vos outils envoient depuis `notifications.mon-entreprise.fr`,
déclarez la marque et ses domaines légitimes dans `phishguard/data.py`.

### Étape 5 — Sortie JSON et automatisation

```bash
python -m phishguard scan --user moi@exemple.fr --limit 100 --json rapport.json
```

Le JSON contient, pour chaque message : expéditeur, objet, date, score, verdict, conseil,
domaines des liens, pièces jointes et **la liste complète des signaux** avec leur poids.
Utilisez `--json -` pour écrire sur la sortie standard et chaîner avec `jq` :

```bash
python -m phishguard scan --user moi@exemple.fr --json - | jq '.[] | select(.score >= 70) | .subject'
```

**Codes de sortie**, pratiques pour une tâche planifiée :

| Code | Signification |
|---|---|
| `0` | Aucun message n'atteint 45/100 |
| `1` | Au moins un message à 45/100 ou plus |
| `2` | Erreur IMAP (connexion, authentification, dossier introuvable) |
| `130` | Interrompu par l'utilisateur |

Exemple de contrôle quotidien sous Linux (`crontab -e`), qui n'écrit un rapport que
lorsqu'il y a quelque chose à signaler :

```cron
0 8 * * * cd ~/phishguard && PHISHGUARD_PASSWORD='...' python -m phishguard scan \
  --user moi@exemple.fr --since 1 --min-score 45 --json ~/alertes-$(date +\%F).json
```

### Étape 6 — Adapter l'outil à votre contexte

Tout se règle dans **`phishguard/data.py`**, qui ne contient que des listes.

**Déclarer vos domaines légitimes** — le plus efficace contre les faux positifs :

```python
BRANDS = {
    ...
    "mon entreprise": {"mon-entreprise.fr", "notifications.mon-entreprise.fr"},
}
```

Un message dont le nom affiché ou l'objet mentionne « Mon Entreprise » sans venir de ces
domaines déclenchera alors une alerte d'usurpation — et l'inverse ne déclenchera rien.

**Ajouter des mots-clés** propres à votre secteur :

```python
URGENCY_TERMS += ["avant régularisation", "dernière relance"]
MONEY_LURE_TERMS += ["appel de fonds", "changement de RIB"]
```

**Ajuster les seuils de verdict** dans `phishguard/analyzer.py` :

```python
VERDICTS = (
    (70, "PHISHING", "…"),
    (45, "TRÈS SUSPECT", "…"),
    (22, "SUSPECT", "…"),      # abaissez à 15 pour un tri plus agressif
    (0,  "PROBABLEMENT LÉGITIME", "…"),
)
```

### Étape 7 — Écrire votre propre règle

Une règle est une fonction décorée qui reçoit le message analysé et produit des signaux.
Créez-la dans le fichier de la famille concernée — par exemple
`phishguard/rules/content.py` :

```python
from .base import CONTENT, Signal, rule

@rule
def fraude_au_president(parsed):
    """Demande de virement urgent et confidentiel : arnaque au président."""
    texte = parsed.searchable          # objet + nom affiché + corps, en minuscules
    if "virement" in texte and "confidentiel" in texte:
        yield Signal(
            id="content.fraude_president",
            category=CONTENT,
            title="Demande de virement confidentiel",
            detail="Combinaison typique de la fraude au président.",
            weight=30,
        )
```

Les attributs utiles de `parsed` :

| Attribut | Contenu |
|---|---|
| `parsed.from_addr`, `parsed.from_name` | Adresse et nom affiché de l'expéditeur |
| `parsed.from_domain`, `parsed.from_registrable` | Domaine complet et domaine enregistrable (eTLD+1) |
| `parsed.subject`, `parsed.text_body`, `parsed.html_body` | Objet et corps |
| `parsed.searchable` | Objet + nom affiché + corps, en minuscules — pour chercher des mots-clés |
| `parsed.links` | Liste de `Link` (`.href`, `.text`, `.host`, `.domain`, `.scheme`, `.path_and_query`) |
| `parsed.attachments` | Liste d'`Attachment` (`.filename`, `.content_type`, `.size`, `.extension`) |
| `parsed.auth_results`, `parsed.received` | En-têtes d'authentification et de routage bruts |

Un `weight` **négatif** produit un signal rassurant qui fait baisser le score.
Passez `dampenable=False` pour que le signal ne soit pas atténué quand le DMARC est
valide (voir la section suivante).

Ajoutez ensuite un test dans `tests/test_phishguard.py` et relancez la suite.

---

## Référence des commandes

```
phishguard [options] {scan,file,folders} [options]
```

Les options communes sont acceptées **avant ou après** la sous-commande.

| Option commune | Effet |
|---|---|
| `--json [FICHIER]` | Écrit le rapport en JSON (`-` pour la sortie standard) |
| `--min-score N` | N'affiche que les messages atteignant le score `N` |
| `--verbose`, `-v` | Affiche aussi les éléments rassurants et le détail technique |
| `--no-color` | Désactive la couleur (également via `NO_COLOR=1`) |

### `scan` — analyser une boîte IMAP

| Option | Défaut | Effet |
|---|---|---|
| `--user`, `-u` | *(requis)* | Adresse / identifiant IMAP |
| `--host` | deviné | Serveur IMAP |
| `--port` | `993` | Port IMAP |
| `--no-ssl` | | Connexion en clair puis STARTTLS (port 143) |
| `--folder`, `-f` | `INBOX` | Dossier à analyser |
| `--limit`, `-n` | `25` | Nombre de messages les plus récents |
| `--unseen` | | Seulement les messages non lus |
| `--since JOURS` | | Seulement les messages reçus depuis N jours |
| `--from` | | Filtre sur l'expéditeur |
| `--query` | | Critères IMAP bruts supplémentaires |

### `file` — analyser des fichiers `.eml`

```bash
python -m phishguard file message.eml
python -m phishguard file "dossier/*.eml"
python -m phishguard file mon-dossier/        # parcours récursif des .eml
```

Pour récupérer un `.eml` depuis Gmail : ouvrez le message → menu `⋮` → **Afficher
l'original** → **Télécharger le message**.

### `folders` — lister les dossiers de la boîte

```bash
python -m phishguard folders --user moi@exemple.fr
```

---

## Comment le score est calculé

1. Les 25 règles sont appliquées au message. Chacune peut produire un ou plusieurs
   **signaux** pondérés — une soixantaine de types de signaux différents au total.
2. Si le message présente un **DMARC valide et aligné** sur un domaine d'entreprise, le
   domaine expéditeur n'est pas usurpé : les signaux marqués `dampenable` voient leur
   poids **divisé par deux**.
3. Cette atténuation **ne s'applique pas aux messageries gratuites** : un DMARC valide
   sur `gmail.com` prouve seulement que le compte Gmail existe, pas que l'expéditeur est
   légitime.
4. Le score est la somme des poids, bornée à `[0, 100]`, puis traduite en verdict.

C'est ce mécanisme qui permet à un message signé `Microsoft Facturation
<compta.fournisseur2026@gmail.com>` de sortir à **100/100** malgré un DMARC Gmail
parfaitement valide.

---

## Limites à connaître

- **C'est une heuristique, pas une vérité.** Un score bas ne garantit pas la légitimité.
  Le spear-phishing bien rédigé, envoyé depuis un compte légitime compromis, ne déclenche
  presque aucune règle — parce qu'il n'y a objectivement rien d'anormal à détecter.
- Les verdicts SPF / DKIM / DMARC sont **lus dans les en-têtes** ajoutés par votre serveur
  de réception ; ils ne sont pas revérifiés par DNS. Un message récupéré autrement que par
  le serveur final peut ne pas les porter.
- Les pièces jointes sont jugées **sur leur nom et leur type déclaré**, pas sur leur
  contenu : PhishGuard n'est pas un antivirus et ne remplace pas l'analyse du fichier.
- Les listes de marques, TLD et hébergeurs sont **à compléter selon votre contexte**
  (voir l'étape 6). Telles quelles, elles couvrent surtout les usurpations grand public
  francophones.
- PhishGuard **ne modifie jamais votre boîte mail** : il ne peut ni classer, ni supprimer,
  ni répondre. C'est un outil d'aide à la décision.

---

## Tests

```bash
python -m unittest discover -s tests -v
```

25 tests couvrent l'extraction du domaine enregistrable, la normalisation des caractères
trompeurs, la lecture des en-têtes d'authentification, chaque famille de règles, les
cas légitimes qui **ne doivent pas** déclencher d'alerte, et le verdict attendu sur les
trois messages de `samples/`.

## Structure du projet

```
phishguard/
├── phishguard/
│   ├── cli.py           # interface en ligne de commande
│   ├── imap_client.py   # connexion IMAP en lecture seule
│   ├── parser.py        # message brut → structure exploitable
│   ├── analyzer.py      # exécution des règles et calcul du score
│   ├── report.py        # rendu terminal
│   ├── data.py          # marques, TLD, hébergeurs, lexiques  ← à personnaliser
│   ├── util.py          # domaines, distance d'édition, confusables
│   └── rules/
│       ├── base.py          # Signal, registre des règles
│       ├── headers.py       # authentification et expéditeur
│       ├── links.py         # URL
│       ├── content.py       # texte et structure du corps
│       └── attachments.py   # pièces jointes
├── samples/             # messages d'exemple pour la prise en main
└── tests/
```
