# PRD — Crypto Vibeness

> Système de chat sécurisé en Python | Groupe de 3 | Branches GitHub | Dockerisé  
> La Plateforme — Vibe coding avec agent IA

---

## 1. Vue d'ensemble — Qui fait quoi

| Jour/Partie | Branche | Ce qui est produit | Fichiers créés / modifiés |
|---|---|---|---|
| J1 – P1 | 🔵 `dev1-core-network` | Serveur TCP multi-clients, rooms, couleurs, logs | `server.py`, `client.py`, `config.py` |
| J1 – P2 | 🟢 `dev2-auth-crypto` | Authentification + mots de passe hashés MD5 | `auth.py`, `this_is_safe.txt`, `password_rules.json` |
| J2 – P1 | 🟢 `dev2-auth-crypto` | Attaque hashcat + migration bcrypt + salage 96 bits | `auth.py` (màj), `md5_decrypted.txt` |
| J2 – P2 | 🟢 `dev2-auth-crypto` | Chiffrement symétrique AES de tout le trafic | `crypto_sym.py`, `user_keys_do_not_steal_plz.txt` |
| J3 – P1 | 🟣 `dev3-e2ee-docker` | Crypto asymétrique : paires RSA/Ed25519, échange de clé | `crypto_asym.py`, `*.priv`, `*.pub` |
| J3 – P2 | 🟣 `dev3-e2ee-docker` | E2EE 1-1 : clé de session + signatures + rejet si invalide | `e2ee.py` |
| J3 – P2 | 🟣 `dev3-e2ee-docker` | Dockerisation complète du projet | `Dockerfile`, `docker-compose.yml`, `requirements.txt` |

> ⚠️ Les branches 2 et 3 dépendent de la branche 1. Dev 2 et Dev 3 rebasent sur `main` après chaque merge précédent.

---

## 2. Architecture globale Python

Deux processus Python communiquant via TCP. Un module = une branche.

```
client.py  ──────── TCP port 9000 ────────  server.py
   │                                              │
   ├── auth.py           🟢 Dev 2                ├── auth.py
   ├── crypto_sym.py     🟢 Dev 2                ├── crypto_sym.py
   ├── crypto_asym.py    🟣 Dev 3                ├── crypto_asym.py
   └── e2ee.py           🟣 Dev 3                └── e2ee.py
```

| 🔵 Dev 1 — `dev1-core-network` | 🟢 Dev 2 — `dev2-auth-crypto` | 🟣 Dev 3 — `dev3-e2ee-docker` |
|---|---|---|
| `server.py` — TCP, rooms, broadcast | `auth.py` — login, hash, salage | `crypto_asym.py` — RSA/Ed25519 |
| `client.py` — CLI, couleurs, timestamps | `crypto_sym.py` — KDF + AES | `e2ee.py` — session keys, signatures |
| `config.py` — constantes & config | `password_rules.json` — règles mdp | `Dockerfile` + `docker-compose.yml` |

---

## 3. 🔵 Branche 1 — Dev 1

**Branche :** `feature/dev1-core-network`  
**Périmètre :** Core réseau — serveur IRC multi-clients + client CLI  
**Prérequis :** aucun

### Jour 1 — Partie 1 : Serveur IRC de base (YOLO)

Objectif : avoir un chat CLI fonctionnel multi-clients, sans aucune sécurité. C'est la fondation du projet entier.

| Tâche | Détail | Priorité |
|---|---|---|
| Serveur TCP multi-clients | `asyncio` ou `threading`. Port configurable via argument CLI ou `DEFAULT_PORT` dans `config.py`. | 🔴 CRITIQUE |
| Système de rooms | Room `general` par défaut. Commandes `/join`, `/create`, `/list`. Rooms protégées affichées avec 🔒. | 🔴 CRITIQUE |
| Usernames uniques | Le serveur refuse 2 connexions simultanées avec le même username. | 🔴 CRITIQUE |
| Couleurs déterministes | `hash(username) % nb_couleurs` via colorama. Identique chez tous les clients, stable durant toute la session. | 🟠 HAUTE |
| Timestamps sur les messages | Format `[HH:MM:SS]` affiché côté client pour chaque message. | 🟠 HAUTE |
| Logs serveur horodatés | Fichier `log_YYYY-MM-DD_HH-MM-SS.txt`. Connexions, déconnexions, messages, erreurs. | 🟠 HAUTE |

> ✅ **Validation Dev 1 :** tester avec 3 terminaux simultanés. Vérifier rooms, couleurs, timestamps, logs. Merger uniquement si tout passe.

### Fichiers produits par Dev 1

- `server.py` — serveur TCP principal (asyncio/threading)
- `client.py` — client CLI interactif avec couleurs
- `config.py` — `DEFAULT_PORT`, liste de couleurs, constantes
- `requirements.txt` — colorama (+ futures dépendances des branches 2 & 3)
- `CONTEXT.md` — contexte pour l'agent IA (architecture, contraintes, état)
- `README.md` — `python server.py [port]` / `python client.py [host] [port]`

---

## 4. 🟢 Branche 2 — Dev 2

**Branche :** `feature/dev2-auth-crypto`  
**Périmètre :** Authentification + Hash + Crypto symétrique  
**Prérequis :** branche Dev 1 mergée sur `main`

> ℹ️ Dev 2 crée sa branche depuis `main` après le merge de Dev 1.

### Jour 1 — Partie 2 : Authentification (hash MD5)

Ajouter un système d'authentification avant l'accès au chat. Mots de passe hashés en MD5 (volontairement faible — on corrigera au Jour 2).

| Tâche | Détail | Priorité |
|---|---|---|
| Flux d'authentification | Login ou création de compte **avant** toute entrée dans le chat. Les non-authentifiés ne reçoivent aucun message. | 🔴 CRITIQUE |
| Règles de mot de passe | ≥ 3 règles dans `password_rules.json` (longueur min 8, 1 chiffre, 1 majuscule). Lues au démarrage du serveur. | 🔴 CRITIQUE |
| Indicateur de force | Calcul d'entropie Shannon. Retourner `Faible` / `Moyen` / `Fort` après enregistrement. | 🟠 HAUTE |
| Hash MD5 + base64 | `hashlib.md5()`. Stockage : `username:hash_b64` dans `this_is_safe.txt`. `hmac.compare_digest` pour comparaison en temps constant. | 🔴 CRITIQUE |
| Confirmation à la création | Demander 2 fois le mot de passe lors du premier enregistrement. | 🟠 HAUTE |

> ✅ **Validation :** `this_is_safe.txt` ne contient jamais de texte en clair. Tester refus avec mauvais mot de passe.

---

### Jour 2 — Partie 1 : Hacker marseillais — hashcat + bcrypt

Simuler l'attaque (vol du fichier de mots de passe), puis migrer vers un algorithme robuste avec salage.

| Tâche | Détail | Priorité |
|---|---|---|
| Déchiffrer le MD5 avec hashcat | `hashcat -a 3 -m 0` avec masque `?u?u?l?l?u?u?s` sur `35b95f7c0f63631c453220fb2a86f218`. Commande + résultat dans `md5_decrypted.txt`. | 🔴 CRITIQUE |
| Casser mots de passe courts | Démontrer qu'un mdp ≤ 5 chars se casse en quelques secondes avec hashcat brute-force. | 🟠 HAUTE |
| Remplacer MD5 par bcrypt/argon2 | `bcrypt` ou `argon2-cffi`. Facteur de coût configurable (ex: bcrypt `cost=12`). Stocké dans la table. | 🔴 CRITIQUE |
| Salage 96 bits minimum | `os.urandom(12)` → 12 octets = 96 bits. Sel unique par utilisateur, encodé en base64 dans la table. | 🔴 CRITIQUE |
| Nouveau format de table | `username:algo:cost:salt_b64:hash_b64` — ex: `alice:bcrypt:12:aBcD==:xYz==` | 🟠 HAUTE |

> ✅ **Validation :** 2 users avec le même mdp ont des hashs différents. Montrer qu'hashcat ne peut plus casser un mdp fort en temps raisonnable.

---

### Jour 2 — Partie 2 : Hacker russe — chiffrement symétrique AES

Le hacker a capturé tout le trafic réseau. Chiffrer toutes les communications client ↔ serveur.

| Tâche | Détail | Priorité |
|---|---|---|
| Dérivation de clé (KDF) | PBKDF2 ou scrypt (lib `cryptography` de PyCA) à partir d'un secret saisi par l'utilisateur. Sel dédié ≥ 96 bits par user. | 🔴 CRITIQUE |
| Stockage clé côté serveur | `user_keys_do_not_steal_plz.txt` : `username:kdf_algo:cost:salt_b64:key_b64` | 🟠 HAUTE |
| Stockage clé côté client | `./users/<username>/key.txt` — fichier local uniquement. | 🟠 HAUTE |
| Chiffrement AES par bloc | AES-CBC ou AES-GCM via `cryptography` ou `pycryptodome`. Clé ≥ 128 bits (16 octets). | 🔴 CRITIQUE |
| Chiffrement de tout le trafic | Tous les messages `client→serveur` et `serveur→clients` passent par le chiffrement AES. | 🔴 CRITIQUE |

> ✅ **Validation :** capturer le trafic (Wireshark / tcpdump) — aucun message ne doit être lisible en clair.

### Fichiers produits par Dev 2

- `auth.py` — flux login/register, règles mdp, hash, salage, entropie
- `crypto_sym.py` — KDF (PBKDF2/scrypt) + chiffrement AES (CBC ou GCM)
- `password_rules.json` — règles de mots de passe (modifiable sans redéploiement)
- `this_is_safe.txt` — table des mots de passe (générée auto, gitignorée)
- `user_keys_do_not_steal_plz.txt` — table des clés symétrique (générée auto, gitignorée)
- `md5_decrypted.txt` — preuve de l'attaque hashcat + commande utilisée

---

## 5. 🟣 Branche 3 — Dev 3

**Branche :** `feature/dev3-e2ee-docker`  
**Périmètre :** Crypto asymétrique + E2EE + Dockerisation  
**Prérequis :** branches Dev 1 ET Dev 2 mergées sur `main`

> ℹ️ Dev 3 crée sa branche depuis `main` après les merges de Dev 1 et Dev 2.

### Jour 3 — Partie 1 : Crypto asymétrique (échange de clé)

Éliminer l'échange manuel de clés. Chaque client génère une paire RSA/Ed25519 et utilise la clé publique de l'autre pour chiffrer la clé de session.

| Tâche | Détail | Priorité |
|---|---|---|
| Génération paire de clés | RSA 2048 bits ou Ed25519 via lib `cryptography`. Persistance locale : `<username>.priv` et `<username>.pub`. | 🔴 CRITIQUE |
| Échange de clé de session | Alice génère une clé AES aléatoire, la chiffre avec la clé publique de Bob (RSA-OAEP), envoie via le serveur. | 🔴 CRITIQUE |
| Suppression fichier serveur | Plus de `user_keys_do_not_steal_plz.txt` côté serveur. Les clés ne quittent jamais le client. | 🟠 HAUTE |
| Encapsulation de clé | Réutiliser le module `crypto_sym.py` de la branche 2 avec la nouvelle clé de session échangée. | 🟠 HAUTE |

> ✅ **Validation :** vérifier que le dossier serveur ne contient aucune clé privée ni aucun fichier de clés symétrique.

---

### Jour 3 — Partie 2 : E2EE — Chiffrement de bout en bout (1-1)

Le serveur est compromis (modèle honnête-mais-curieux, comme Signal). Les messages 1-1 ne doivent être lisibles que par les deux participants.

| Tâche | Détail | Priorité |
|---|---|---|
| Annuaire clés publiques | À la connexion, chaque client envoie sa clé publique. Serveur maintient `{username: pub_key}` et le distribue aux clients. | 🔴 CRITIQUE |
| Clé de session par paire | Alice → clé AES aléatoire chiffrée RSA-OAEP avec `pub_key` de Bob → envoi via serveur → Bob déchiffre avec sa `priv_key`. | 🔴 CRITIQUE |
| Messages opaques pour le serveur | Tous les messages 1-1 chiffrés AES (réutiliser `crypto_sym.py`). Le serveur ne loggue que des blobs illisibles. | 🔴 CRITIQUE |
| Signature des messages | Chaque message signé avec `priv_key` de l'expéditeur (RSA-PSS ou Ed25519). Destinataire vérifie avec `pub_key` avant affichage. | 🔴 CRITIQUE |
| Rejet si signature invalide | Si vérification échoue : afficher alerte côté client, rejeter le message silencieusement. | 🟠 HAUTE |

> ✅ **Validation :** altérer manuellement 1 octet dans un message en transit (via un petit proxy Python) et vérifier que le destinataire le rejette.

---

### Jour 3 — Dockerisation

Tout le projet doit fonctionner avec `docker compose up`, sans aucune installation Python locale.

| Tâche | Détail | Priorité |
|---|---|---|
| `Dockerfile` (serveur) | `FROM python:3.11-slim` / `WORKDIR /app` / `COPY requirements.txt .` / `RUN pip install --no-cache-dir -r requirements.txt` / `COPY . .` / `EXPOSE 9000` / `CMD ["python","server.py"]` | 🔴 CRITIQUE |
| `Dockerfile.client` | Même base `python:3.11-slim`. Pas de CMD fixe. Lancement interactif : `stdin_open: true` + `tty: true` dans compose. | 🔴 CRITIQUE |
| `requirements.txt` complet | Toutes les dépendances avec versions fixes : `cryptography`, `bcrypt`, `argon2-cffi`, `colorama`, `python-dotenv`. | 🔴 CRITIQUE |
| `docker-compose.yml` | Service `server` + service `client`. Network bridge `crypto_net`. Volumes : `./logs:/app/logs` et `./users:/app/users`. | 🔴 CRITIQUE |
| `.env` / `.env.example` | Variables `SERVER_HOST`, `SERVER_PORT` (défaut 9000), `LOG_DIR`, `KEY_DIR`. `.env.example` commité, `.env` dans `.gitignore`. | 🟠 HAUTE |
| `DOCKER.md` | Commandes exactes : `docker compose up server` / `docker compose run --rm client`. Guide multi-terminaux. | 🟠 HAUTE |

> ✅ **Validation Docker :** tester depuis un poste vierge (sans Python installé). `docker compose up` doit suffire.

### Fichiers produits par Dev 3

- `crypto_asym.py` — génération paires RSA/Ed25519, RSA-OAEP, signatures PSS/Ed25519
- `e2ee.py` — annuaire clés publiques, établissement clé de session, routage E2EE
- `Dockerfile` — image Python 3.11-slim pour le serveur
- `Dockerfile.client` — image Python 3.11-slim pour le client (interactif)
- `docker-compose.yml` — orchestration complète (server + client + network + volumes)
- `requirements.txt` — à maintenir en sync avec les branches 1 & 2
- `.env.example` — template des variables d'environnement
- `.gitignore` — `.env`, `__pycache__`, `*.priv`, `users/`, `logs/`
- `DOCKER.md` — guide pas-à-pas pour lancer le projet

---

## 6. Structure du projet Python

```
crypto-vibeness/
├── server.py               # 🔵 Serveur TCP multi-clients
├── client.py               # 🔵 Client CLI interactif
├── config.py               # 🔵 DEFAULT_PORT, couleurs, constantes
├── auth.py                 # 🟢 Login, hash bcrypt, salage, entropie
├── crypto_sym.py           # 🟢 KDF + AES (CBC ou GCM)
├── crypto_asym.py          # 🟣 RSA/Ed25519, RSA-OAEP, signatures
├── e2ee.py                 # 🟣 E2EE : annuaire, session keys, vérif
├── password_rules.json     # Règles de mots de passe (modifiable)
├── requirements.txt        # cryptography, bcrypt, colorama...
├── CONTEXT.md              # Contexte pour l'agent IA
├── README.md               # Documentation principale
├── DOCKER.md               # Guide Docker pas-à-pas
├── Dockerfile              # Image Python 3.11-slim — serveur
├── Dockerfile.client       # Image Python 3.11-slim — client
├── docker-compose.yml      # Orchestration complète
├── .env.example            # Template variables d'environnement
├── .gitignore              # .env, __pycache__, *.priv, users/, logs/
├── logs/                   # log_YYYY-MM-DD_HH-MM-SS.txt (gitignored)
└── users/                  # Clés par utilisateur (gitignored)
    └── <username>/
        ├── key.txt         # Clé AES locale
        ├── <username>.priv # Clé privée RSA/Ed25519
        └── <username>.pub  # Clé publique RSA/Ed25519
```

### Dépendances Python recommandées

| Package | Usage | Branche |
|---|---|---|
| `colorama` | Couleurs dans le terminal CLI | 🔵 Dev 1 |
| `bcrypt` | Hash des mots de passe avec facteur de coût | 🟢 Dev 2 |
| `argon2-cffi` | Alternative à bcrypt (finaliste NIST) | 🟢 Dev 2 |
| `cryptography` | AES, RSA, Ed25519, PBKDF2, HKDF (lib PyCA) | 🟢 Dev 2 + 🟣 Dev 3 |
| `python-dotenv` | Lecture du fichier `.env` | 🟣 Dev 3 |

> ⚠️ **Jamais** `pycrypto` (dépréciée et non maintenue). Utiliser `pycryptodome` si besoin, mais préférer `cryptography` (PyCA) en priorité.

---

## 7. Workflow Git

### Règles de collaboration

1. `main` est protégé — aucun commit direct. Tout passe par des Pull Requests reviewées.
2. **Ordre de merge strict :** Dev 1 → Dev 2 → Dev 3 (chaque branche dépend de la précédente).
3. Commiter à chaque étape validée — pas de mega-commit en fin de journée.
4. Dev 2 et Dev 3 rebasent sur `main` après chaque merge précédent.
5. Le code est intégralement en **anglais** (variables, fonctions, commentaires). Les prompts peuvent être en français.
6. Chaque PR inclut un script `test_<feature>.py` démontrant que la feature fonctionne.

### Planning indicatif

|  | 🔵 Dev 1 | 🟢 Dev 2 | 🟣 Dev 3 |
|---|---|---|---|
| **J1 AM** | Serveur TCP + rooms + CLI | Setup branche + lecture code Dev 1 | Setup branche + Docker hello world |
| **J1 PM** | Couleurs + timestamps + logs → PR | Auth + MD5 + entropie | Dockeriser serveur + client (base) |
| **J2 AM** | Tests & correctifs → merge main | hashcat + bcrypt + salage → PR | Paires RSA/Ed25519 + échange de clé |
| **J2 PM** | Support intégration Dev 2 & 3 | Chiffrement AES complet → merge | Clés de session + encapsulation |
| **J3 AM** | Review PR Dev 2 & 3 | Tests intégration + review | E2EE + signatures + rejet |
| **J3 PM** | Préparation soutenance | Préparation soutenance | Docker final + DOCKER.md → merge |

---

## 8. Bonnes pratiques Agent IA

Vous utilisez un **agent IA** (Claude Code, Copilot CLI…) — pas un chatbot. Ces pratiques sont essentielles.

| Branche | Pratique | Détail | Priorité |
|---|---|---|---|
| 🔵 Dev 1 | Créer `CONTEXT.md` dès J1 | Décrire l'architecture, les fichiers clés, les conventions de code, les contraintes réseau. L'agent lit ce fichier à chaque session. | 🔴 CRITIQUE |
| 🟢 Dev 2 | Spécifier les libs Python exactes | Ne pas laisser l'agent choisir. Dire : `utilise la lib cryptography de PyCA, pas pycrypto`. Mentionner les versions dans `requirements.txt`. | 🟠 HAUTE |
| 🟣 Dev 3 | Tester avant chaque PR | Demander à l'agent d'écrire `test_<feature>.py`. Lancer `python test_auth.py`, `test_crypto_sym.py`... avant tout merge. | 🟠 HAUTE |
| 🔵 Dev 1 | Travailler dans un venv | `python -m venv .venv && source .venv/bin/activate`. Ou directement via Docker. | 🟠 HAUTE |
| 🟢 Dev 2 | LLM comme tuteur crypto | Demander à Claude/ChatGPT d'expliquer un concept **avant** d'implémenter. Ex: *"explique-moi ce qu'est un IV en AES-CBC"*. | 🟠 HAUTE |
| 🟣 Dev 3 | Mettre à jour `CONTEXT.md` | Après chaque étape validée, mettre à jour `CONTEXT.md` pour refléter l'état actuel. L'agent a besoin de contexte frais. | 🟠 HAUTE |

---

## 9. Ressources

- **hashcat** — Outil de cracking de hash — requis pour la partie hacker marseillais
- **Crypto 101** — Cours essentiel sur les primitives cryptographiques (hash, sym, asym)
- **cryptography (PyCA)** — La bibliothèque Python recommandée pour AES, RSA, Ed25519, KDF
- **bcrypt / argon2-cffi** — Bibliothèques pour le hash de mots de passe avec facteur de coût
- **xkcd #936** — Entropie des mots de passe — incontournable pour la section entropie
- **Latacora — crypto guide** — Les bons réflexes en cryptographie moderne
- **Don't roll your own crypto** — La règle d'or — sauf pour apprendre, bien sûr !

---

> *"Don't roll your own crypto"* — sauf si c'est pour apprendre, bien sûr !  
> **Crypto Vibeness — La Plateforme**
