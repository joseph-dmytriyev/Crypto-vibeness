# CONTEXT — Crypto Vibeness

> Ce fichier est lu par l'agent IA à chaque session de travail.
> Le mettre à jour après chaque étape validée.

---

## Projet

Système de chat CLI sécurisé en Python, construit progressivement par 3 développeurs sur 3 branches GitHub distinctes. Dockerisé. Pas d'interface graphique — tout se passe dans le terminal.

**École :** La Plateforme  
**Équipe :** 3 développeurs (Dev 1, Dev 2, Dev 3)  
**Repo :** `crypto-vibeness`

---

## Architecture

```
client.py  ←──── TCP port 9000 ────→  server.py
   │                                       │
   ├── auth.py          (Dev 2)            ├── auth.py
   ├── crypto_sym.py    (Dev 2)            ├── crypto_sym.py
   ├── crypto_asym.py   (Dev 3)            ├── crypto_asym.py
   └── e2ee.py          (Dev 3)            └── e2ee.py
```

Le serveur est **honnête-mais-curieux** (modèle Signal) : il route les messages fidèlement mais ne doit pas pouvoir lire les messages 1-1 (E2EE).

---

## Branches et responsabilités

| Branche | Dev | Fichiers produits |
|---------|-----|-------------------|
| `feature/dev1-core-network` | Dev 1 | `server.py`, `client.py`, `config.py` |
| `feature/dev2-auth-crypto` | Dev 2 | `auth.py`, `crypto_sym.py`, `password_rules.json` |
| `feature/dev3-e2ee-docker` | Dev 3 | `crypto_asym.py`, `e2ee.py`, `Dockerfile`, `docker-compose.yml` |

**Ordre de merge strict :** Dev 1 → Dev 2 → Dev 3

---

## Fichiers clés et leur rôle

### `server.py` (Dev 1)
- Serveur TCP multi-clients avec `asyncio` ou `threading`
- Gestion des rooms (room `general` par défaut)
- Broadcast des messages aux membres d'une room
- Logs horodatés dans `logs/log_YYYY-MM-DD_HH-MM-SS.txt`
- Routage des messages E2EE (blobs opaques — ne pas essayer de les déchiffrer)

### `client.py` (Dev 1)
- Client CLI interactif
- Couleurs déterministes via `hash(username) % nb_couleurs` (colorama)
- Timestamps `[HH:MM:SS]` sur chaque message
- Commandes : `/join`, `/create`, `/list`, `/dm`, `/quit`

### `config.py` (Dev 1)
- `DEFAULT_PORT = 9000`
- `DEFAULT_HOST = "localhost"`
- `COLORS = [...]` — liste des couleurs disponibles (colorama)
- Toutes les constantes globales du projet

### `auth.py` (Dev 2)
- Flux login / register avant l'accès au chat
- Hash des mots de passe : **bcrypt** ou **argon2-cffi** (jamais MD5 après le Jour 2)
- Salage : `os.urandom(12)` → 96 bits minimum, encodé en base64
- Format stockage : `username:algo:cost:salt_b64:hash_b64`
- Comparaison en temps constant : `hmac.compare_digest()`
- Règles de mots de passe lues depuis `password_rules.json`
- Indicateur de force : entropie Shannon → Faible / Moyen / Fort

### `crypto_sym.py` (Dev 2)
- Dérivation de clé : **PBKDF2** ou **scrypt** (lib `cryptography` de PyCA)
- Sel KDF : `os.urandom(12)` → 96 bits minimum
- Chiffrement : **AES-GCM** ou AES-CBC (lib `cryptography`)
- Clé : 128 bits minimum (16 octets)
- Stockage serveur : `user_keys_do_not_steal_plz.txt`
- Stockage client : `users/<username>/key.txt`

### `crypto_asym.py` (Dev 3)
- Génération paires de clés : **RSA 2048 bits** ou **Ed25519** (lib `cryptography`)
- Persistance : `users/<username>/<username>.priv` et `.pub`
- Chiffrement asymétrique : **RSA-OAEP** pour encapsuler la clé de session
- Signatures : **RSA-PSS** ou **Ed25519**

### `e2ee.py` (Dev 3)
- Annuaire `{username: public_key}` côté serveur (distribué aux clients)
- Établissement clé de session par paire (Alice → chiffre avec pub_key Bob)
- Messages 1-1 chiffrés AES avec la clé de session
- Signature de chaque message avec priv_key de l'expéditeur
- Vérification + rejet si signature invalide

---

## Contraintes techniques — À respecter absolument

### Bibliothèques autorisées
```
cryptography    # PRIORITÉ 1 — AES, RSA, Ed25519, KDF, signatures
bcrypt          # Hash mots de passe
argon2-cffi     # Alternative bcrypt
colorama        # Couleurs terminal
python-dotenv   # Lecture .env
```

> **JAMAIS** `pycrypto` (dépréciée, failles connues).  
> `pycryptodome` accepté en dernier recours uniquement.

### Algorithmes imposés
- Hash mots de passe : **bcrypt** (cost ≥ 10) ou **argon2id**
- KDF : **PBKDF2-HMAC-SHA256** (iterations ≥ 100000) ou **scrypt**
- Chiffrement symétrique : **AES-GCM** (préféré) ou AES-CBC avec padding PKCS7
- Chiffrement asymétrique : **RSA-OAEP** avec SHA-256
- Signatures : **RSA-PSS** ou **Ed25519**
- Sel : toujours `os.urandom(12)` minimum (96 bits)

### Ce qui est interdit
- Stocker des mots de passe ou clés en clair
- Utiliser MD5 ou SHA-1 pour le hash de mots de passe
- Utiliser AES-ECB (pas d'IV = patterns visibles)
- Réutiliser un IV/nonce pour AES-GCM
- Clés en dur dans le code (`hardcoded secrets`)

### Conventions de code
- Tout le code en **anglais** (variables, fonctions, commentaires, docstrings)
- Les prompts à l'agent peuvent être en français
- `snake_case` pour les fonctions et variables
- Docstrings sur toutes les fonctions publiques
- Pas de `print()` de debug laissé en production — utiliser le logger

---

## État actuel du projet

> **Mettre à jour cette section après chaque étape validée.**

```
[ ] Jour 1 — Partie 1 : Serveur IRC de base        (Dev 1)
[ ] Jour 1 — Partie 2 : Authentification MD5        (Dev 2)
[ ] Jour 2 — Partie 1 : hashcat + bcrypt + salage   (Dev 2)
[ ] Jour 2 — Partie 2 : Chiffrement AES             (Dev 2)
[ ] Jour 3 — Partie 1 : Crypto asymétrique          (Dev 3)
[ ] Jour 3 — Partie 2 : E2EE + signatures           (Dev 3)
[ ] Jour 3 — Docker                                 (Dev 3)
```

---

## Format des fichiers de données

### `this_is_safe.txt`
```
alice:bcrypt:12:aBcDeFgHiJkL==:xYz1234567890abcdef==
bob:argon2id:3:mNoPqRsTuVwX==:abcdef1234567890xyz==
```

### `user_keys_do_not_steal_plz.txt` (supprimé au Jour 3)
```
alice:pbkdf2:100000:aBcDeFgHiJkL==:clé_aes_b64==
```

### `password_rules.json`
```json
{
  "rules": [
    {"type": "min_length", "value": 8, "message": "Au moins 8 caractères"},
    {"type": "has_digit", "message": "Au moins 1 chiffre"},
    {"type": "has_upper", "message": "Au moins 1 majuscule"}
  ]
}
```

---

## Instructions pour l'agent IA

1. **Toujours lire ce fichier en début de session** avant d'écrire du code
2. Utiliser **uniquement les bibliothèques listées** dans "Bibliothèques autorisées"
3. Respecter les **algorithmes imposés** — ne pas choisir librement
4. Écrire un fichier `test_<feature>.py` pour chaque feature implémentée
5. Mettre à jour la section **État actuel** après chaque étape validée
6. Ne jamais modifier les fichiers d'une autre branche sans accord de l'équipe
7. En cas de doute sur un concept crypto, demander une explication avant d'implémenter
