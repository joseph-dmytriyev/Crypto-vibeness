# Crypto Vibeness

> Système de chat sécurisé en Python — construit progressivement avec un agent IA (vibe coding)

**La Plateforme** — Groupe de 3 | Python 3.11 | Dockerisé

---

## Vue d'ensemble

Ce projet implémente un système de chat CLI multi-utilisateurs qui se sécurise progressivement au fil des jours :

| Jour | Partie | Ce qui est ajouté |
|------|--------|-------------------|
| J1 | P1 | Serveur IRC multi-clients, rooms, couleurs, logs |
| J1 | P2 | Authentification + mots de passe hashés (MD5) |
| J2 | P1 | Attaque hashcat + migration bcrypt + salage 96 bits |
| J2 | P2 | Chiffrement symétrique AES de tout le trafic |
| J3 | P1 | Crypto asymétrique — paires RSA/Ed25519, échange de clé |
| J3 | P2 | Chiffrement de bout en bout (E2EE) + signatures |

---

## Lancement rapide

### Sans Docker (développement local)

```bash
# 1. Créer l'environnement virtuel
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer le serveur (terminal 1)
python server.py
# ou sur un port spécifique :
python server.py 9001

# 4. Lancer un client (terminal 2, 3, ...)
python client.py
# ou en précisant host et port :
python client.py localhost 9001
```

### Avec Docker (recommandé)

Voir [DOCKER.md](DOCKER.md) pour les instructions complètes.

```bash
# Lancer le serveur
docker compose up server

# Lancer un client (dans un nouveau terminal)
docker compose run --rm client
```

---

## Structure du projet

```
crypto-vibeness/
├── server.py                  # Serveur TCP multi-clients (Dev 1)
├── client.py                  # Client CLI interactif (Dev 1)
├── config.py                  # Constantes globales (Dev 1)
├── auth.py                    # Authentification + hash + salage (Dev 2)
├── crypto_sym.py              # KDF + chiffrement AES (Dev 2)
├── crypto_asym.py             # RSA / Ed25519 + signatures (Dev 3)
├── e2ee.py                    # Chiffrement bout en bout 1-1 (Dev 3)
├── password_rules.json        # Règles de mots de passe
├── requirements.txt           # Dépendances Python
├── CONTEXT.md                 # Contexte pour l'agent IA
├── README.md                  # Ce fichier
├── DOCKER.md                  # Guide Docker
├── Dockerfile                 # Image Python serveur
├── Dockerfile.client          # Image Python client
├── docker-compose.yml         # Orchestration
├── .env.example               # Template variables d'environnement
├── .gitignore
├── logs/                      # Fichiers de logs (gitignored)
└── users/                     # Clés par utilisateur (gitignored)
    └── <username>/
        ├── key.txt            # Clé symétrique locale
        ├── <username>.priv    # Clé privée RSA/Ed25519
        └── <username>.pub     # Clé publique RSA/Ed25519
```

---

## Commandes du chat

Une fois connecté, les commandes disponibles sont :

| Commande | Description |
|----------|-------------|
| `/join <room>` | Rejoindre une room existante |
| `/join <room> <password>` | Rejoindre une room protégée |
| `/create <room>` | Créer une room publique |
| `/create <room> <password>` | Créer une room protégée (affichée avec 🔒) |
| `/list` | Lister toutes les rooms disponibles |
| `/dm <username> <message>` | Envoyer un message privé (E2EE) |
| `/quit` | Se déconnecter |

---

## Branches GitHub

| Branche | Responsable | Périmètre |
|---------|-------------|-----------|
| `feature/dev1-core-network` | Dev 1 | `server.py`, `client.py`, `config.py` |
| `feature/dev2-auth-crypto` | Dev 2 | `auth.py`, `crypto_sym.py`, `password_rules.json` |
| `feature/dev3-e2ee-docker` | Dev 3 | `crypto_asym.py`, `e2ee.py`, Docker |

**Ordre de merge :** Dev 1 → Dev 2 → Dev 3

---

## Dépendances Python

```
colorama        # Couleurs dans le terminal
cryptography    # AES, RSA, Ed25519, PBKDF2 (lib PyCA — recommandée)
bcrypt          # Hash des mots de passe avec facteur de coût
argon2-cffi     # Alternative à bcrypt (finaliste NIST)
python-dotenv   # Lecture du fichier .env
```

> **Note :** Ne jamais utiliser `pycrypto` (dépréciée). Utiliser `pycryptodome` si besoin, mais préférer `cryptography` (PyCA).

---

## Fichiers générés automatiquement (gitignorés)

| Fichier | Contenu |
|---------|---------|
| `this_is_safe.txt` | Table des mots de passe : `username:algo:cost:salt_b64:hash_b64` |
| `user_keys_do_not_steal_plz.txt` | Table des clés symétrique (supprimé au Jour 3) |
| `logs/log_YYYY-MM-DD_HH-MM-SS.txt` | Logs horodatés du serveur |
| `users/<username>/key.txt` | Clé AES locale du client |
| `users/<username>/<username>.priv` | Clé privée RSA/Ed25519 |
| `users/<username>/<username>.pub` | Clé publique RSA/Ed25519 |

---

## Avertissement

> Ce projet est un exercice pédagogique. Les systèmes cryptographiques implémentés sont volontairement simplifiés.  
> **Ne pas utiliser en production.** Suivre la règle d'or : *"Don't roll your own crypto"*.
