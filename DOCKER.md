# 🐳 Crypto Vibeness — Docker Guide

Guide complet pour lancer **Crypto Vibeness** (chat chiffré CLI) avec Docker Compose.

---

## Prérequis

- ✅ Docker Desktop ou Docker Engine installé
- ✅ Docker Compose (v2.x+)
- ✅ Pas besoin d'installer Python localement (tout se passe dans les conteneurs)

---

## Démarrage rapide

### 1️⃣ **Copier le fichier `.env`**

```bash
cp .env.example .env
```

(Optionnel : modifiez les variables si nécessaire)

### 2️⃣ **Démarrer le serveur**

```bash
docker compose up server
```

Le serveur démarre sur `0.0.0.0:9000` et affiche :
```
[2026-04-14 10:00:00] Server listening on 0.0.0.0:9000...
```

**Gardez ce terminal ouvert.**

### 3️⃣ **Démarrer le client (dans un nouveau terminal)**

```bash
docker compose run --rm client
```

Ou depuis un autre terminal :

```bash
docker compose up client
```

Entrez votre `username` et continuez comme d'habitude.

---

## Commandes courantes

### Démarrer tout en arrière-plan
```bash
docker compose up -d
```

### Arrêter tous les services
```bash
docker compose down
```

### Voir les logs du serveur
```bash
docker compose logs -f server
```

### Voir les logs du client
```bash
docker compose logs -f client
```

### Réinitialiser (supprimer volumes et données)
```bash
docker compose down -v
```

> ⚠️ Cela supprime les fichiers dans `logs/` et `users/`

---

## Architecture

```
┌─────────────────────────────────────────┐
│        Docker Compose Network           │
│         (crypto_net bridge)             │
├──────────────────┬──────────────────────┤
│                  │                      │
│    server        │    client ×N         │
│ (Port 9000)      │  (Interactive CLI)   │
│ ├─ logs/         │  ├─ logs/            │
│ └─ users/        │  └─ users/           │
│                  │                      │
└──────────────────┴──────────────────────┘
```

**Services :**
- **`server`** — Serveur TCP multi-clients (asyncio) portant sur port 9000
- **`client`** — Client CLI interactif (stdin/stdout ouvert)

**Volumes partagés :**
- `./logs/` — Logs horodatés côté serveur
- `./users/` — Clés cryptographiques par utilisateur (`.priv`, `.pub`, `key.txt`)

**Networking :**
- Bridge network `crypto_net` — les services communiquent par nom de conteneur

---

## Multi-clients (Scénario de test)

### Terminal 1 — Démarrer le serveur
```bash
docker compose up server
```

### Terminal 2 — Client Alice
```bash
docker compose run --rm -e "USER=alice" client
```

### Terminal 3 — Client Bob
```bash
docker compose run --rm -e "USER=bob" client
```

Les deux clients se connectent au même serveur et peuvent échanger des messages.

---

## Fichier `.env`

Variables de configuration (voir `.env.example`) :

```bash
# Serveur
SERVER_HOST=localhost       # localhost pour dev, 0.0.0.0 en Docker
SERVER_PORT=9000           # Port TCP du serveur

# Répertoires
LOG_DIR=./logs              # Logs horodatés
KEY_DIR=./users             # Clés publiques/privées par user

# Crypto
CRYPTO_ALGORITHM=rsa        # "rsa" (défaut) ou "ed25519"
```

---

## Vérification de la santé

### Le serveur est-il up?
```bash
docker compose logs server | tail -10
```

### Les clients se connectent-ils?
```bash
docker compose logs client
```

### Vérifier les fichiers de clés
```bash
ls -la users/
ls -la logs/
```

---

## Troubleshooting

### Le serveur ne démarre pas
```bash
docker compose up server --build
```

(Force le rebuild de l'image)

### Les clients ne voient pas le serveur
Vérifiez que le serveur est sain :
```bash
docker compose ps
```

Doit afficher `STATUS: Up (healthy)` pour le serveur.

### Permission denied sur les volumes
```bash
sudo chown -R $USER:$USER logs/ users/
```

### Réinitialiser complètement
```bash
docker compose down -v
docker system prune -a
docker compose up --build server
```

---

## Tests automatisés

À l'intérieur du conteneur serveur ou client, lancer :

```bash
docker compose run --rm server python test_crypto_asym.py
docker compose run --rm server python test_e2ee.py          # Phase 2
```

---

## Structure des répertoires en Docker

```
./
├── server.py              # Serveur TCP
├── client.py              # Client CLI
├── crypto_asym.py         # Crypto asymétrique (RSA/Ed25519)
├── e2ee.py                # E2EE (Phase 2)
├── crypto_sym.py          # Crypto symétrique (AES) — Dev 2
├── auth.py                # Auth + hash mots de passe — Dev 2
├── Dockerfile             # Image serveur
├── Dockerfile.client      # Image client
├── docker-compose.yml     # Orchestration
├── requirements.txt       # Dépendances Python
├── .env                   # Configuration (local, gitignored)
├── .env.example           # Template .env (commité)
├── logs/                  # Logs serveur (gitignored, créé auto)
└── users/                 # Clés utilisateurs (gitignored, créé auto)
    └── <username>/
        ├── username.priv  # Clé privée RSA/Ed25519
        ├── username.pub   # Clé publique RSA/Ed25519
        └── key.txt        # Clé AES locale (symétrique)
```

---

## Déploiement en production

⚠️ Pour production, ajouter :

1. **Secrets management** — Utiliser Docker secrets ou Vault
2. **TLS/HTTPS** — Proxy reverse (nginx) devant le serveur
3. **Healthchecks** — Vérifié dans `docker-compose.yml`
4. **Resource limits** — CPU/mémoire
5. **Logging centralisé** — ELK, Grafana, etc.

---

## Références

- **Docker Compose docs :** https://docs.docker.com/compose/
- **Crypto Vibeness CONTEXT.md** — Architecture complète du projet
- **PRD.md** — Product requirements et planification

---

**Crypto Vibeness — La Plateforme**  
*Don't roll your own crypto — sauf si c'est pour apprendre !* 🎓
