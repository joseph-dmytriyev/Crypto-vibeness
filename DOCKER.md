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
│ └─ logs/         │  ├─ logs/            │
│                  │  └─ users/           │
│                  │                      │
└──────────────────┴──────────────────────┘
```

**Services :**
- **`server`** — Serveur TCP multi-clients (asyncio) portant sur port 9000
- **`client`** — Client CLI interactif (stdin/stdout ouvert)

**Volumes partagés :**
- `./logs/` — Logs horodatés côté serveur
- `./users/` — Clés cryptographiques côté client (`.priv`, `.pub`, `key.txt`)

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

## Diagnostic & Troubleshooting (Production)

### Status de tous les services
```bash
docker compose ps
```
Expected output:
```
NAME                        STATUS            PORTS
crypto_vibeness_server      Up (healthy)      0.0.0.0:9000->9000/tcp
crypto_vibeness_client      Up                (stdin open)
```

### Logs en temps réel
```bash
# Server logs
docker compose logs -f server

# Client logs
docker compose logs -f client

# All logs with timestamps
docker compose logs --timestamps
```

### Inspecter les conteneurs
```bash
# Check server health status
docker compose exec server curl -s http://localhost:9000/health 2>/dev/null || \
  python -c "import socket; socket.create_connection(('localhost', 9000))"

# Check running processes inside server
docker compose exec server ps aux

# Check user privileges (should be UID 1000, not 0)
docker compose exec server id

# Check volume mounts and permissions
docker compose exec server ls -la /app/logs
docker compose exec client ls -la /app/users
```

### Test de rejet de signature (Tampering Detection)

Pour vérifier que les signatures RSA-PSS rejettent les messages altérés :

```bash
docker compose exec -T server python << 'EOF'
import sys
sys.path.insert(0, '/app')
from e2ee import E2EEManager
from crypto_asym import AsymmetricKeyManager
import json
import base64

# Setup: Alice and Bob exchange keys
alice_km = AsymmetricKeyManager('test_alice')
bob_km = AsymmetricKeyManager('test_bob')
alice_e2ee = E2EEManager()
bob_e2ee = E2EEManager()

alice_e2ee.register_public_key('test_bob', bob_km.get_public_key_pem().decode())
bob_e2ee.register_public_key('test_alice', alice_km.get_public_key_pem().decode())

# Alice sends a signed + encrypted message
original_msg = "Sensitive data: account balance 1000 EUR"
e2ee_msg = alice_e2ee.prepare_e2ee_message('test_alice', 'test_bob', original_msg)
print(f"✓ Original message signed & encrypted")

# Simulate tampering: modify the ciphertext
msg_dict = json.loads(e2ee_msg)
tampered_ct = base64.b64encode(
    base64.b64decode(msg_dict['ciphertext'])[:-8] + b'HACKED!!'
).decode()
msg_dict['ciphertext'] = tampered_ct
tampered_msg = json.dumps(msg_dict)
print(f"✓ Message tampered in transit")

# Bob tries to receive tampered message
try:
    result = bob_e2ee.receive_e2ee_message('test_alice', tampered_msg)
    print(f"✗ SECURITY FAILURE: Tampered message was accepted!")
    sys.exit(1)
except Exception as e:
    print(f"✓ SECURITY SUCCESS: Tampered message rejected")
    print(f"  Reason: {str(e)[:60]}...")

# Verify legitimate message still works
decrypted = bob_e2ee.receive_e2ee_message('test_alice', e2ee_msg)
assert decrypted == original_msg
print(f"✓ Legitimate message verified & decrypted successfully")
EOF
```

Expected output:
```
✓ Original message signed & encrypted
✓ Message tampered in transit
✓ SECURITY SUCCESS: Tampered message rejected
  Reason: Decryption failed: invalid ciphertext...
✓ Legitimate message verified & decrypted successfully
```

### Vérifier la persistance des clés
```bash
# List generated keys
ls -lh users/

# Verify key formats
file users/alice/alice.priv   # Should be PEM text
file users/alice/alice.pub    # Should be PEM text
file users/alice/key.txt      # Should be binary (AES-256 key)
```

### Benchmark de performance
```bash
# Measure server startup time
time docker compose up -d server

# Measure healthcheck response time
time docker compose exec server python -c \
  "import socket; s = socket.socket(); s.connect(('localhost', 9000)); s.close()"

# Measure encryption/decryption latency
docker compose exec -T server python << 'EOF'
import time
from crypto_sym import SymmetricEncryption
from crypto_asym import AsymmetricKeyManager

# E2EE performance: RSA-OAEP key encapsulation
km = AsymmetricKeyManager('bench_user')
msg = "X" * 1000

start = time.time()
for _ in range(100):
    km.encrypt_session_key(km.public_key)
elapsed = time.time() - start
print(f"RSA-OAEP (100 iterations): {elapsed*1000:.2f}ms ({elapsed*10:.2f}ms per op)")

# AES-256-GCM symmetric encryption
se = SymmetricEncryption()
key = se.generate_session_key()

start = time.time()
for _ in range(1000):
    se.encrypt_message(msg, key)
elapsed = time.time() - start
print(f"AES-256-GCM (1000 iterations): {elapsed*1000:.2f}ms ({elapsed:.3f}ms per op)")
EOF
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

## Production Deployment Checklist

### Security Hardening
- [x] **Non-root user**: Containers run as UID 1000 (`appuser`), not root
- [x] **Volume isolation**: 
  - `logs/` mounted RW for logging
  - `users/` mounted only on client (private keys never exposed to server container)
  - Client can access both RW for key generation
- [x] **Network isolation**: Dedicated bridge network `crypto_net` (subnet: 172.28.0.0/16)
- [x] **Dependency pinning**: Exact versions in requirements.txt to prevent supply chain attacks
- [x] **Healthchecks**: Server validates port 9000 listening every 10s (15s startup grace)
- [ ] **TLS/HTTPS**: Requires reverse proxy (nginx) for encryption in transit
- [ ] **Secrets management**: Use Docker secrets or Vault instead of .env in production

### Performance & Resource Management
```yaml
# Recommended docker-compose additions for production:
services:
  server:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M

  client:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

### Monitoring & Logging
- **Container logs**: Use `docker compose logs` or centralized logging (ELK, Datadog)
- **Performance metrics**: Monitor CPU, memory, disk I/O with `docker stats`
- **Audit logs**: All messages are signed and timestamped in `/logs/`
- **Key rotation**: Plan rotation strategy for RSA/Ed25519 keys (currently: manual)

### Deployment Steps
```bash
# 1. Pre-deployment validation
./smoke_test.sh

# 2. Build optimized images
docker compose build --no-cache

# 3. Push to registry (if multi-host)
docker tag crypto_vibeness_server myregistry/crypto-vibeness:v1.0
docker push myregistry/crypto-vibeness:v1.0

# 4. Deploy with docker compose (single host) or Kubernetes
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 5. Verify health
docker compose ps
docker compose logs -f server
```

### Rollback Procedure
```bash
# If deployment fails, rollback to previous version:
git checkout v0.9 -- Dockerfile Dockerfile.client docker-compose.yml
docker compose down
docker compose up -d
```


---

## Références

- **Docker Compose docs :** https://docs.docker.com/compose/
- **Crypto Vibeness CONTEXT.md** — Architecture complète du projet
- **PRD.md** — Product requirements et planification

---

**Crypto Vibeness — La Plateforme**  
*Don't roll your own crypto — sauf si c'est pour apprendre !* 🎓
