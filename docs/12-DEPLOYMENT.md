# 12. Deployment & Local Operations Guide

## Overview
Ospysin is designed to deploy seamlessly on a local developer workstation or dedicated internal audit appliance using **Docker Compose** and a host-managed **Ollama** inference engine.

---

## Prerequisites
1. **Operating System**: Windows 10/11 (with WSL2), Linux (Ubuntu 22.04+), or macOS (Apple Silicon / Intel).
2. **Docker & Docker Compose**: Docker Desktop 4.28+ or Docker Engine 26+.
3. **Ollama**: Installed natively on host (enables native GPU acceleration with CUDA, ROCm, or Metal).

---

## Step-by-Step Setup

### 1. Download & Pull Local AI Model
Install Ollama from [ollama.com](https://ollama.com). Open your terminal and pull the pinned cybersecurity model artifact directly from Hugging Face:

```bash
# Pull and start the pinned Dolphin3-Cyber (8B Q4_K_M GGUF) checkpoint
ollama run hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M
```

*Note on Model Provenance*: This model is a community-hosted GGUF quantized fine-tune hosted on Hugging Face by `RavichandranJ`, built on the Meta Llama-3.1-8B-Instruct architecture and Dolphin dataset. It requires ~5 GB of RAM/VRAM.

Verify that Ollama responds locally:
```bash
curl http://localhost:11434/api/tags
```

---

### 2. Configure Environment Variables
Copy the environment template in `infra/`:

```bash
cd infra
cp .env.example .env
```

Review critical parameters in `infra/.env`:
```ini
APP_ENV=local
SERVER_PORT=8080
# Mandatory default: 127.0.0.1 for local isolation.
APP_BIND_HOST=127.0.0.1
POSTGRES_DB=ospysin
POSTGRES_USER=ospysin_admin
POSTGRES_PASSWORD=your_secure_password_here
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=hf.co/RavichandranJ/Dolphin3-Cyber-8B-GGUF:Q4_K_M
DEFAULT_AUDIT_MODE=LOCAL
```

---

### 3. Launch the Stack with Docker Compose
Start PostgreSQL, Backend, and Frontend containers:

```bash
docker-compose up -d --build
```

Monitor container health:
```bash
docker-compose ps
```

- **Frontend UI**: `http://127.0.0.1:5173`
- **Backend API & Health**: `http://127.0.0.1:8080/api/health`
- **PostgreSQL**: `127.0.0.1:5432`

---

### 4. First-Run Initialization
On first boot:
- Flyway automatically applies all schema migrations from `V1__init_schema.sql`.
- Default administrative credentials (`admin`) are initialized with the password configured in `ADMIN_INITIAL_PASSWORD` (or securely generated and output to console on startup), hashed via Argon2id.
- Backend verifies connectivity to Ollama via `http://host.docker.internal:11434`.

---

## LAN & Remote Mode Configuration (Auditing Staging Networks)
By default, all containers publish ports strictly on the loopback adapter (`127.0.0.1`) to prevent unauthorized network access.

To permit team members on the same local network to access the workbench:
1. Set `APP_BIND_HOST=0.0.0.0` in `infra/.env`.
2. **SECURITY REQUIREMENT**: When exposed on non-loopback interfaces, you **MUST** deploy an authenticating TLS reverse proxy (e.g., Caddy or NGINX with HTTPS) in front of Ospysin. Never expose unencrypted plain HTTP authentication over an untrusted LAN or WAN.
3. Configure `COOKIE_SECURE=true` so that the `JSESSIONID` cookie is enforced with `Secure; SameSite=Strict; HttpOnly`.
4. Ensure host firewall rules permit inbound connections only from trusted management subnets.

---

## Backup & Disaster Recovery

### PostgreSQL Backup
```bash
docker exec -t ospysin-postgres pg_dump -U ospysin_admin -d ospysin -F c -b -v -f /tmp/backup.dump
docker cp ospysin-postgres:/tmp/backup.dump ./ospysin_backup_$(date +%Y%m%d).dump
```

### PostgreSQL Restore
```bash
docker cp ./ospysin_backup.dump ospysin-postgres:/tmp/backup.dump
docker exec -t ospysin-postgres pg_restore -U ospysin_admin -d ospysin -c -v /tmp/backup.dump
```

---

## Log Rotation & Maintenance
Docker Compose logs are bounded by container log drivers:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "20m"
    max-file: "5"
```
To purge orphaned volumes during deep maintenance:
```bash
docker-compose down -v  # WARNING: Deletes local database volumes!
```
