<div align="center">

# 🛡️ Project Sentinel XDR

**AI-Powered Extended Detection & Response Platform**

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=flat&logo=nextdotjs)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

*Real-time threat detection · AI behavioral analysis · Automated response*

</div>

---

## 📖 Overview

**Project Sentinel** is a fully open-source XDR (Extended Detection & Response) platform built as a computer engineering graduation project. It deploys lightweight C agents on Windows and Linux endpoints, streams kernel-level telemetry to a central Go server, analyzes events with a multi-layer AI engine, and responds to threats automatically — all with zero commercial licensing costs.

> **Academic context:** Designed and implemented as a university graduation project to demonstrate a production-grade security platform using modern open-source technologies.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🖥️ **Dual-Platform Agents** | Lightweight C agents for Linux (eBPF/Netlink) and Windows (ETW/Schannel) |
| 🔒 **Layered Encryption** | All agent↔server traffic is XOR-encrypted + TLS 1.2/1.3 wrapped |
| 🧠 **Hybrid AI Detection** | Rule engine (20+ threat categories) + Isolation Forest behavioral baseline |
| 🖼️ **Static PE Analysis** | Malware visualization (Nataraj method) + EfficientNet-B0 CNN classification |
| ⚡ **Automated Response** | `kill_process` / `quarantine_file` / `block_firewall` triggered at score ≥ 90 |
| 📡 **Kernel Telemetry** | Linux Netlink CN_IDX_PROC + Windows ETW ring-0 event streams |
| 🔍 **Threat Intelligence** | Built-in malware hash DB + VirusTotal API v3 integration + YARA scanning |
| 📊 **SOC Dashboard** | Real-time Next.js dashboard with agent management, alert timeline, terminal |
| 📝 **KQL Rule Engine** | Custom detection rules with Kusto Query Language syntax |
| 🎯 **Behavioral Calibration** | Per-agent IsolationForest model trained on normal-usage baseline |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SENTINEL XDR PLATFORM                        │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │  Linux Agent │    │Windows Agent │    │    Dashboard      │   │
│  │  C + eBPF    │    │  C + ETW     │    │    Next.js 15     │   │
│  │  OpenSSL TLS │    │  Schannel    │    │    Port :3000     │   │
│  └──────┬───────┘    └──────┬───────┘    └────────┬─────────┘   │
│         │  XOR + TLS 1.2+   │                     │ REST API     │
│         ▼                   ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           Go C2 Server  (:8080 agent / :8081 API)        │   │
│  │   TLS termination · JSON parse · PostgreSQL write         │   │
│  │   Agent registry · Action dispatch · REST API            │   │
│  └─────────────────────────┬────────────────────────────────┘   │
│                             │ HTTP (internal)                     │
│                             ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │           Python AI Server  (:8000 FastAPI)              │   │
│  │   Rule engine · IsolationForest · YARA · VT API          │   │
│  │   Static CNN · KQL rules · Calibration engine            │   │
│  └─────────────────────────┬────────────────────────────────┘   │
│                             ▼                                     │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   PostgreSQL :5432                        │   │
│  │  agents · events · alerts · file_scans · agent_baseline  │   │
│  │  malware_hashes · kql_rules · action_logs                │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 AI / Detection Layers

### Event Analysis Pipeline (`POST /analyze/event`)

Every agent event passes through this sequential pipeline:

```
Incoming Event
  │
  ├─ 1. Parent-process lookup  (PPID chain for parent-child rules)
  ├─ 2. Rule Engine            (18 malware names, 38 cmdline regexes, 20 parent-child pairs)
  ├─ 3. Beacon Detection       (≥3 connections to same IP in 10 min → C2 beacon)
  ├─ 4. Behavioral Analysis    (IsolationForest + Z-score, only if calibrated)
  ├─ 5. Score Fusion           (final = max(rule_score, behavioral_score))
  ├─ 6. KQL Custom Rules       (analyst-defined detection logic)
  └─ 7. Auto-Action            (score ≥ 90 → kill_process / quarantine / block)

Total latency: ~26 ms  |  Auto-action latency: ~50 ms
```

### Behavioral Calibration

```
Start Calibration → collect metrics for 5-15 min (normal usage)
Stop Calibration  → train IsolationForest (200 trees, 5% contamination)

Features (7-dim vector per event):
  [cpu, cpu_std, ram, ram_std, avg_connections, process_frequency, ip_known]

Anomaly score = max(z_score, 0.4·z_score + 0.6·IF_score)
```

### Static File Analysis Pipeline (`POST /analyze/static`)

```
File SHA-256
  ├─ 1. Local hash DB    (~1ms)  → instant verdict if known
  ├─ 2. YARA scanner             → signature matching (ransomware, trojan, APT...)
  ├─ 3. VirusTotal API           → 72-engine consensus (parallel with YARA)
  ├─ 4. Binary CNN               → EfficientNet-B0, RGB pixel encoding, threshold 0.70
  └─ 5. Multiclass CNN           → 9-class Nataraj encoding (benign/ransomware/trojan/...)

VT score formula: risk = min(100, 60 + positives × 3 + ratio_bonus)
Score ≥ 90 → automatic quarantine_file action
```

---

## 🔐 Security Architecture

| Layer | Mechanism |
|---|---|
| **L1 — Application** | XOR stream cipher with configurable key |
| **L2 — Transport** | TLS 1.2/1.3 (OpenSSL on Linux, Schannel on Windows) |
| **L3 — PKI** | Self-signed CA with server cert; Linux agents use mTLS |
| **L4 — API Auth** | JWT (HS256, 8h expiry) with PBKDF2-HMAC-SHA256 password hashing |
| **L5 — Agent ID** | Per-machine deterministic UUID, rejected if unregistered |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Docker + Docker Compose | Latest | PostgreSQL + Redis containers |
| Go | 1.22+ | Build the C2 server |
| Python | 3.12+ | AI service |
| Node.js | 20+ | Dashboard (Next.js) |
| GCC / OpenSSL dev | Any | Build Linux agent |
| Visual Studio 2022 | Any edition | Build Windows agent (optional) |
| OpenSSL CLI | Any | Generate TLS certificates |

**Install Docker (Ubuntu/Debian):**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER   # re-login after this
```

**Install Go:**
```bash
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
```

**Install Python deps & Node.js:**
```bash
sudo apt install python3.12 python3.12-venv python3-pip gcc libssl-dev -y
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt install nodejs -y
```

---

### 1. Clone & Configure

```bash
git clone https://github.com/AbdulkadirSadi/Project-Sentinel.git
cd Project-Sentinel
mkdir -p certs logs
```

**Create `sentinel-ai/.env`** (AI service configuration):

```env
# Database — must match docker-compose values below
DATABASE_URL=postgresql://sentinel:YourStrongPassword@localhost:5432/sentinel_db

# VirusTotal (optional — file scanning is disabled without this)
VT_API_KEY=your_virustotal_api_key_here

# Auth secrets — use long random strings
JWT_SECRET=change_me_to_a_random_64char_string
INTERNAL_SECRET=change_me_to_another_random_string

# Detection thresholds
ACTION_THRESHOLD=90
ALERT_THRESHOLD=70
VT_MIN_POSITIVES=5

# Admin account (created on first start)
ADMIN_PASSWORD=change_me_strong_password
```

**Create `.env`** (Docker Compose secrets — in the project root):

```env
POSTGRES_USER=sentinel
POSTGRES_PASSWORD=YourStrongPassword
POSTGRES_DB=sentinel_db
REDIS_PASSWORD=AnotherStrongPassword
```

> ⚠️ Both `.env` files are in `.gitignore` — they are **never committed**. Use strong, unique passwords.

---

### 2. Generate TLS Certificates

```bash
mkdir -p certs && cd certs

# Certificate Authority
openssl req -new -x509 -days 3650 -newkey rsa:4096 \
  -keyout ca.key -out ca.crt -nodes -subj "/CN=Sentinel CA"

# Server certificate
openssl req -new -newkey rsa:4096 -keyout server.key \
  -out server.csr -nodes -subj "/CN=sentinel-server"
openssl x509 -req -days 3650 -in server.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Linux agent client certificate (mTLS)
openssl req -new -newkey rsa:4096 -keyout agent-client.key \
  -out agent-client.csr -nodes -subj "/CN=sentinel-agent"
openssl x509 -req -days 3650 -in agent-client.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -out agent-client.crt

cd ..
```

---

### 3. Start All Services

```bash
bash start.sh
```

This script:
1. Starts PostgreSQL + Redis via Docker Compose
2. Waits for DB health checks to pass
3. Builds and starts the Go C2 server (`:8080` agent / `:8081` API)
4. Creates a Python venv, installs dependencies, starts the AI service (`:8000`)
5. Installs Node.js deps and starts the Next.js dashboard (`:3000`)

**Services after startup:**

| Service | URL | Description |
|---|---|---|
| Dashboard | http://localhost:3000 | SOC interface |
| AI API | http://localhost:8000/docs | Swagger UI |
| Adminer | http://localhost:5051 | Database browser |

**Stop everything:**
```bash
bash stop.sh
```

**View logs:**
```bash
tail -f logs/server.log    # Go server
tail -f logs/ai.log        # AI service
tail -f logs/frontend.log  # Dashboard
```

---

### 4. Deploy Linux Agent

The Linux agent connects back to your server. Edit the server IP/port before building:

```bash
# Edit server address (line ~25 in linux_agent.c)
nano agents/LinuxAgent/linux_agent.c
# Change: #define SERVER_IP  "YOUR_SERVER_IP"
#         #define SERVER_PORT 8080

cd agents/LinuxAgent
gcc -O2 -o sentinel-agent linux_agent.c -lssl -lcrypto -lpthread

# Install as systemd service (runs on boot, auto-restarts)
sudo bash install_service.sh

# Check status
sudo systemctl status sentinel-agent
```

---

### 5. Deploy Windows Agent

1. Edit server address in `WindowsAgent.c` before building:
   ```c
   // ~line 35
   #define DEFAULT_IP   "YOUR_SERVER_IP"
   #define DEFAULT_PORT  8080
   ```
2. Open `agents/WindowsAgent/WindowsAgent.sln` in **Visual Studio 2022**
3. Select **Release / x64** configuration
4. Build (`Ctrl+Shift+B`) → output: `x64/Release/WindowsAgent.exe`
5. Copy `WindowsAgent.exe` to the target Windows machine
6. **Run as Administrator** once — agent self-installs via Task Scheduler for persistence (runs on every login)

> **Ghost mode:** The agent has no console window (`/SUBSYSTEM:windows`). It runs silently in the background.



---

## 📁 Project Structure

```
Project-Sentinel/
├── agents/
│   ├── LinuxAgent/
│   │   ├── linux_agent.c          # Linux agent (eBPF + OpenSSL TLS)
│   │   └── install_service.sh     # systemd installer
│   └── WindowsAgent/
│       └── WindowsAgent/
│           └── WindowsAgent.c     # Windows agent (ETW + Schannel TLS)
├── server/
│   └── server.go                  # Go C2 server (:8080/:8081)
├── sentinel-ai/
│   ├── main.py                    # FastAPI AI service (:8000)
│   ├── models/
│   │   ├── behavioral_model.py    # IsolationForest + rule engine
│   │   └── static_model.py        # EfficientNet-B0 CNN (binary + multiclass)
│   └── yara_rules/                # YARA signature files
├── frontend/
│   └── src/app/                   # Next.js 15 SOC dashboard
├── docker-compose.yml             # PostgreSQL + Redis
├── start.sh / stop.sh
└── certs/                         # TLS certificates (generate, do not commit)
```

---

## 🛠️ API Reference

### Go Server (`:8081`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/agents` | List connected agents |
| `GET` | `/api/events` | Recent events stream |
| `GET` | `/api/alerts` | Active alerts |
| `POST` | `/api/action` | Dispatch action to agent |
| `POST` | `/api/shell` | Remote shell command |
| `GET` | `/api/shell/result` | Retrieve shell output |

### AI Service (`:8000`) — [Full Swagger at `/docs`]

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/analyze/event` | Behavioral event analysis |
| `POST` | `/analyze/static` | Static PE file analysis |
| `POST` | `/calibrate/{id}/control` | Start/stop behavioral calibration |
| `GET` | `/baseline/{id}` | View agent calibration data |
| `GET` | `/alerts` | List alerts with filters |
| `POST` | `/rules` | Create KQL detection rule |
| `GET` | `/beats/summary` | XDR beats dashboard stats |
| `POST` | `/auth/login` | JWT authentication |

---

## 🎯 Automated Response Actions

| Action | Trigger Condition | What Happens |
|---|---|---|
| `kill_process` | pid > 0, score ≥ 90 | `TerminateProcess()` / `kill -9` |
| `quarantine_file` | file scan, score ≥ 90 | Moves file to isolated directory |
| `block_ip` | C2 beacon / network threat | `iptables` / `netsh advfirewall` rule |
| `isolate_network` | Lateral movement | Blocks all outbound to target IP |

---

## 🗃️ Database Schema

Core tables in PostgreSQL:

```sql
agents          -- registered endpoints (agent_id, hostname, os, ip, online)
events          -- raw telemetry (type, ts, raw JSONB, risk_score, threat_type)
alerts          -- fired alerts (risk_score, threat_type, action_taken)
agent_baseline  -- calibration data (cpu_mean/std, known_processes, known_ips)
file_scans      -- static analysis results (sha256, vt_positives, yara_matches)
malware_hashes  -- threat intel hash database (sha256, name, source)
kql_rules       -- custom detection rules (query, severity, action)
action_logs     -- audit trail for all automated actions
```

---

## 🔧 Configuration

All sensitive configuration is via environment variables (`.env` file, never committed):

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `VT_API_KEY` | `""` (disabled) | VirusTotal API key |
| `JWT_SECRET` | — | JWT signing secret |
| `INTERNAL_SECRET` | — | Go↔AI service shared secret |
| `ACTION_THRESHOLD` | `90` | Minimum score for auto-action |
| `ALERT_THRESHOLD` | `70` | Minimum score for alert creation |
| `VT_MIN_POSITIVES` | `5` | Minimum VT engines for positive verdict |
| `ADMIN_PASSWORD` | — | Initial admin account password |

---

## 🧪 Detection Examples

### Known Malware Hash
```
Any file with SHA-256 matching the built-in threat intel DB (WannaCry, Mimikatz, etc.)
→ Instant 100/100 score, quarantine_file action
```

### Privilege Escalation (Linux)
```
eBPF uid_change event: old_uid=1000, new_uid=0
→ Rule score: 95, threat: "privilege_escalation", kill_process
```

### C2 Beacon
```
3+ connections to same remote IP within 10 minutes
→ Beacon detected, score: 78+, block_ip action
```

### Word → CMD (Spear Phishing)
```
Parent: winword.exe → Child: cmd.exe
→ Parent-child rule, score: 88, threat: "spear_phishing"
```

### Behavioral Anomaly (post-calibration)
```
Baseline: cpu_mean=15%, cpu_std=8%
Observed: cpu=94%  →  z-score = (94-15)/8 = 9.87  →  score: 100
```

---

## 📋 Threat Categories

The rule engine covers the following threat types:

`ransomware` · `credential_theft` · `rat` · `cryptominer` · `backdoor` · `c2_framework` · `c2_beacon` · `lateral_movement` · `privilege_escalation` · `dropper` · `spear_phishing` · `macro_attack` · `obfuscated_ps` · `reverse_shell` · `service_abuse` · `anomaly`

---

## ⚠️ Disclaimer

> This project is developed **strictly for educational and research purposes** as part of a university graduation project. All detection and response capabilities are intended to be deployed only on systems you own or have explicit written permission to monitor.
>
> Do **not** deploy agents on systems without authorization. The authors accept no responsibility for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with ❤️ as a graduation project · Go · Python · C · Next.js · PostgreSQL · EfficientNet-B0

</div>
