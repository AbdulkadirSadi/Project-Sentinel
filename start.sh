#!/bin/bash
# Sentinel XDR — Tam başlatma scripti
# Kullanım: chmod +x start.sh && ./start.sh

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

log() { echo -e "${CYAN}[Sentinel]${NC} $1"; }
ok()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; }

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"
mkdir -p logs

# ── 0. Önceki process'leri temizle ───────────────────────────────────────────
log "Eski process'ler temizleniyor..."
for pidfile in logs/server.pid logs/ai.pid logs/frontend.pid; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile" 2>/dev/null)
        kill -- -$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') 2>/dev/null
        kill "$pid" 2>/dev/null && warn "Önceki process durduruldu (PID:$pid)"
        rm -f "$pidfile"
    fi
done
pkill -f "sentinel-server"   2>/dev/null
pkill -f "uvicorn main:app"  2>/dev/null
pkill -f "next"              2>/dev/null   # Next.js tüm child'lar
fuser -k 3000/tcp            2>/dev/null   # Port 3000 garantili serbest
sleep 1

# ── Log rotasyonu (10MB üzeri dosyaları rotate et) ────────────────────────────
MAX_LOG_KB=10240  # 10 MB
rotate_log() {
    local f="$1"
    if [ -f "$f" ]; then
        size_kb=$(du -k "$f" | cut -f1)
        if [ "$size_kb" -gt "$MAX_LOG_KB" ]; then
            mv "$f" "${f}.old"
            warn "$(basename $f) rotated (${size_kb}KB → ${f}.old)"
        fi
    fi
    # Dosya yoksa veya rotate edildiyse sıfır byte ile oluştur
    > "$f"
}
rotate_log "$PROJECT_ROOT/logs/server.log"
rotate_log "$PROJECT_ROOT/logs/ai.log"
rotate_log "$PROJECT_ROOT/logs/frontend.log"

# Eski rotate dosyaları sil (1 önceki saklansın)
for old in logs/*.old; do
    [ -f "$old" ] && rm -f "$old" && warn "Eski log silindi: $old"
done

# Disk durumu
disk_free=$(df -h "$PROJECT_ROOT" | tail -1 | awk '{print $4}')
ok "Disk: $disk_free boş alan"

# ── 1. Docker ────────────────────────────────────────────────────────────────
log "Docker servisleri başlatılıyor..."
docker compose up -d 2>/dev/null || docker-compose up -d
sleep 3
ok "PostgreSQL, Redis hazır"

# ── 2. Go Server ─────────────────────────────────────────────────────────────
log "Go C2 server derleniyor ve başlatılıyor..."
cd "$PROJECT_ROOT/server"
if [ server.go -nt sentinel-server ] || [ ! -f sentinel-server ]; then
    if go build -o sentinel-server . 2>&1 | tee /tmp/go_build.log; then
        ok "Derleme tamamlandı"
    else
        err "Derleme başarısız! Detay: /tmp/go_build.log"
        cat /tmp/go_build.log
        exit 1
    fi
else
    ok "Binary güncel, yeniden derleme atlanıyor"
fi
nohup ./sentinel-server > /dev/null 2>"$PROJECT_ROOT/logs/server.log" &
echo $! > "$PROJECT_ROOT/logs/server.pid"
ok "Go server başlatıldı (PID: $(cat "$PROJECT_ROOT/logs/server.pid")) — :8080/:8081"
cd "$PROJECT_ROOT"

# ── 3. AI Servisi ─────────────────────────────────────────────────────────────
log "AI servisi başlatılıyor..."
cd "$PROJECT_ROOT/sentinel-ai"
source venv/bin/activate
nohup uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --log-level warning \
    --no-access-log \
    > "$PROJECT_ROOT/logs/ai.log" 2>&1 &
echo $! > "$PROJECT_ROOT/logs/ai.pid"
ok "AI servisi başlatıldı (PID: $(cat "$PROJECT_ROOT/logs/ai.pid")) — :8000"
deactivate
cd "$PROJECT_ROOT"

# ── 4. Frontend ───────────────────────────────────────────────────────────────
log "Frontend başlatılıyor..."
cd "$PROJECT_ROOT/frontend"
nohup npm run dev > "$PROJECT_ROOT/logs/frontend.log" 2>&1 &
echo $! > "$PROJECT_ROOT/logs/frontend.pid"
ok "Frontend başlatıldı (PID: $(cat "$PROJECT_ROOT/logs/frontend.pid")) — :3000"
cd "$PROJECT_ROOT"

# ── 5. Logrotate ayarı (sistem geneli, bir kez çalışır) ──────────────────────
LOGROTATE_CONF="/etc/logrotate.d/sentinel"
if [ ! -f "$LOGROTATE_CONF" ]; then
    sudo tee "$LOGROTATE_CONF" > /dev/null 2>&1 << CONF
$PROJECT_ROOT/logs/*.log {
    daily
    rotate 3
    size 50M
    compress
    missingok
    notifempty
    copytruncate
}
CONF
    [ -f "$LOGROTATE_CONF" ] && ok "Logrotate yapılandırıldı"
fi

# ── Özet ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Sentinel XDR Platform — Tüm servisler çalışıyor${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  Dashboard  : ${CYAN}http://localhost:3000${NC}"
echo -e "  AI Swagger : ${CYAN}http://localhost:8000/docs${NC}"
echo -e "  Adminer    : ${CYAN}http://localhost:5051${NC}"
echo -e "  Disk:      : ${YELLOW}$disk_free boş${NC}"
echo ""
echo -e "  Logları izle : ${YELLOW}tail -f logs/server.log${NC}"
echo -e "  Durdurmak    : ${YELLOW}./stop.sh${NC}"
echo ""
