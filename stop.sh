#!/bin/bash
# Sentinel XDR — Tüm servisleri durdur

YELLOW='\033[1;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
cd "$(dirname "$0")"

stop_pid() {
    local name=$1 pidfile="logs/$2.pid"
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill -0 "$pid" 2>/dev/null; then
            # Tüm process grubunu öldür (child'lar dahil)
            kill -- -$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ') 2>/dev/null
            kill "$pid" 2>/dev/null
            echo -e "${GREEN}[✓]${NC} $name durduruldu (PID:$pid)"
        fi
        rm -f "$pidfile"
    fi
}

stop_pid "Go Server"  "server"
stop_pid "AI Servisi" "ai"
stop_pid "Frontend"   "frontend"

# Frontend için ekstra temizlik — Next.js child process'ler
pkill -f "next"        2>/dev/null
pkill -f "next-server" 2>/dev/null
pkill -f "next dev"    2>/dev/null

# Port 3000 hâlâ meşgulse zorunlu serbest bırak
if fuser 3000/tcp >/dev/null 2>&1; then
    echo -e "${YELLOW}[!]${NC} Port 3000 hâlâ meşgul, zorla kapatılıyor..."
    fuser -k 3000/tcp 2>/dev/null
    echo -e "${GREEN}[✓]${NC} Port 3000 serbest bırakıldı"
fi

echo -e "${YELLOW}[!]${NC} Docker servisleri durduruluyor..."
docker compose stop
echo -e "${GREEN}[✓]${NC} Tüm servisler durduruldu."
