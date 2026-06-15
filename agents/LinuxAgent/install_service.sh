#!/bin/bash
# Linux Ajan'ı systemd servisi olarak kurar
# Kullanım: sudo bash install_service.sh
#
# Gerekli dosyalar (aynı klasörde olmalı):
#   linux_agent        — TLS'li ajan binary (10 Haziran)
#   sentinel_ebpf      — Kernel monitor binary
#   agent-client.crt   — Ajan TLS sertifikası
#   agent-client.key   — Ajan TLS özel anahtarı
#   ca.crt             — Sentinel CA sertifikası

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/linux_agent"
EBPF_BIN="$SCRIPT_DIR/sentinel_ebpf"
CERT_DIR="/etc/sentinel/certs"

# ── Kontroller ──────────────────────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    echo "[!] Bu betik root yetkisi gerektirir. sudo ile çalıştırın."
    exit 1
fi

if [ ! -f "$AGENT_BIN" ]; then
    echo "[!] linux_agent binary bulunamadı: $AGENT_BIN"
    exit 1
fi

# ── Sertifika dizini ────────────────────────────────────────────────────────
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

for cert_file in agent-client.crt agent-client.key ca.crt; do
    if [ -f "$SCRIPT_DIR/$cert_file" ]; then
        cp "$SCRIPT_DIR/$cert_file" "$CERT_DIR/"
        echo "[+] Sertifika kopyalandı: $CERT_DIR/$cert_file"
    else
        echo "[!] UYARI: $cert_file bulunamadı — mTLS çalışmayabilir!"
    fi
done

chmod 600 "$CERT_DIR/agent-client.key"
chmod 644 "$CERT_DIR/agent-client.crt"
chmod 644 "$CERT_DIR/ca.crt"

# ── Binary'leri kopyala ─────────────────────────────────────────────────────
cp "$AGENT_BIN" /usr/local/bin/sentinel-agent
chmod +x /usr/local/bin/sentinel-agent
echo "[+] Ajan binary kopyalandı: /usr/local/bin/sentinel-agent"

if [ -f "$EBPF_BIN" ]; then
    cp "$EBPF_BIN" /usr/local/bin/sentinel-ebpf
    chmod +x /usr/local/bin/sentinel-ebpf
    echo "[+] eBPF binary kopyalandı: /usr/local/bin/sentinel-ebpf"
fi

# ── Ajan systemd servisi ────────────────────────────────────────────────────
cat > /etc/systemd/system/sentinel-agent.service << 'EOF'
[Unit]
Description=Sentinel XDR Linux Agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-agent
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[+] sentinel-agent.service oluşturuldu"

# ── eBPF (Kernel Monitor) systemd servisi ───────────────────────────────────
if [ -f /usr/local/bin/sentinel-ebpf ]; then
    cat > /etc/systemd/system/sentinel-ebpf.service << 'EOF'
[Unit]
Description=Sentinel XDR Kernel Monitor (eBPF/CN_PROC)
After=network-online.target sentinel-agent.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentinel-ebpf
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    echo "[+] sentinel-ebpf.service oluşturuldu"
fi

# ── Servisleri etkinleştir ve başlat ────────────────────────────────────────
systemctl daemon-reload
systemctl enable sentinel-agent
systemctl start  sentinel-agent
echo "[✓] sentinel-agent servisi başlatıldı"

if [ -f /usr/local/bin/sentinel-ebpf ]; then
    systemctl enable sentinel-ebpf
    systemctl start  sentinel-ebpf
    echo "[✓] sentinel-ebpf servisi başlatıldı"
fi

echo ""
echo "══════════════════════════════════════════"
echo " Kurulum tamamlandı!"
echo "══════════════════════════════════════════"
echo " Ajan durumu  : systemctl status sentinel-agent"
echo " Ajan logları : journalctl -u sentinel-agent -f"
echo " eBPF durumu  : systemctl status sentinel-ebpf"
echo " eBPF logları : journalctl -u sentinel-ebpf -f"
echo " Durdur       : systemctl stop sentinel-agent sentinel-ebpf"
echo "══════════════════════════════════════════"
