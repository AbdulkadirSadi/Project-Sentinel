#!/bin/bash
# Sentinel XDR — TLS Sertifika Üretici
# docker compose up'dan önce bir kez çalıştırın: bash certs/generate.sh

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -f server.crt ] && [ -f server.key ]; then
    echo "[!] Sertifikalar zaten mevcut. Yeniden üretmek için önce silin:"
    echo "    rm certs/*.crt certs/*.key"
    exit 0
fi

echo "[*] Sentinel XDR TLS sertifikaları üretiliyor..."

# Certificate Authority
openssl req -new -x509 -days 3650 -newkey rsa:4096 \
    -keyout ca.key -out ca.crt -nodes \
    -subj "/CN=Sentinel CA/O=Project Sentinel" 2>/dev/null

# Server sertifikası
openssl req -new -newkey rsa:4096 -keyout server.key \
    -out server.csr -nodes \
    -subj "/CN=sentinel-server" 2>/dev/null
openssl x509 -req -days 3650 -in server.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt 2>/dev/null

# Linux agent istemci sertifikası (mTLS için)
openssl req -new -newkey rsa:4096 -keyout agent-client.key \
    -out agent-client.csr -nodes \
    -subj "/CN=sentinel-agent" 2>/dev/null
openssl x509 -req -days 3650 -in agent-client.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out agent-client.crt 2>/dev/null

# Geçici dosyaları temizle
rm -f *.csr *.srl

chmod 600 *.key
chmod 644 *.crt

echo "[+] Sertifikalar başarıyla oluşturuldu:"
ls -lh *.crt *.key
echo ""
echo "[*] Şimdi çalıştırabilirsiniz: docker compose up -d"
