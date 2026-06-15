#!/usr/bin/env python3
"""Auth sistemi test scripti"""
import urllib.request
import json

BASE = "http://localhost:8000"

def post(path, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def get(path, token=None):
    req = urllib.request.Request(BASE + path)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        resp = urllib.request.urlopen(req, timeout=5)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

print("=" * 50)
print("Sentinel XDR — Auth Sistem Testi")
print("=" * 50)

# Test 1: Doğru şifre ile login
print("\n[TEST 1] Login (admin/admin123)")
status, data = post("/auth/login", {"username": "admin", "password": "admin123"})
print(f"  HTTP {status}: {data}")
token = data.get("access_token", "")

if token:
    print("  ✅ Token alındı!")

    # Test 2: /auth/me ile token doğrulama
    print("\n[TEST 2] Token doğrulama (/auth/me)")
    status, data = get("/auth/me", token)
    print(f"  HTTP {status}: {data}")

    # Test 3: Geçersiz token
    print("\n[TEST 3] Geçersiz token ile /auth/me")
    status, data = get("/auth/me", "invalid.token.here")
    print(f"  HTTP {status}: {data}")
    if status == 401:
        print("  ✅ Geçersiz token reddedildi!")

# Test 4: Yanlış şifre
print("\n[TEST 4] Yanlış şifre ile login")
status, data = post("/auth/login", {"username": "admin", "password": "yanlis123"})
print(f"  HTTP {status}: {data}")
if status == 401:
    print("  ✅ Yanlış şifre reddedildi!")

# Test 5: CORS / public endpoint'ler hâlâ çalışıyor mu?
print("\n[TEST 5] /health endpoint (public)")
status, data = get("/health")
print(f"  HTTP {status}: {list(data.keys())}")
if status == 200:
    print("  ✅ Public endpoint çalışıyor!")

print("\n" + "=" * 50)
print("Test tamamlandı.")
