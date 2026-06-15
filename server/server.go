package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	PORT       = ":8080"
	SECRET_KEY = "EDR_SUPER_SECRET_KEY"
	AI_ADDR    = "http://localhost:8000"
)

// Çalışma zamanı yapılandırma — ortam değişkenlerinden okunur
var (
	REDIS_ADDR       = getenv("REDIS_ADDR",       "localhost:6379")
	REDIS_PASSWORD   = getenv("REDIS_PASSWORD",   "sentinel_redis_pass")
	JWT_SECRET       = getenv("JWT_SECRET",       "sentinel-xdr-jwt-secret-2024-change-in-production")
	INTERNAL_SECRET  = getenv("INTERNAL_SECRET",  "sentinel-internal-ai-secret-2024")
	CERTS_DIR        = getenv("CERTS_DIR",        "/home/quietus/Project-Sentinel/certs")
)

// loadTLSConfig — mTLS konfigürasyonı oluşturur (Phase 5)
// Sertifika dosyaları yoksa nil döner (plain TCP'e geri düşer)
func loadTLSConfig() *tls.Config {
	serverCert := filepath.Join(CERTS_DIR, "server.crt")
	serverKey  := filepath.Join(CERTS_DIR, "server.key")
	caFile     := filepath.Join(CERTS_DIR, "ca.crt")

	// Dosyalar yoksa TLS'siz çalış
	for _, f := range []string{serverCert, serverKey, caFile} {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			fmt.Printf("[!] TLS sertifikası bulunamadı (%s), plain TCP kullanılıyor.\n", f)
			return nil
		}
	}

	cert, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		fmt.Printf("[!] Sunucu sertifikası yüklenemedi: %v\n", err)
		return nil
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		fmt.Printf("[!] CA sertifikası okunamadı: %v\n", err)
		return nil
	}
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		// NoClientCert: Sunucu CertificateRequest gondermez.
		// Windows ajanlar (Schannel) client sertifikasi saglamaz;
		// sunucu CertificateRequest gonderseydi Schannel
		// SEC_I_INCOMPLETE_CREDENTIALS (0x00090320) ile bağlantıyı keserdi.
		// Linux ajanlar hâlâ kendi sertifikalarıyla bağlanır (OpenSSL mTLS),
		// ancak sunucu doğrulamayı uygulama katmanında (agent_id) yapar.
		ClientAuth: tls.NoClientCert,
		// TLS 1.2 minimum: Windows Schannel ile uyumluluk icin.
		MinVersion: tls.VersionTLS12,
	}
}


func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type AgentInfo struct {
	Conn     net.Conn
	OS       string
	CPU      float64
	RAMUsed  int64
	RAMTotal int64
	LastSeen int64
}

// Ajan metrik cache
type MetricSnap struct {
	AgentID  string  `json:"agent_id"`
	OS       string  `json:"os"`
	CPU      float64 `json:"cpu"`
	RAMPct   float64 `json:"ram_pct"`
	RAMUsed  int64   `json:"ram_used_kb"`
	RAMTotal int64   `json:"ram_total_kb"`
	LastSeen int64   `json:"last_seen"`
}

var (
	agents            = make(map[string]*AgentInfo)
	agentsMutex       sync.Mutex
	selectedID        string
	rdb               *redis.Client
	ctx               = context.Background()
	// Shell result buffer
	shellBuffers      = make(map[string][]string)
	shellBufferMutex  sync.Mutex
)

func initRedis() {
	rdb = redis.NewClient(&redis.Options{
		Addr:     REDIS_ADDR,
		Password: REDIS_PASSWORD,
	})
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Printf("[!] Redis baglantisi kurulamadi: %v\n", err)
		rdb = nil
	} else {
		fmt.Println("[+] Redis baglantisi kuruldu.")
	}
}

// Veriyi Redis'e gönderir; Redis yoksa sessizce geçer
func pushToRedis(msgType string, data map[string]interface{}) {
	if rdb == nil {
		return
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	key := "sentinel:" + msgType
	rdb.LPush(ctx, key, string(raw)) // hata sessizce geçer
	rdb.LTrim(ctx, key, 0, 9999)
}

// AI servisine event gönderir; servis yoksa sessizce geçer
func analyzeWithAI(eventID int64, data map[string]interface{}) {
	payload := map[string]interface{}{
		"event_id": eventID,
		"data":     data,
	}
	body, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Post(AI_ADDR+"/analyze/event", "application/json", bytes.NewReader(body))
	if err != nil {
		return // AI servisi çalışmıyor, sessizce geç
	}
	defer resp.Body.Close()
}

func decryptMessage(hexStr string) string {
	hexStr = strings.TrimSpace(hexStr)
	encryptedBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}
	keyLen := len(SECRET_KEY)
	decrypted := make([]byte, len(encryptedBytes))
	for i, b := range encryptedBytes {
		decrypted[i] = b ^ SECRET_KEY[i%keyLen]
	}
	return string(decrypted)
}

func encryptMessage(plain string) string {
	keyLen := len(SECRET_KEY)
	encrypted := make([]byte, len(plain))
	for i := 0; i < len(plain); i++ {
		encrypted[i] = plain[i] ^ SECRET_KEY[i%keyLen]
	}
	return hex.EncodeToString(encrypted) + "\n"
}

// AI servisine otomatik kalibrasyon tetikleyici gönderir
func triggerCalibration(agentID string) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(fmt.Sprintf("%s/calibrate/%s", AI_ADDR, agentID), "application/json", nil)
	if err != nil {
		fmt.Printf("[!] Kalibrasyon tetiklenemedi (%s): %v\n", agentID[:8], err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[+] Otomatik kalibrasyon tetiklendi (%s), HTTP %d\n", agentID[:8], resp.StatusCode)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	var agentID string // bu goroutine'in sahip olduğu ajan ID'si

	defer func() {
		// Goroutine bitince (bağlantı kopunca) ajanı map'ten sil
		if agentID != "" {
			agentsMutex.Lock()
			if info, ok := agents[agentID]; ok && info.Conn == conn {
				delete(agents, agentID)
				fmt.Printf("[-] Ajan koptu: %s\n", agentID[:8])
			}
			agentsMutex.Unlock()
		}
	}()

	scanner := bufio.NewScanner(conn)
	// Kapasiteyi artırıyoruz ki uzun process çıktıları kesilmesin
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		msg := scanner.Text()
		decrypted := decryptMessage(msg)
		if decrypted == "" {
			continue
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(decrypted), &data); err != nil {
			continue
		}

		id, idOk := data["agent_id"].(string)
		osName, osOk := data["os"].(string)
		msgType, typeOk := data["type"].(string)

		if !idOk || !osOk || !typeOk {
			continue
		}

		// Ajan kaydı / güncelleme — sadece yeni ajan ise oluştur, var olanı sıfırlama
		agentsMutex.Lock()
		if _, exists := agents[id]; !exists {
			agents[id] = &AgentInfo{Conn: conn, OS: osName, LastSeen: time.Now().Unix()}
			fmt.Printf("[+] Yeni Ajan: [%s] %s\n", osName, id[:8])
		} else {
			agents[id].Conn     = conn          // bağlantıyı güncelle
			agents[id].LastSeen = time.Now().Unix() // 4a: her mesajda heartbeat güncelle
		}
		agentID = id
		agentsMutex.Unlock()

		switch msgType {
		case "shell_result":
			output, ok := data["output"].(string)
			if !ok {
				output = "(gecersiz cikti)"
			}
			// Shell buffer'a kaydet (frontend okur)
			shellBufferMutex.Lock()
			shellBuffers[id] = append(shellBuffers[id], output)
			if len(shellBuffers[id]) > 200 {
				shellBuffers[id] = shellBuffers[id][len(shellBuffers[id])-200:]
			}
			shellBufferMutex.Unlock()
		case "metrics", "process_new", "network_new", "etw_process_start", "etw_process_stop":
			// Redis'e yaz (worker PG'ye aktaracak)
			pushToRedis(msgType, data)
			// Metrik ise in-memory cache'e kaydet
			if msgType == "metrics" {
				cpu, _      := data["cpu_percent"].(float64)
				ramUsed, _  := data["ram_used_kb"].(float64)
				ramTotal, _ := data["ram_total_kb"].(float64)
				ts, _       := data["ts"].(float64)
				agentsMutex.Lock()
				if info, ok := agents[id]; ok {
					info.CPU      = cpu
					info.RAMUsed  = int64(ramUsed)
					info.RAMTotal = int64(ramTotal)
					info.LastSeen = int64(ts)
				}
				agentsMutex.Unlock()
			}
			// Yalnızca process/network/ETW eventlerini AI'ya gönder (metrics değil — çok sık gelir)
			if msgType == "process_new" || msgType == "network_new" || msgType == "etw_process_start" || msgType == "etw_process_stop" {
				go analyzeWithAI(0, data)
			}
		}
	}
}

// ── HTTP REST API (port 8081) — Frontend ve AI Servisi için ─────────────────

const API_PORT = ":8081"

// GET /api/metrics — in-memory metrik cache (AI servisi gerekmez)
func handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentsMutex.Lock()
	snaps := make([]MetricSnap, 0, len(agents))
	for id, info := range agents {
		ramPct := 0.0
		if info.RAMTotal > 0 {
			ramPct = float64(info.RAMUsed) / float64(info.RAMTotal) * 100.0
		}
		snaps = append(snaps, MetricSnap{
			AgentID:  id,
			OS:       info.OS,
			CPU:      info.CPU,
			RAMPct:   ramPct,
			RAMUsed:  info.RAMUsed,
			RAMTotal: info.RAMTotal,
			LastSeen: info.LastSeen,
		})
	}
	agentsMutex.Unlock()
	json.NewEncoder(w).Encode(snaps)
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Sadece localhost frontend'e izin ver
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

// ── JWT Doğrulama ─────────────────────────────────────────────────────────────

func b64urlDecode(s string) ([]byte, error) {
	// padding ekle
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// verifyJWT token'ı doğrular; geçersizse hata döner
func verifyJWT(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("geçersiz JWT formatı")
	}
	// İmzayı doğrula
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(JWT_SECRET))
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, fmt.Errorf("imza geçersiz")
	}
	// Payload'u çöz
	payloadBytes, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload decode hatası: %w", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("payload JSON hatası: %w", err)
	}
	// Süre kontrolü
	if exp, ok := payload["exp"]; ok {
		var expTime int64
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case string:
			expTime, _ = strconv.ParseInt(v, 10, 64)
		}
		if expTime > 0 && time.Now().Unix() > expTime {
			return nil, fmt.Errorf("token süresi dolmuş")
		}
	}
	return payload, nil
}

// withAuth — JWT doğrulaması zorunlu endpoint'ler için middleware
// İstisna: X-Internal-Secret header'ı doğru olan çağrılar (AI servisi) JWT olmadan geçer
func withAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// OPTIONS preflight'ı doğrudan geç (CORS ile birlikte çalışır)
		if r.Method == "OPTIONS" {
			h(w, r)
			return
		}
		// Dahili AI servisi bypass — X-Internal-Secret header
		if r.Header.Get("X-Internal-Secret") == INTERNAL_SECRET {
			h(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Kimlik doğrulama gerekli."}`))
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		_, err := verifyJWT(token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Geçersiz veya süresi dolmuş token."}`))
			return
		}
		h(w, r)
	}
}

// GET /api/agents — bağlı tüm ajanları listele
func handleGetAgents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentsMutex.Lock()
	defer agentsMutex.Unlock()
	type AgentDTO struct {
		ID       string `json:"id"`
		OS       string `json:"os"`
		Addr     string `json:"addr"`
		LastSeen int64  `json:"last_seen"` // 4c: offline badge için
		Offline  bool   `json:"offline"`
	}
	list := make([]AgentDTO, 0, len(agents))
	now := time.Now().Unix()
	for id, info := range agents {
		offline := info.LastSeen > 0 && (now-info.LastSeen) > 60
		list = append(list, AgentDTO{
			ID:       id,
			OS:       info.OS,
			Addr:     info.Conn.RemoteAddr().String(),
			LastSeen: info.LastSeen,
			Offline:  offline,
		})
	}
	json.NewEncoder(w).Encode(list)
}

// validateActionParams — action'a özgü parametre doğrulama (Aşama 3d)
func validateActionParams(action string, params map[string]interface{}) error {
	switch action {
	case "block_ip", "unblock_ip", "isolate_network":
		ip, _ := params["ip"].(string)
		if ip == "" {
			return fmt.Errorf("'ip' parametresi zorunlu")
		}
		if !isValidIP(ip) {
			return fmt.Errorf("geçersiz IP formatı: %s", ip)
		}
	case "kill_process":
		pidVal, ok := params["pid"]
		if !ok {
			return fmt.Errorf("'pid' parametresi zorunlu")
		}
		var pid int64
		switch v := pidVal.(type) {
		case float64:
			pid = int64(v)
		case string:
			_, err := fmt.Sscanf(v, "%d", &pid)
			if err != nil {
				return fmt.Errorf("geçersiz PID değeri")
			}
		default:
			return fmt.Errorf("geçersiz PID tipi")
		}
		if pid <= 0 || pid > 4194304 {
			return fmt.Errorf("PID aralık dışı: %d", pid)
		}
	case "quarantine_file", "delete_file":
		path, _ := params["path"].(string)
		if path == "" {
			return fmt.Errorf("'path' parametresi zorunlu")
		}
		if strings.Contains(path, "..") {
			return fmt.Errorf("path traversal tespit edildi, reddedildi")
		}
		if len(path) > 512 {
			return fmt.Errorf("dosya yolu çok uzun")
		}
	}
	return nil
}

// isValidIP — sadece IPv4 (CIDR dahil) formatını kabul eder
func isValidIP(ip string) bool {
	if len(ip) == 0 || len(ip) > 43 {
		return false
	}
	// CIDR kısmını ayır
	parts := strings.SplitN(ip, "/", 2)
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return false
	}
	for _, o := range octets {
		if len(o) == 0 || len(o) > 3 {
			return false
		}
		for _, c := range o {
			if c < '0' || c > '9' {
				return false
			}
		}
		var n int
		fmt.Sscanf(o, "%d", &n)
		if n < 0 || n > 255 {
			return false
		}
	}
	if len(parts) == 2 {
		var prefix int
		if _, err := fmt.Sscanf(parts[1], "%d", &prefix); err != nil || prefix < 0 || prefix > 32 {
			return false
		}
	}
	return true
}

// POST /api/action — ajana eylem komutu gönder
// Body: {"agent_id": "...", "action": "kill_process", "params": {"pid": 1234}}
func handleSendAction(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		AgentID string                 `json:"agent_id"`
		Action  string                 `json:"action"`
		Params  map[string]interface{} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, 400)
		return
	}

	// ── 3d: Action whitelist doğrulaması ──────────────────────────────────────
	allowedActions := map[string]bool{
		"kill_process":    true,
		"block_ip":        true,
		"unblock_ip":      true,
		"isolate_network": true,
		"quarantine_file": true,
		"delete_file":     true,
	}
	if !allowedActions[req.Action] {
		http.Error(w, `{"error":"bilinmeyen action reddedildi"}`, 400)
		return
	}

	// ── Parametre doğrulama (action'a özel) ──────────────────────────────────
	if err := validateActionParams(req.Action, req.Params); err != nil {
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// ACTION:: komutunu oluştur
	cmd := "ACTION::" + req.Action
	if req.Params != nil {
		for k, v := range req.Params {
			cmd += fmt.Sprintf(" %v=%v", k, v)
		}
	}

	agentsMutex.Lock()
	info, ok := agents[req.AgentID]
	agentsMutex.Unlock()

	if !ok {
		http.Error(w, `{"error":"agent not found"}`, 404)
		return
	}

	_, err := info.Conn.Write([]byte(encryptMessage(cmd)))
	if err != nil {
		agentsMutex.Lock()
		delete(agents, req.AgentID)
		agentsMutex.Unlock()
		http.Error(w, `{"error":"send failed, agent disconnected"}`, 500)
		return
	}

	fmt.Printf("[ACTION] %s → %s | %s\n", req.AgentID[:8], req.Action, cmd)
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "sent", "cmd": cmd})
}

// GET /api/status — sunucu durumu
func handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentsMutex.Lock()
	count := len(agents)
	agentsMutex.Unlock()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"agent_count":  count,
		"c2_port":      PORT,
		"api_port":     API_PORT,
	})
}

// POST /api/shell — ajana shell komutu gönder
func handleShellSend(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		AgentID string `json:"agent_id"`
		Cmd     string `json:"cmd"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Cmd == "" {
		http.Error(w, `{"error":"invalid body"}`, 400); return
	}
	agentsMutex.Lock()
	info, ok := agents[req.AgentID]
	agentsMutex.Unlock()
	if !ok { http.Error(w, `{"error":"agent not found"}`, 404); return }
	_, err := info.Conn.Write([]byte(encryptMessage(req.Cmd)))
	if err != nil { http.Error(w, `{"error":"send failed"}`, 500); return }
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
}

// GET /api/shell/result?agent_id=xxx — birikmiş çıktıları al ve temizle
func handleShellResult(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agentID := r.URL.Query().Get("agent_id")
	if agentID == "" { http.Error(w, `{"error":"agent_id required"}`, 400); return }
	shellBufferMutex.Lock()
	lines := shellBuffers[agentID]
	shellBuffers[agentID] = nil
	shellBufferMutex.Unlock()
	if lines == nil { lines = []string{} }
	json.NewEncoder(w).Encode(lines)
}

// POST /api/file-scan — Ajan'dan gelen PE dosyasını FastAPI'ye ilet
type FileScanRequest struct {
	AgentID    string `json:"agent_id"`
	FileName   string `json:"file_name"`
	FilePath   string `json:"file_path"`
	ExeB64     string `json:"exe_b64"`
	Source     string `json:"source"`
	Categorize bool   `json:"categorize"`
}

func handleFileScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}

	var req FileScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid body"}`, 400)
		return
	}
	if req.AgentID == "" || req.ExeB64 == "" {
		http.Error(w, `{"error":"agent_id and exe_b64 required"}`, 400)
		return
	}
	if req.Source == "" {
		req.Source = "auto_scan"
	}

	// FastAPI'ye async ilet (büyük dosyalar uzun sürebilir)
	go func() {
		payload := map[string]interface{}{
			"agent_id":   req.AgentID,
			"exe_b64":    req.ExeB64,
			"file_name":  req.FileName,
			"file_path":  req.FilePath,
			"source":     req.Source,
			"categorize": false,
		}
		body, _ := json.Marshal(payload)
		client := &http.Client{Timeout: 120 * time.Second}
		resp, err := client.Post(AI_ADDR+"/analyze/static", "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Printf("[FileScan] AI hatasi: %v\n", err)
			return
		}
		defer resp.Body.Close()
		name := req.FileName
		if name == "" {
			name = req.FilePath
		}
		fmt.Printf("[FileScan] AI yaniti: HTTP %d | ajan:%s | dosya:%s\n",
			resp.StatusCode, req.AgentID[:8], name)
	}()

	w.WriteHeader(202)
	json.NewEncoder(w).Encode(map[string]string{"status": "scanning", "file": req.FileName})
}

// startHeartbeatWatcher — 4b: 60 saniye sessiz kalan ajanları AI'ya bildir
func startHeartbeatWatcher() {
	// Hangi agent için offline bildirimi gönderildi (tekrar gönderme)
	notified := make(map[string]bool)
	go func() {
		for {
			time.Sleep(15 * time.Second)
			now := time.Now().Unix()
			agentsMutex.Lock()
			for id, info := range agents {
				if info.LastSeen == 0 {
					continue // henüz metrik gelmedi
				}
				silent := now - info.LastSeen
				if silent > 60 && !notified[id] {
					notified[id] = true
					fmt.Printf("[!] Ajan %s sessiz (%ds) — offline event gönderiliyor\n", id[:8], silent)
					go analyzeWithAI(0, map[string]interface{}{
						"agent_id": id,
						"type":     "agent_offline",
						"os":       info.OS,
						"ts":       now,
						"silent_seconds": silent,
					})
				} else if silent <= 60 && notified[id] {
					// Ajan geri döndü — bildirim durumunu sıfırla
					delete(notified, id)
					fmt.Printf("[+] Ajan %s geri döndü\n", id[:8])
				}
			}
			agentsMutex.Unlock()
		}
	}()
}

// POST /api/ebpf-event — sentinel_ebpf'ten gelen kernel olaylarını işle
func handleEbpfEvent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}

	var data map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, `{"error":"invalid body"}`, 400)
		return
	}

	msgType, ok := data["type"].(string)
	if !ok || msgType == "" {
		http.Error(w, `{"error":"missing type"}`, 400)
		return
	}

	// Redis'e yaz (worker PG'ye aktaracak)
	pushToRedis(msgType, data)

	// AI analiz motoruna gönder (async)
	go analyzeWithAI(0, data)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func startAPIServer() {
	mux := http.NewServeMux()
	// Public endpoint'ler (auth gerektirmez)
	mux.HandleFunc("/api/status",       withCORS(handleStatus))
	mux.HandleFunc("/api/metrics",      withCORS(handleGetMetrics))
	mux.HandleFunc("/api/agents",       withCORS(handleGetAgents))
	mux.HandleFunc("/api/file-scan",    withCORS(handleFileScan))
	// Korumalı endpoint'ler — geçerli JWT zorunlu
	mux.HandleFunc("/api/action",       withCORS(withAuth(handleSendAction)))
	mux.HandleFunc("/api/shell",        withCORS(withAuth(handleShellSend)))
	mux.HandleFunc("/api/shell/result", withCORS(withAuth(handleShellResult)))
	mux.HandleFunc("/api/ebpf-event",   withCORS(withAuth(handleEbpfEvent)))

	go func() {
		fmt.Printf("[+] HTTP API baslatildi: %s\n", API_PORT)
		if err := http.ListenAndServe(API_PORT, mux); err != nil {
			fmt.Printf("[!] HTTP API hatasi: %v\n", err)
		}
	}()
}

func main() {
	initRedis()

	if err := initDB(); err != nil {
		fmt.Printf("[!] PostgreSQL hazir degil: %v\n", err)
		fmt.Println("[!] Veriler sadece Redis'te tutulacak, DB olmadan devam ediliyor.")
	} else {
		startWorker()
	}

	startHeartbeatWatcher() // 4b: ajan offline izleyici
	startAPIServer()

	listener, err := func() (net.Listener, error) {
		tlsCfg := loadTLSConfig()
		if tlsCfg != nil {
			fmt.Println("[+] TLS mTLS aktif — şifreli ajan bağlantısı")
			return tls.Listen("tcp", PORT, tlsCfg)
		}
		fmt.Println("[!] Plain TCP — TLS devre dışı (sertifikalar bulunamadı)")
		return net.Listen("tcp", PORT)
	}()
	if err != nil {
		fmt.Printf("[!] Server baslatma hatasi: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("EDR C2 Server Baslatildi %s\nKomutlar: 'list', 'select <id>', 'back'\n", PORT)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				continue
			}
			go handleConnection(conn)
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		if selectedID == "" {
			fmt.Print("Main Console > ")
		} else {
			fmt.Printf("[%s] > ", selectedID)
		}

		if scanner.Scan() {
			input := scanner.Text()
			parts := strings.Split(input, " ")

			switch parts[0] {
			case "list":
				fmt.Println("--- Bagli Ajanlar ---")
				agentsMutex.Lock()
				if len(agents) == 0 {
					fmt.Println("(Bagli ajan yok)")
				}
				for id, info := range agents {
					fmt.Printf("ID: %s | OS: %s | Addr: %s\n", id, info.OS, info.Conn.RemoteAddr())
				}
				agentsMutex.Unlock()
			case "select":
				if len(parts) > 1 {
					agentsMutex.Lock()
					if _, ok := agents[parts[1]]; ok {
						selectedID = parts[1]
					} else {
						fmt.Println("Ajan bulunamadi.")
					}
					agentsMutex.Unlock()
				}
			case "back":
				selectedID = ""
			default:
				if selectedID != "" && input != "" {
					agentsMutex.Lock()
					info, ok := agents[selectedID]
					if !ok {
						fmt.Println("Ajan artik bagli degil.")
						selectedID = ""
						agentsMutex.Unlock()
						continue
					}
					_, err := info.Conn.Write([]byte(encryptMessage(input)))
					if err != nil {
						fmt.Println("Gonderim hatasi, ajan kopmus olabilir.")
						delete(agents, selectedID)
						selectedID = ""
					}
					agentsMutex.Unlock()
				}
			}
		}
	}
}