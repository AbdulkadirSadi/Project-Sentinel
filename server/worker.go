package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const PG_DSN = "postgresql://admin:password123@localhost:5432/xdr_db"

var pgPool *pgxpool.Pool

// ── Şema ─────────────────────────────────────────────────────────────────────

const schema = `
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    TEXT        NOT NULL,
    os          TEXT        NOT NULL,
    type        TEXT        NOT NULL,
    ts          BIGINT      NOT NULL,
    raw         JSONB       NOT NULL,
    risk_score  FLOAT       DEFAULT 0.0,
    threat_type TEXT        DEFAULT 'none',
    confidence  FLOAT       DEFAULT 0.0,
    is_anomaly  BOOLEAN     DEFAULT FALSE,
    actioned    BOOLEAN     DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_events_agent_ts  ON events(agent_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_type_ts   ON events(type, ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_anomaly   ON events(is_anomaly) WHERE is_anomaly = TRUE;

CREATE TABLE IF NOT EXISTS agent_baseline (
    agent_id        TEXT    PRIMARY KEY,
    os              TEXT,
    calibrated      BOOLEAN DEFAULT FALSE,
    calib_start     BIGINT  DEFAULT 0,
    calib_end       BIGINT  DEFAULT 0,
    cpu_mean        FLOAT   DEFAULT 0,
    cpu_std         FLOAT   DEFAULT 0,
    ram_mean        FLOAT   DEFAULT 0,
    ram_std         FLOAT   DEFAULT 0,
    avg_connections FLOAT   DEFAULT 0,
    known_processes JSONB   DEFAULT '{}',
    known_ips       JSONB   DEFAULT '{}',
    updated_at      BIGINT  DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    event_id     BIGINT,
    agent_id     TEXT,
    ts           BIGINT,
    risk_score   FLOAT   DEFAULT 0,
    threat_type  TEXT    DEFAULT 'unknown',
    confidence   FLOAT   DEFAULT 0,
    action_taken TEXT    DEFAULT 'none',
    resolved     BOOLEAN DEFAULT FALSE,
    notes        TEXT    DEFAULT '',
    pname        TEXT    DEFAULT '',
    pid          INT     DEFAULT 0,
    rule_name    TEXT    DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_unresolved ON alerts(resolved) WHERE resolved = FALSE;
CREATE INDEX IF NOT EXISTS idx_alerts_ts         ON alerts(ts DESC);

CREATE TABLE IF NOT EXISTS detection_rules (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT    DEFAULT '',
    rule_text   TEXT    NOT NULL,
    threat_type TEXT    DEFAULT 'custom',
    score       FLOAT   DEFAULT 80,
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  BIGINT  DEFAULT 0,
    updated_at  BIGINT  DEFAULT 0
);

CREATE TABLE IF NOT EXISTS file_scans (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT    DEFAULT 'manual',
    file_name    TEXT    NOT NULL,
    file_hash    TEXT    NOT NULL,
    file_size    BIGINT  DEFAULT 0,
    threat_type  TEXT    DEFAULT 'benign',
    risk_score   FLOAT   DEFAULT 0,
    confidence   FLOAT   DEFAULT 0,
    is_malware   BOOLEAN DEFAULT FALSE,
    quarantined  BOOLEAN DEFAULT FALSE,
    ts           BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_ts      ON file_scans(ts DESC);
CREATE INDEX IF NOT EXISTS idx_scans_malware ON file_scans(is_malware) WHERE is_malware = TRUE;

CREATE TABLE IF NOT EXISTS action_logs (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT    NOT NULL,
    action_type  TEXT    NOT NULL,
    threat_type  TEXT    DEFAULT '',
    risk_score   FLOAT   DEFAULT 0,
    params       JSONB   DEFAULT '{}',
    is_success   BOOLEAN DEFAULT FALSE,
    message      TEXT    DEFAULT '',
    ts           BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_logs_ts ON action_logs(ts DESC);
`

// ── Bağlantı & Şema ──────────────────────────────────────────────────────────

func initDB() error {
	var err error
	pgPool, err = pgxpool.New(context.Background(), PG_DSN)
	if err != nil {
		return fmt.Errorf("PostgreSQL bağlantısı kurulamadı: %w", err)
	}
	// Bağlantıyı test et
	if err = pgPool.Ping(context.Background()); err != nil {
		return fmt.Errorf("PostgreSQL ping hatası: %w", err)
	}
	// Şemayı oluştur
	if _, err = pgPool.Exec(context.Background(), schema); err != nil {
		return fmt.Errorf("Şema oluşturma hatası: %w", err)
	}
	fmt.Println("[+] PostgreSQL bağlantısı kuruldu ve şema hazır.")
	return nil
}

// ── Worker Goroutine'leri ────────────────────────────────────────────────────

func startWorker() {
	// Ana drain döngüsü: her 500ms Redis'ten PG'ye aktar
	go func() {
		for {
			drainRedis()
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Kalibrasyon job'ı: her gece 02:00'da çalışır
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 2, 0, 0, 0, now.Location())
			time.Sleep(time.Until(next))
			runCalibration()
		}
	}()
}

// ── Redis → PostgreSQL ───────────────────────────────────────────────────────

func drainRedis() {
	if rdb == nil || pgPool == nil {
		return
	}
	keys := []string{
		"sentinel:metrics",
		"sentinel:process_new",
		"sentinel:network_new",
		"sentinel:etw_process_start",
		"sentinel:etw_process_stop",
		"sentinel:ebpf_exec",
		"sentinel:ebpf_fork",
		"sentinel:ebpf_exit",
		"sentinel:ebpf_uid_change",
	}
	for _, key := range keys {
		for {
			// Non-blocking: liste boşsa hemen çık
			result, err := rdb.RPop(ctx, key).Result()
			if err != nil {
				break
			}
			var data map[string]interface{}
			if err := json.Unmarshal([]byte(result), &data); err != nil {
				continue
			}
			insertEvent(data, result)
		}
	}
}

func insertEvent(data map[string]interface{}, raw string) {
	agentID, _   := data["agent_id"].(string)
	osName, _    := data["os"].(string)
	eventType, _ := data["type"].(string)
	tsFloat, _   := data["ts"].(float64)
	ts := int64(tsFloat)

	if agentID == "" || eventType == "" {
		return
	}

	// events tablosuna yaz
	_, err := pgPool.Exec(ctx,
		`INSERT INTO events (agent_id, os, type, ts, raw)
		 VALUES ($1, $2, $3, $4, $5::jsonb)`,
		agentID, osName, eventType, ts, raw,
	)
	if err != nil {
		fmt.Printf("[!] DB yazma hatası (%s): %v\n", eventType, err)
		return
	}

	// Ajan baseline kaydı yoksa oluştur (ilk görülme zamanını kaydet)
	pgPool.Exec(ctx,
		`INSERT INTO agent_baseline (agent_id, os, calib_start)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (agent_id) DO NOTHING`,
		agentID, osName, ts,
	)
}

// ── Kalibrasyon ──────────────────────────────────────────────────────────────

func runCalibration() {
	if pgPool == nil {
		return
	}
	sevenDaysAgo := time.Now().Unix() - 7*24*3600

	// 7+ gün veri birikmiş, kalibre edilmemiş ajanları bul
	rows, err := pgPool.Query(ctx,
		`SELECT agent_id FROM agent_baseline
		 WHERE calibrated = FALSE AND calib_start < $1`,
		sevenDaysAgo,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	var agents []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		agents = append(agents, id)
	}

	for _, agentID := range agents {
		calibrateAgent(agentID, sevenDaysAgo)
	}
}

func calibrateAgent(agentID string, since int64) {
	// CPU / RAM istatistikleri
	var cpuMean, cpuStd, ramMean, ramStd float64
	pgPool.QueryRow(ctx,
		`SELECT
			COALESCE(AVG((raw->>'cpu_percent')::float), 0),
			COALESCE(STDDEV((raw->>'cpu_percent')::float), 0),
			COALESCE(AVG((raw->>'ram_percent')::float), 0),
			COALESCE(STDDEV((raw->>'ram_percent')::float), 0)
		 FROM events
		 WHERE agent_id = $1 AND type = 'metrics' AND ts > $2`,
		agentID, since,
	).Scan(&cpuMean, &cpuStd, &ramMean, &ramStd)

	// Bilinen processler: {"chrome.exe": 12.4, "svchost.exe": 150.1} (günlük frekans)
	procRows, _ := pgPool.Query(ctx,
		`SELECT raw->>'pname', COUNT(*)::float / 7.0
		 FROM events
		 WHERE agent_id = $1 AND type = 'process_new' AND ts > $2
		 GROUP BY raw->>'pname'`,
		agentID, since,
	)
	knownProcs := map[string]float64{}
	if procRows != nil {
		defer procRows.Close()
		for procRows.Next() {
			var name string
			var freq float64
			procRows.Scan(&name, &freq)
			knownProcs[name] = freq
		}
	}

	// Bilinen IP'ler
	ipRows, _ := pgPool.Query(ctx,
		`SELECT raw->>'remote_ip', COUNT(*)
		 FROM events
		 WHERE agent_id = $1 AND type = 'network_new' AND ts > $2
		 GROUP BY raw->>'remote_ip'`,
		agentID, since,
	)
	knownIPs := map[string]int{}
	if ipRows != nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var ip string
			var cnt int
			ipRows.Scan(&ip, &cnt)
			knownIPs[ip] = cnt
		}
	}

	// Ortalama bağlantı sayısı
	var avgConns float64
	pgPool.QueryRow(ctx,
		`SELECT COALESCE(COUNT(*)::float / 7.0, 0)
		 FROM events
		 WHERE agent_id = $1 AND type = 'network_new' AND ts > $2`,
		agentID, since,
	).Scan(&avgConns)

	procsJSON, _ := json.Marshal(knownProcs)
	ipsJSON, _   := json.Marshal(knownIPs)

	pgPool.Exec(ctx,
		`UPDATE agent_baseline SET
			calibrated      = TRUE,
			calib_end       = $1,
			cpu_mean        = $2,
			cpu_std         = $3,
			ram_mean        = $4,
			ram_std         = $5,
			avg_connections = $6,
			known_processes = $7::jsonb,
			known_ips       = $8::jsonb,
			updated_at      = $1
		 WHERE agent_id = $9`,
		time.Now().Unix(),
		cpuMean, cpuStd,
		ramMean, ramStd,
		avgConns,
		string(procsJSON),
		string(ipsJSON),
		agentID,
	)

	fmt.Printf("[+] Kalibrasyon tamamlandı: %s | CPU: %.1f±%.1f%% | RAM: %.1f±%.1f%% | %d process tanındı\n",
		agentID, cpuMean, cpuStd, ramMean, ramStd, len(knownProcs))
}
