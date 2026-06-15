"""
Davranışsal Anomali Tespiti — Kural Motoru + Isolation Forest
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# ── Kural Tabloları ───────────────────────────────────────────────────────────

MALICIOUS_NAMES: dict[str, tuple[int, str]] = {
    "mimikatz.exe":    (98, "credential_theft"),
    "mimikatz":        (98, "credential_theft"),
    "meterpreter.exe": (98, "rat"),
    "nc.exe":          (85, "backdoor"),
    "ncat.exe":        (85, "backdoor"),
    "ncat":            (85, "backdoor"),
    "xmrig.exe":       (92, "cryptominer"),
    "xmrig":           (92, "cryptominer"),
    "psexec.exe":      (78, "lateral_movement"),
    "psexesvc.exe":    (78, "lateral_movement"),
    "lazagne.exe":     (95, "credential_theft"),
    "lazagne":         (95, "credential_theft"),
    "wce.exe":         (98, "credential_theft"),
    "procdump.exe":    (85, "credential_theft"),    # lsass dump
    "sharphound.exe":  (90, "reconnaissance"),
    "rubeus.exe":      (95, "credential_theft"),
    "cobalt strike":   (99, "c2_framework"),
    "beacon.exe":      (99, "c2_framework"),
    "metasploit":      (99, "c2_framework"),
}

CMDLINE_PATTERNS: list[tuple[str, int, str]] = [
    # PowerShell obfuscation & abuse
    (r"powershell.*-e(nc|ncodedcommand)\s",         90, "obfuscated_ps"),
    (r"powershell.*bypass",                          80, "policy_bypass"),
    (r"powershell.*hidden",                          70, "hidden_ps"),
    (r"powershell.*-nop.*-w\s+hidden",               85, "hidden_ps"),
    (r"powershell.*iex\s*\(",                        88, "ps_invoke_expr"),
    (r"powershell.*downloadstring",                  85, "ps_download"),
    (r"powershell.*\[convert\]::frombase64",         88, "obfuscated_ps"),

    # Certutil abuse (downloader)
    (r"certutil.*-(urlcache|decode|decodehex)",      88, "dropper"),

    # Regsvr32 / COM hijack
    (r"regsvr32.*/s.*/u.*/i(:http|\s+http)",         92, "squiblydoo"),
    (r"regsvr32.*scrobj",                            90, "squiblydoo"),

    # Mshta abuse
    (r"mshta.*(http|vbscript|javascript)",           88, "mshta_abuse"),

    # Rundll32 abuse
    (r"rundll32.*javascript:",                       90, "rundll32_js"),
    (r"rundll32.*\\temp\\",                          80, "rundll32_temp"),
    (r"rundll32.*,control_rundll",                   75, "rundll32_cpl"),

    # WMIC lateral movement
    (r"wmic.*process.*call.*create",                 88, "wmic_exec"),
    (r"wmic.*/node:.*process",                       85, "wmic_remote"),

    # Forfiles abuse
    (r"forfiles.*/c.*cmd",                           80, "forfiles_exec"),

    # LOLBin persistence/execution
    (r"ie4uinit.*-basesettings",                     85, "lolbin_exec"),
    (r"pcalua.*-a\s",                                85, "lolbin_exec"),
    (r"syncappvpublishingserver",                    80, "lolbin_exec"),
    (r"appsyncpublishingserver",                     80, "lolbin_exec"),

    # Ransomware indicators
    (r"vssadmin.*(delete|resize).*shadows",          97, "ransomware"),
    (r"bcdedit.*(recoveryenabled|bootstatuspolicy)", 92, "ransomware"),
    (r"wbadmin.*delete.*(catalog|backup)",           97, "ransomware"),
    (r"schtasks.*/delete.*/f",                       70, "anti_forensics"),

    # Privilege escalation
    (r"net.*localgroup.*administrators.*/add",       92, "privilege_escalation"),
    (r"net.*user.*/add",                             82, "account_creation"),
    (r"net.*user.*\$",                               85, "hidden_account"),  # hidden user

    # Persistence
    (r"schtasks.*/create.*/ru.*(system|trustedinstaller)", 78, "persistence"),
    (r"reg.*add.*\\run",                             75, "registry_persistence"),
    (r"reg.*add.*\\runonce",                         75, "registry_persistence"),

    # Downloader
    (r"bitsadmin.*transfer.*(http|ftp)",             82, "dropper"),
    (r"curl.*(http|ftp).*-o\s",                      70, "dropper"),
    (r"wget.*(http|ftp)\s",                          70, "dropper"),

    # Credential access
    (r"sekurlsa",                                    99, "credential_theft"),  # mimikatz cmd
    (r"lsadump",                                     99, "credential_theft"),
    (r"procdump.*(lsass|system)",                    95, "credential_theft"),
    (r"task(list|kill).*lsass",                      90, "credential_theft"),

    # Data exfiltration
    (r"copy.*/b.*http",                              80, "exfiltration"),
    (r"ftp.*(open|put|send)",                        75, "exfiltration"),
]

# ── Parent-Child Anomali Kuralları ────────────────────────────────────────────
# (parent_pname, child_pname, score, threat_type, description)
PARENT_CHILD_RULES: list[tuple[str, str, int, str, str]] = [
    # Office ürünleri → shell
    ("winword.exe",    "cmd.exe",        92, "office_macro", "Word → CMD (makro)"),
    ("winword.exe",    "powershell.exe", 95, "office_macro", "Word → PowerShell"),
    ("excel.exe",      "cmd.exe",        92, "office_macro", "Excel → CMD"),
    ("excel.exe",      "powershell.exe", 95, "office_macro", "Excel → PowerShell"),
    ("outlook.exe",    "cmd.exe",        90, "phishing",     "Outlook → CMD (phishing)"),
    ("outlook.exe",    "powershell.exe", 92, "phishing",     "Outlook → PowerShell"),
    ("mspub.exe",      "cmd.exe",        88, "office_macro", "Publisher → CMD"),
    ("onenote.exe",    "cmd.exe",        88, "phishing",     "OneNote → CMD"),

    # Tarayıcılar → shell (drive-by download)
    ("chrome.exe",     "cmd.exe",        85, "browser_exploit", "Chrome → CMD"),
    ("msedge.exe",     "cmd.exe",        85, "browser_exploit", "Edge → CMD"),
    ("firefox.exe",    "cmd.exe",        85, "browser_exploit", "Firefox → CMD"),
    ("iexplore.exe",   "cmd.exe",        88, "browser_exploit", "IE → CMD"),
    ("iexplore.exe",   "powershell.exe", 90, "browser_exploit", "IE → PowerShell"),

    # System process'lerden shell (exploit)
    ("svchost.exe",    "cmd.exe",        88, "service_exploit", "svchost → CMD"),
    ("svchost.exe",    "powershell.exe", 90, "service_exploit", "svchost → PowerShell"),
    ("lsass.exe",      "cmd.exe",        99, "lsass_exploit",   "LSASS → CMD (kritik!)"),
    ("services.exe",   "cmd.exe",        90, "service_exploit", "services → CMD"),
    ("wininit.exe",    "cmd.exe",        95, "system_exploit",  "wininit → CMD"),

    # WMI / Task Scheduler
    ("wmiprvse.exe",   "cmd.exe",        85, "wmi_exec",        "WMI → CMD"),
    ("wmiprvse.exe",   "powershell.exe", 88, "wmi_exec",        "WMI → PowerShell"),
    ("taskeng.exe",    "cmd.exe",        75, "scheduled_task",  "TaskEng → CMD"),
    ("taskhost.exe",   "powershell.exe", 80, "scheduled_task",  "TaskHost → PowerShell"),
]


SUSPICIOUS_PORTS: dict[int, tuple[int, str]] = {
    4444:  (92, "metasploit"),
    4445:  (87, "reverse_shell"),
    1337:  (78, "c2_common"),
    6666:  (72, "c2_common"),
    6667:  (72, "irc_c2"),
    31337: (82, "elite_backdoor"),
    8888:  (62, "c2_common"),
    9999:  (62, "c2_common"),
    443:   (0,  "none"),  # normal HTTPS — puan verme
    5985:  (78, "winrm"),   # WinRM
    5986:  (78, "winrm"),
    22:    (55, "ssh"),     # SSH — bağlama göre
    3389:  (60, "rdp"),     # RDP
    135:   (65, "dcom"),    # DCOM
    139:   (65, "smb"),     # SMB
    445:   (65, "smb"),
}


@dataclass
class RuleResult:
    score:       int = 0
    threat_type: str = "none"
    triggered:   list[str] = field(default_factory=list)


def apply_rules(event: dict, parent_pname: str = "") -> RuleResult:
    r     = RuleResult()
    etype = event.get("type", "")

    # ── Process eventi ────────────────────────────────────────────────────────
    if etype in ("process_new", "ebpf_exec", "etw_process_start"):
        pname   = (event.get("pname",   "") or "").lower().strip()
        cmdline = (event.get("cmdline", "") or "").lower()
        ppid    = int(event.get("ppid", 0) or 0)

        # 1. Bilinen kötü process isimleri
        for name, (score, ttype) in MALICIOUS_NAMES.items():
            if pname == name.lower():
                if score > r.score:
                    r.score = score
                    r.threat_type = ttype
                r.triggered.append(f"known_malware:{name}")
                break

        # 2. Cmdline pattern eşleşmesi
        for pattern, score, ttype in CMDLINE_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                if score > r.score:
                    r.score = score
                    r.threat_type = ttype
                r.triggered.append(f"cmdline:{ttype}")

        # 3. SYSTEM olarak çalışan şüpheli shell
        username = (event.get("username", "") or "").lower()
        if ("system" in username or "nt authority" in username) and pname in (
            "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"
        ):
            if r.score < 74:
                r.score = 74
                r.threat_type = "suspicious_system_shell"
            r.triggered.append("system_shell")

        # 4. Parent-child anomali kontrolü
        pname_lower = pname
        parent_lower = parent_pname.lower().strip() if parent_pname else ""
        if parent_lower:
            for (par, chld, score, ttype, desc) in PARENT_CHILD_RULES:
                if par.lower() == parent_lower and chld.lower() == pname_lower:
                    if score > r.score:
                        r.score = score
                        r.threat_type = ttype
                    r.triggered.append(f"parent_child:{desc}")
                    break

    # ── Ağ eventi ─────────────────────────────────────────────────────────────
    elif etype == "network_new":
        port = int(event.get("remote_port", 0) or 0)
        if port in SUSPICIOUS_PORTS and SUSPICIOUS_PORTS[port][0] > 0:
            score, ttype = SUSPICIOUS_PORTS[port]
            if score > r.score:
                r.score = score
                r.threat_type = ttype
            r.triggered.append(f"suspicious_port:{port}")

        # Gece saati (00:00-06:00) ağ bağlantısı şüpheli
        hour = time.gmtime().tm_hour
        if 0 <= hour < 6 and port not in (80, 443):
            bonus = 15
            if r.score + bonus > r.score:
                r.score = min(100, r.score + bonus)
            r.triggered.append(f"off_hours_network:UTC{hour:02d}h")

    # ── Metrics eventi ────────────────────────────────────────────────────────
    elif etype == "metrics":
        cpu = float(event.get("cpu_percent", 0) or 0)
        ram = float(event.get("ram_percent",  0) or 0)
        if cpu > 95:
            if r.score < 48:
                r.score = 48
                r.threat_type = "cpu_spike"
            r.triggered.append(f"high_cpu:{cpu:.0f}%")
        if ram > 95:
            if r.score < 42:
                r.score = 42
                r.threat_type = "ram_spike"
            r.triggered.append(f"high_ram:{ram:.0f}%")

    # ── UID Change eventi (Privilege Escalation) ─────────────────────────────────
    elif etype == "ebpf_uid_change":
        old_uid = int(event.get("old_uid", 0))
        new_uid = int(event.get("new_uid", 0))
        pname   = event.get("pname", "")
        if old_uid != 0 and new_uid == 0:
            r.score = 95
            r.threat_type = "privilege_escalation"
            r.triggered.append(f"uid_to_root:{pname}")

    return r


# ── Isolation Forest ──────────────────────────────────────────────────────────

class BehavioralAnalyzer:
    MODEL_DIR = Path("models/behavioral")

    def __init__(self):
        self.MODEL_DIR.mkdir(parents=True, exist_ok=True)
        self._models: dict[str, IsolationForest] = {}

    def _path(self, agent_id: str) -> Path:
        return self.MODEL_DIR / f"{agent_id.replace('/', '_')}.joblib"

    def is_calibrated(self, agent_id: str) -> bool:
        return agent_id in self._models or self._path(agent_id).exists()

    def train(self, agent_id: str, baseline: dict) -> bool:
        return self.train_with_data(agent_id, baseline, [])

    def train_with_data(self, agent_id: str, baseline: dict, metrics: list[dict]) -> bool:
        try:
            X_list = []
            for m in metrics:
                feat = self._event_features(m, baseline)
                if feat is not None:
                    X_list.append(feat)

            if len(X_list) < 10:
                # Yeterli gerçek veri yoksa sentetik üreterek bir başlangıç modeli oluştur.
                feat = self._baseline_features(baseline)
                if feat is None:
                    # Baseline tamamen boşsa (yeni ajan), default vektör oluştur
                    feat = np.array([0.0, 1.0, 0.0, 1.0, 0.0, 0.0, 0.0], dtype=np.float32)
                np.random.seed(42)
                X = np.tile(feat, (100, 1)) + np.random.randn(100, len(feat)) * 0.05
            else:
                X = np.array(X_list)

            model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
            model.fit(X)
            self._models[agent_id] = model
            joblib.dump(model, self._path(agent_id))
            print(f"[+] IsolationForest trained for {agent_id[:8]} with {len(X)} samples.")
            return True
        except Exception as e:
            print(f"[!] Behavioral train hatası ({agent_id}): {e}")
            return False

    def load(self, agent_id: str) -> bool:
        p = self._path(agent_id)
        if p.exists() and agent_id not in self._models:
            self._models[agent_id] = joblib.load(p)
        return agent_id in self._models

    def score_event(self, agent_id: str, event: dict, baseline: dict) -> float:
        self.load(agent_id)
        z = self._zscore(event, baseline)
        if_s = 0.0
        if agent_id in self._models:
            feat = self._event_features(event, baseline)
            if feat is not None:
                raw  = self._models[agent_id].decision_function([feat])[0]
                if_s = max(0.0, min(100.0, (-raw + 0.1) * 200))
        return round(max(z, 0.4 * z + 0.6 * if_s), 2)

    # ── Feature helpers ───────────────────────────────────────────────────────

    def _baseline_features(self, b: dict) -> Optional[np.ndarray]:
        try:
            return np.array([
                float(b.get("cpu_mean", 0)),
                float(b.get("cpu_std",  1)),
                float(b.get("ram_mean", 0)),
                float(b.get("ram_std",  1)),
                float(b.get("avg_connections", 0)),
                float(len(b.get("known_processes", {}))),
                float(len(b.get("known_ips", {}))),
            ], dtype=np.float32)
        except Exception:
            return None

    def _event_features(self, event: dict, b: dict) -> Optional[np.ndarray]:
        try:
            cpu  = float(event.get("cpu_percent", b.get("cpu_mean", 0)))
            ram  = float(event.get("ram_percent",  b.get("ram_mean", 0)))
            pname = event.get("pname", "")
            freq  = float(b.get("known_processes", {}).get(pname, 0))
            ip    = event.get("remote_ip", "")
            ip_k  = 1.0 if ip in b.get("known_ips", {}) else 0.0
            return np.array([
                cpu, float(b.get("cpu_std", 1)),
                ram, float(b.get("ram_std", 1)),
                float(b.get("avg_connections", 0)),
                freq, ip_k,
            ], dtype=np.float32)
        except Exception:
            return None

    def _zscore(self, event: dict, b: dict) -> float:
        scores = []
        etype  = event.get("type", "")

        if etype == "metrics":
            for fld, mk, sk in [
                ("cpu_percent", "cpu_mean", "cpu_std"),
                ("ram_percent", "ram_mean", "ram_std"),
            ]:
                val = float(event.get(fld, 0))
                mu  = float(b.get(mk, 0))
                sig = float(b.get(sk, 1))
                if sig > 0.1:
                    z = abs(val - mu) / sig
                    scores.append(min(100.0, z / 3.0 * 100))

        elif etype in ("process_new", "ebpf_exec", "etw_process_start"):
            pname = event.get("pname", "")
            known = b.get("known_processes", {})
            if pname not in known:
                scores.append(75.0)
            elif float(known[pname]) < 0.5:
                scores.append(45.0)

        elif etype == "network_new":
            ip    = event.get("remote_ip", "")
            known = b.get("known_ips", {})
            if ip and ip not in known:
                scores.append(55.0)

        return max(scores) if scores else 0.0
