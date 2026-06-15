"""
YARA Kural Tarayıcısı — Sentinel XDR
======================================
yara_rules/ dizinindeki tüm .yar/.yara dosyalarını yükler,
ham binary veriyi tarar ve eşleşen kuralları döndürür.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional

try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    print("[!] yara-python yüklü değil. YARA taraması devre dışı.")
    print("    Kur: pip install yara-python")


class YaraScanner:
    def __init__(self, rules_dir: str = "yara_rules"):
        self.rules_dir  = Path(rules_dir)
        self.rules: Optional[object] = None  # yara.Rules
        self._rule_count = 0
        self._load_rules()

    # ── Yükleme ────────────────────────────────────────────────────────────────

    def _load_rules(self) -> None:
        """Kural dizinindeki tüm .yar ve .yara dosyalarını derler (disabled olanları atlar)."""
        if not _YARA_AVAILABLE:
            return

        disabled = self._load_disabled()

        files: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for f in self.rules_dir.glob(ext):
                if f.name not in disabled:
                    files[f.stem] = str(f)

        if not files:
            print(f"[YARA] Aktif kural bulunamadı: {self.rules_dir.resolve()}")
            return

        try:
            self.rules = yara.compile(filepaths=files)  # type: ignore[attr-defined]
            self._rule_count = len(files)
            print(f"[+] YARA: {self._rule_count} kural dosyası yüklendi "
                  f"({', '.join(files.keys())})")
        except Exception as e:
            print(f"[!] YARA derleme hatası: {e}")

    def reload(self) -> None:
        """Kuralları yeniden yükler (hot-reload)."""
        self.rules = None
        self._load_rules()

    # ── Disabled Yönetimi ───────────────────────────────────────────────────────

    def _disabled_path(self) -> Path:
        return self.rules_dir / "disabled.json"

    def _load_disabled(self) -> set[str]:
        p = self._disabled_path()
        try:
            return set(json.loads(p.read_text())) if p.exists() else set()
        except Exception:
            return set()

    def _save_disabled(self, disabled: set[str]) -> None:
        self._disabled_path().write_text(json.dumps(sorted(disabled)), encoding="utf-8")

    def toggle_file(self, filename: str) -> bool:
        """
        Kural dosyasını etkinleştirir/devre dışı bırakır.
        Returns: True = şu an aktif, False = devre dışı
        """
        disabled = self._load_disabled()
        if filename in disabled:
            disabled.discard(filename)
        else:
            disabled.add(filename)
        self._save_disabled(disabled)
        self.reload()
        return filename not in disabled

    def disabled_files(self) -> set[str]:
        return self._load_disabled()

    # ── Tarama ─────────────────────────────────────────────────────────────────

    def is_ready(self) -> bool:
        return _YARA_AVAILABLE and self.rules is not None

    def scan(self, data: bytes) -> list[dict]:
        """
        Ham bytes'ı tarar.

        Returns:
            Eşleşen kuralların listesi:
            [{"rule": str, "description": str, "severity": str,
              "score": int, "tags": list[str]}]
        """
        if not self.is_ready():
            return []

        try:
            matches = self.rules.match(data=data)  # type: ignore[union-attr]
        except Exception as e:
            print(f"[YARA] Tarama hatası: {e}")
            return []

        results = []
        for m in matches:
            meta = m.meta
            results.append({
                "rule":        m.rule,
                "description": meta.get("description", ""),
                "severity":    meta.get("severity", "medium"),
                "score":       int(meta.get("score", 70)),
                "tags":        list(m.tags),
            })
        return results

    def scan_file(self, path: str) -> list[dict]:
        """Dosya yolunu doğrudan tarar (büyük dosyalar için daha verimli)."""
        if not self.is_ready():
            return []
        try:
            matches = self.rules.match(path)  # type: ignore[union-attr]
        except Exception as e:
            print(f"[YARA] Dosya tarama hatası {path}: {e}")
            return []

        results = []
        for m in matches:
            meta = m.meta
            results.append({
                "rule":        m.rule,
                "description": meta.get("description", ""),
                "severity":    meta.get("severity", "medium"),
                "score":       int(meta.get("score", 70)),
                "tags":        list(m.tags),
            })
        return results

    @property
    def rule_count(self) -> int:
        return self._rule_count
