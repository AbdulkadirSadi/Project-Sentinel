"""
Statik PE Analiz Modeli — Inference
Eğitilmiş EfficientNet-B0 modelini yükleyip yeni PE dosyalarını tahmin eder.
"""

import io
import base64
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from PIL import Image
from torchvision import transforms
import timm

CLASSES = [
    "benign",
    "ransomware",
    "trojan",
    "worm",
    "backdoor",
    "adware",
    "spyware",
    "dropper",
    "cryptominer",
]

IMG_SIZE = 224

_transform = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
])


def pe_to_image(data: bytes, size: int = IMG_SIZE) -> Image.Image:
    """Ham PE byte'ı grayscale görüntüye dönüştürür (Nataraj yöntemi).
    StaticAnalyzer (multiclass) tarafından kullanılır."""
    arr = np.frombuffer(data, dtype=np.uint8)
    n = len(arr)
    if   n < 10_000:   w = 32
    elif n < 30_000:   w = 64
    elif n < 60_000:   w = 128
    elif n < 100_000:  w = 256
    elif n < 200_000:  w = 384
    elif n < 500_000:  w = 512
    elif n < 1_000_000:w = 768
    else:              w = 1024

    h = int(np.ceil(n / w))
    padded = np.zeros(h * w, dtype=np.uint8)
    padded[:n] = arr
    img = Image.fromarray(padded.reshape(h, w), mode="L")
    img = img.resize((size, size), Image.LANCZOS)
    return img.convert("RGB")


def pe_to_rgb_image(data: bytes, size: int = IMG_SIZE) -> Image.Image:
    """Ham PE byte'ı RGB görüntüye dönüştürür (3-byte-per-pixel yöntemi).
    BinaryAnalyzer tarafından kullanılır — binary_model.pt eğitim verisiyle AYNI dönüşüm."""
    pixels = []
    i = 0
    while i + 3 <= len(data):
        pixels.append((data[i], data[i + 1], data[i + 2]))
        i += 3
    if not pixels:
        raise ValueError("Görsel oluşturulamadı (dosya çok küçük)")
    width = int(np.sqrt(len(pixels))) + 1
    img = Image.new("RGB", (width, width))
    img.putdata(pixels)
    img = img.resize((size, size), Image.LANCZOS)
    return img


class StaticAnalyzer:
    def __init__(self, model_path: str = "models/static_model.pt"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.classes = CLASSES
        self._load(model_path)

    def _load(self, path: str):
        if not Path(path).exists():
            print(f"[!] Statik model bulunamadı: {path}. Yalnızca eğitim sonrası kullanılabilir.")
            return
        ckpt = torch.load(path, map_location=self.device)
        self.classes = ckpt.get("classes", CLASSES)
        self.model = timm.create_model(
            ckpt.get("arch", "efficientnet_b0"),
            pretrained=False,
            num_classes=len(self.classes),
        )
        self.model.load_state_dict(ckpt["model_state"])
        self.model.eval().to(self.device)
        print(f"[+] Statik model yüklendi: {path} (val_acc={ckpt.get('val_acc', '?'):.4f})")

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(self, pe_bytes: bytes) -> dict:
        """
        PE byte'larını alır, tahmin döndürür.

        Döndürür:
          {
            "threat_type": "ransomware",
            "confidence": 0.91,
            "is_malware": True,
            "scores": {"benign": 0.02, "ransomware": 0.91, ...}
          }
        """
        if not self.is_ready():
            return {"error": "model_not_loaded"}

        try:
            img = pe_to_image(pe_bytes)
        except Exception as e:
            return {"error": f"pe_to_image hatası: {e}"}

        tensor = _transform(img).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            probs  = F.softmax(logits, dim=1).squeeze().cpu().numpy()

        top_idx  = int(np.argmax(probs))
        top_cls  = self.classes[top_idx]
        top_prob = float(probs[top_idx])

        return {
            "threat_type": top_cls,
            "confidence":  round(top_prob, 4),
            "is_malware":  top_cls != "benign",
            "risk_score":  round((1 - probs[0]) * 100, 2),   # benign dışı olasılık
            "scores":      {cls: round(float(p), 4) for cls, p in zip(self.classes, probs)},
        }

    def predict_from_base64(self, b64: str) -> dict:
        """Base64 kodlu PE dosyasını tahmin eder (API endpoint'i için)."""
        try:
            pe_bytes = base64.b64decode(b64)
        except Exception as e:
            return {"error": f"base64 decode hatası: {e}"}
        return self.predict(pe_bytes)


# ── Binary Triage Analyzer (Aşama 1) ─────────────────────────────────────────

class BinaryAnalyzer:
    """
    İki aşamalı pipeline'ın 1. aşaması.
    binary_model.pt kullanarak PE dosyasını hızlıca
    'benign' veya 'malicious' olarak sınıflandırır.
    """

    def __init__(self, model_path: str = "models/binary_model.pt"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model  = None
        self._load(model_path)

    def _load(self, path: str):
        if not Path(path).exists():
            print(f"[!] Binary model bulunamadı: {path}. Triage devre dışı.")
            return
        try:
            ckpt = torch.load(path, map_location=self.device, weights_only=False)
            arch = ckpt.get("arch", "efficientnet_b0")
            self.model = timm.create_model(arch, pretrained=False, num_classes=1)
            self.model.load_state_dict(ckpt["model_state"])
            self.model.eval().to(self.device)
            val_acc = ckpt.get("val_acc", 0.0)
            print(f"[+] Binary model yüklendi: {path}  (val_acc={val_acc:.4f}  device={self.device})")
        except Exception as e:
            print(f"[!] Binary model yüklenemedi: {e}")

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(self, pe_bytes: bytes) -> dict:
        """
        PE byte'larını alır, binary tahmin döndürür.

        Döndürür:
          {
            "verdict":             "malicious" | "benign",
            "is_malware":          True | False,
            "malware_probability": 0.91,
            "confidence":          0.91,
            "method":              "binary_triage"
          }
        """
        if not self.is_ready():
            return {"error": "binary_model_not_loaded"}

        try:
            img = pe_to_rgb_image(pe_bytes)
        except Exception as e:
            return {"error": f"pe_to_image hatası: {e}"}

        tensor = _transform(img).unsqueeze(0).to(self.device)
        with torch.no_grad():
            logit = self.model(tensor)
            prob  = float(torch.sigmoid(logit).squeeze().cpu())

        # Threshold: 0.70 — false positive oranını azaltır
        # (0.50–0.69 arası "belirsiz" bölge → temiz sayılır)
        THRESHOLD = 0.70
        is_malicious = prob > THRESHOLD
        confidence   = round(prob if is_malicious else 1.0 - prob, 4)

        return {
            "verdict":             "malicious" if is_malicious else "benign",
            "is_malware":          is_malicious,
            "malware_probability": round(prob, 4),
            "confidence":          confidence,
            "method":              "binary_triage",
        }

    def predict_from_base64(self, b64: str) -> dict:
        """Base64 kodlu PE dosyasını tahmin eder."""
        try:
            pe_bytes = base64.b64decode(b64)
        except Exception as e:
            return {"error": f"base64 decode hatası: {e}"}
        return self.predict(pe_bytes)
