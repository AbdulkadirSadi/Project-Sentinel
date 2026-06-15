"""
PE → Grayscale Görüntü Dönüşümü + CNN Eğitim Scripti
=====================================================
Veri seti: MalImg (https://img.poly.edu/malimg) — 9341 örnek, 25 malware ailesi
Önce indir: kaggle datasets download -d amauriciogonzalez/malimg-dataset
            veya: https://www.kaggle.com/datasets/amauriciogonzalez/malimg-dataset

Klasör yapısı bekleneni:
  data/
  ├── train/
  │   ├── benign/         ← temiz PE dosyaları (Windows system dosyaları vb.)
  │   ├── ransomware/
  │   ├── trojan/
  │   ├── worm/
  │   ├── backdoor/
  │   ├── adware/
  │   ├── spyware/
  │   ├── dropper/
  │   └── cryptominer/
  └── val/
      └── ...

Çalıştır:
  python training/train_static.py --data_dir data/ --epochs 30 --output models/static_model.pt
"""

import argparse
import os
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset
from torchvision import transforms
from PIL import Image
import timm  # pip install timm

# ── Sabitler ──────────────────────────────────────────────────────────────────

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
NUM_CLASSES = len(CLASSES)

# ── PE → Görüntü ──────────────────────────────────────────────────────────────

def pe_to_image(path: str, size: int = IMG_SIZE) -> Image.Image:
    """
    PE dosyasını byte dizisi olarak okuyup grayscale görüntüye çevirir.
    Nataraj et al. (2011) yöntemi — her byte bir piksel değeri (0-255).
    """
    with open(path, "rb") as f:
        data = np.frombuffer(f.read(), dtype=np.uint8)

    # Dosya boyutuna göre genişlik seç (Nataraj tablosu)
    n = len(data)
    if n < 10_000:
        w = 32
    elif n < 30_000:
        w = 64
    elif n < 60_000:
        w = 128
    elif n < 100_000:
        w = 256
    elif n < 200_000:
        w = 384
    elif n < 500_000:
        w = 512
    elif n < 1_000_000:
        w = 768
    else:
        w = 1024

    h = int(np.ceil(n / w))
    padded = np.zeros(h * w, dtype=np.uint8)
    padded[:n] = data
    img_array = padded.reshape(h, w)

    img = Image.fromarray(img_array, mode="L")          # Grayscale
    img = img.resize((size, size), Image.LANCZOS)       # Sabit boyuta getir
    img = img.convert("RGB")                            # EfficientNet 3 kanal bekler
    return img

# ── Dataset ───────────────────────────────────────────────────────────────────

class MalwareDataset(Dataset):
    """
    İki mod:
      1) PE dosyalarından anlık dönüşüm (slow, herhangi bir klasör yapısı)
      2) Önceden PNG'ye çevrilmiş görüntüler (fast)
    """
    def __init__(self, root: str, transform=None, preconverted: bool = False):
        self.root = Path(root)
        self.transform = transform
        self.preconverted = preconverted
        self.samples: list[tuple[Path, int]] = []

        for cls_idx, cls_name in enumerate(CLASSES):
            cls_dir = self.root / cls_name
            if not cls_dir.exists():
                continue
            ext = (".png", ".jpg") if preconverted else (".exe", ".dll", ".sys", ".bin")
            for f in cls_dir.iterdir():
                if f.suffix.lower() in ext:
                    self.samples.append((f, cls_idx))

        print(f"  {root}: {len(self.samples)} örnek, {NUM_CLASSES} sınıf")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        if self.preconverted:
            img = Image.open(path).convert("RGB")
        else:
            try:
                img = pe_to_image(str(path))
            except Exception:
                img = Image.new("RGB", (IMG_SIZE, IMG_SIZE))
        if self.transform:
            img = self.transform(img)
        return img, label

# ── Eğitim ────────────────────────────────────────────────────────────────────

def train(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[*] Cihaz: {device}")

    # Data augmentation (sadece train)
    train_tf = transforms.Compose([
        transforms.Resize((IMG_SIZE, IMG_SIZE)),
        transforms.RandomHorizontalFlip(),
        transforms.RandomRotation(10),
        transforms.ColorJitter(brightness=0.2, contrast=0.2),
        transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
    ])
    val_tf = transforms.Compose([
        transforms.Resize((IMG_SIZE, IMG_SIZE)),
        transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
    ])

    train_ds = MalwareDataset(
        os.path.join(args.data_dir, "train"), train_tf, args.preconverted
    )
    val_ds = MalwareDataset(
        os.path.join(args.data_dir, "val"), val_tf, args.preconverted
    )

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True,  num_workers=4)
    val_loader   = DataLoader(val_ds,   batch_size=args.batch_size, shuffle=False, num_workers=4)

    # EfficientNet-B0 — hafif, hızlı, yüksek doğruluk
    model = timm.create_model("efficientnet_b0", pretrained=True, num_classes=NUM_CLASSES)
    model = model.to(device)

    # Sınıf ağırlıkları (dengesiz veri seti için)
    class_counts = [0] * NUM_CLASSES
    for _, lbl in train_ds.samples:
        class_counts[lbl] += 1
    weights = torch.tensor(
        [max(class_counts) / (c + 1) for c in class_counts], dtype=torch.float32
    ).to(device)

    criterion = nn.CrossEntropyLoss(weight=weights)
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=args.epochs)

    best_val_acc = 0.0

    for epoch in range(1, args.epochs + 1):
        # ── Train ──
        model.train()
        train_loss, train_correct, train_total = 0.0, 0, 0
        for imgs, labels in train_loader:
            imgs, labels = imgs.to(device), labels.to(device)
            optimizer.zero_grad()
            out = model(imgs)
            loss = criterion(out, labels)
            loss.backward()
            optimizer.step()
            train_loss  += loss.item() * imgs.size(0)
            preds        = out.argmax(dim=1)
            train_correct += (preds == labels).sum().item()
            train_total   += imgs.size(0)
        scheduler.step()

        # ── Val ──
        model.eval()
        val_correct, val_total = 0, 0
        with torch.no_grad():
            for imgs, labels in val_loader:
                imgs, labels = imgs.to(device), labels.to(device)
                out   = model(imgs)
                preds = out.argmax(dim=1)
                val_correct += (preds == labels).sum().item()
                val_total   += imgs.size(0)

        val_acc = val_correct / max(val_total, 1)
        print(
            f"Epoch {epoch:3d}/{args.epochs} | "
            f"Train Loss: {train_loss/train_total:.4f} | "
            f"Train Acc: {train_correct/train_total:.4f} | "
            f"Val Acc: {val_acc:.4f}"
        )

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            torch.save(
                {
                    "model_state": model.state_dict(),
                    "classes": CLASSES,
                    "img_size": IMG_SIZE,
                    "arch": "efficientnet_b0",
                    "val_acc": val_acc,
                },
                args.output,
            )
            print(f"  → Model kaydedildi (val_acc={val_acc:.4f}): {args.output}")

    print(f"\n[✓] Eğitim tamamlandı. En iyi val_acc: {best_val_acc:.4f}")
    print(f"[✓] Model: {args.output}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentinel Statik Malware Sınıflandırıcısı Eğitimi")
    parser.add_argument("--data_dir",      default="data/",        help="train/ ve val/ alt klasörü olan kök")
    parser.add_argument("--output",        default="models/static_model.pt")
    parser.add_argument("--epochs",        type=int,   default=30)
    parser.add_argument("--batch_size",    type=int,   default=32)
    parser.add_argument("--lr",            type=float, default=1e-3)
    parser.add_argument("--preconverted",  action="store_true", help="Görüntüler zaten PNG ise bu bayrağı kullan")
    args = parser.parse_args()

    os.makedirs(Path(args.output).parent, exist_ok=True)
    train(args)
