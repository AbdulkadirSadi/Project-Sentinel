"""
MalImg veri seti hazırlık scripti
===================================
MalImg'nin 25 malware ailesini modelimizin 9 kategorisine eşler,
train/val split oluşturur ve doğru klasör yapısını hazırlar.

Kullanım:
    python training/prepare_malimg.py --src data/ --dst data/

Sonuç:
    data/train/<kategori>/*.png
    data/val/<kategori>/*.png
"""

import argparse
import shutil
import random
from pathlib import Path

# MalImg aile → model kategorisi eşlemesi
FAMILY_MAP = {
    # Worm
    "Allaple.A":       "worm",
    "Allaple.L":       "worm",
    "Autorun.K":       "worm",
    "Yuner.A":         "worm",
    # Trojan
    "Agent.FYI":       "trojan",
    "Alueron.gen!J":   "trojan",
    "Fakerean":        "trojan",
    "Lolyda.AA1":      "trojan",
    "Lolyda.AA2":      "trojan",
    "Lolyda.AA3":      "trojan",
    "Lolyda.AT":       "trojan",
    "Malex.gen!J":     "trojan",
    "Skintrim.N":      "trojan",
    # Backdoor / RAT
    "C2LOP.P":         "backdoor",
    "C2LOP.gen!g":     "backdoor",
    "Rbot!gen":        "backdoor",
    "VB.AT":           "backdoor",
    # Adware / Spyware
    "Adialer.C":       "adware",
    "Dialplatform.B":  "adware",
    "Instantaccess":   "adware",
    "Swizzor.gen!E":   "adware",
    "Swizzor.gen!I":   "adware",
    "Wintrim.BX":      "adware",
    # Dropper / Obfuscator
    "Dontovo.A":       "dropper",
    "Obfuscator.AD":   "dropper",
}

CATEGORIES = [
    "benign", "ransomware", "trojan", "worm", "backdoor",
    "adware", "spyware", "dropper", "cryptominer",
]


def find_malimg_root(src: Path) -> Path:
    """İndirilmiş MalImg'nin köküni bul."""
    # Olası klasör isimleri
    candidates = [
        src / "malimg_paper_img_samples",
        src / "malimg",
        src / "MalImg",
        src,
    ]
    for c in candidates:
        if c.exists():
            # İçinde bilinen bir aile varsa bu kök
            known = set(FAMILY_MAP.keys())
            children = {p.name for p in c.iterdir() if p.is_dir()}
            if children & known:
                return c
    raise FileNotFoundError(
        f"MalImg klasörü bulunamadı: {src}\n"
        "Beklenen klasörlerden biri: malimg_paper_img_samples/, malimg/, ..."
    )


def prepare(src: Path, dst: Path, val_ratio: float = 0.2, seed: int = 42):
    random.seed(seed)

    # data/malimg_dataset/train|val|test/<aile>/ yapısını algıla
    malimg_root = src / "malimg_dataset" if (src / "malimg_dataset").exists() else src
    print(f"[+] Veri seti kökü: {malimg_root}")

    for split in ("train", "val"):
        split_dir = malimg_root / split
        if not split_dir.exists():
            print(f"  [!] {split_dir} bulunamadı, atlanıyor.")
            continue

        print(f"\n── {split.upper()} ──")
        for family_dir in sorted(split_dir.iterdir()):
            if not family_dir.is_dir():
                continue
            family   = family_dir.name
            category = FAMILY_MAP.get(family)
            if not category:
                print(f"  [?] Eşleme yok, atlanıyor: {family}")
                continue

            images = list(family_dir.glob("*.png")) + list(family_dir.glob("*.jpg"))
            if not images:
                continue

            out_dir = dst / split / category
            out_dir.mkdir(parents=True, exist_ok=True)
            for img in images:
                shutil.copy2(img, out_dir / f"{family}_{img.name}")

            print(f"  {family:<25} → {category:<12} | {len(images):4d} görüntü")

    print(f"\n[✓] Hazırlık tamamlandı → {dst}/train/  ve  {dst}/val/")
    print(f"\n[*] Eğitimi başlatmak için:")
    print(f"    python training/train_static.py --data_dir {dst} --preconverted --epochs 30 --batch_size 64")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default="data/",  help="malimg_dataset/ klasörünün üst dizini")
    parser.add_argument("--dst", default="data/",  help="train/val çıktı klasörü")
    parser.add_argument("--val_ratio", type=float, default=0.2)
    args = parser.parse_args()

    prepare(Path(args.src), Path(args.dst), args.val_ratio)

