FROM python:3.12-slim
WORKDIR /app

# Sistem bağımlılıkları (yara, opencv, pefile için)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# PyTorch CPU-only — GPU gerekmez, imaj boyutu küçük kalır
RUN pip install --no-cache-dir \
    torch==2.3.0+cpu torchvision==0.18.0+cpu \
    --index-url https://download.pytorch.org/whl/cpu

# Proje bağımlılıkları
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# yara-python (derleme gerektirir, ayrı adım)
RUN pip install --no-cache-dir yara-python==4.5.0

# Uygulama dosyaları (modeller ve yara_rules volume olarak bağlanır)
COPY . .

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
