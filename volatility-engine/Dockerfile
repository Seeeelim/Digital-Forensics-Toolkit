FROM python:3.11-slim

# 1. Installer les dépendances système minimales pour Volatility3
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpcre2-dev \
  && rm -rf /var/lib/apt/lists/*

# 2. Travailler dans /app
WORKDIR /app

# 3. Installer les dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copier le code de l’application
COPY . .

# 5. Port par défaut pour Cloud Run
ENV PORT=8080

# 6. Lancer l’app Flask via gunicorn
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 600 analyse:app

ENV GUNICORN_CMD_ARGS="--timeout 600"
