FROM python:3.11-slim

WORKDIR /app

# Evita fallimenti pip su Render quando, per architettura/cache, serve compilare da sorgente
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Render imposta PORT; in locale (docker-compose) senza PORT resta 8000.
EXPOSE 8000

# Render inietta PORT; senza di essa il port scan fallisce ("no open ports detected").
CMD ["sh", "-c", "echo \"uvicorn binding port=${PORT:-8000}\" && exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
