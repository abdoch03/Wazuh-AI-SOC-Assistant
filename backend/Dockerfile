FROM python:3.13-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app


RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install -r requirements.txt

COPY config/ ./config/
COPY app.py wazuh_hybrid_system.py ./

RUN adduser --disabled-password --gecos '' appuser \
    && mkdir -p /app/database_data \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

# ✅ Healthcheck corrigé pour éviter l'authentification
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://localhost:5000/ || exit 1

CMD ["python", "app.py"]