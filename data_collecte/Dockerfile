FROM python:3.11-slim-bookworm

# Declare build-time arguments for sensitive environment variables
ARG MONGO_URI
ARG MONGO_DB_NAME
ARG WAZUH_MANAGER_PASSWORD
ARG WAZUH_INDEXER_PASSWORD

ENV MONGO_URI=${MONGO_URI}
ENV MONGO_DB_NAME=${MONGO_DB_NAME}
ENV WAZUH_MANAGER_PASSWORD=${WAZUH_MANAGER_PASSWORD}
ENV WAZUH_INDEXER_PASSWORD=${WAZUH_INDEXER_PASSWORD}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./

RUN pip install torch==2.8.0 --index-url https://download.pytorch.org/whl/cpu

RUN pip install -r requirements.txt

COPY . ./

ENV WAZUH_MANAGER_USER="wazuh"
ENV WAZUH_MANAGER_API_URL="https://192.168.1.100:55000"
ENV WAZUH_INDEXER_USER="admin"
ENV WAZUH_INDEXER_API_URL="https://192.168.1.100:9200"
ENV HUGGINGFACE_MODEL="sentence-transformers/all-MiniLM-L6-v2"
ENV VECTOR_DB_DIR="./chroma_db"

CMD ["python", "data_collecter_v2.py"]
