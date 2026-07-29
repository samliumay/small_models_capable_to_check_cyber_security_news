FROM ollama/ollama:latest

# Ollama imajındaki varsayılan entrypoint, verilen her komutu `ollama ...`
# olarak çalıştırır. Space başlangıç betiğini doğrudan çalıştırabilmek için sıfırla.
ENTRYPOINT []

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=7860 \
    OLLAMA_BASE_URL=http://127.0.0.1:11434 \
    OLLAMA_HOST=127.0.0.1:11434 \
    OLLAMA_MODEL=qwen3.5:4b \
    OLLAMA_NUM_PARALLEL=1 \
    OLLAMA_MAX_LOADED_MODELS=1

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        ca-certificates \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

# Güncel Ollama image'ında UID 1000, `ubuntu` kullanıcısı olarak hazır gelir.
RUN mkdir -p /home/ubuntu/.ollama \
    && chown -R ubuntu:ubuntu /home/ubuntu /app

COPY --chown=ubuntu:ubuntu . /app
RUN chmod +x /app/start.sh

USER ubuntu
ENV HOME=/home/ubuntu

EXPOSE 7860

CMD ["/app/start.sh"]
