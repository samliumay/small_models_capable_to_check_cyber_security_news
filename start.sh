#!/usr/bin/env bash
set -Eeuo pipefail

MODEL_NAME="${OLLAMA_MODEL:-qwen3.5:4b}"
MODEL_DIR="${OLLAMA_MODELS:-${HOME}/.ollama/models}"

export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
export OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
export OLLAMA_MODELS="${MODEL_DIR}"

mkdir -p "${OLLAMA_MODELS}"

echo "Ollama sunucusu başlatılıyor: ${OLLAMA_HOST}"
ollama serve &
OLLAMA_PID=$!

READY=false
for _ in $(seq 1 120); do
    if ollama list >/dev/null 2>&1; then
        READY=true
        break
    fi
    if ! kill -0 "${OLLAMA_PID}" >/dev/null 2>&1; then
        echo "Hata: Ollama sunucusu beklenmedik şekilde kapandı." >&2
        exit 1
    fi
    sleep 1
done

if [[ "${READY}" != "true" ]]; then
    echo "Hata: Ollama sunucusu 120 saniye içinde hazır olmadı." >&2
    exit 1
fi

if ollama show "${MODEL_NAME}" >/dev/null 2>&1; then
    echo "Model hazır: ${MODEL_NAME}"
else
    echo "Model indiriliyor: ${MODEL_NAME}"
    ollama pull "${MODEL_NAME}"
fi

echo "Gradio başlatılıyor: ${GRADIO_SERVER_NAME:-0.0.0.0}:${GRADIO_SERVER_PORT:-7860}"
exec python /app/app.py
