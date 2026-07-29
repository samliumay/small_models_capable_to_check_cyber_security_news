"""Ollama üzerinde çok adımlı, araç kullanan siber güvenlik asistanı."""

from __future__ import annotations

import json
import os
import threading
import time
from copy import deepcopy
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import requests

from .cyber_security_tools import CyberSecurityTools


SYSTEM_PROMPT = """Sen güncel siber güvenlik haberleri ve zafiyetleri konusunda çalışan,
Türkçe yanıt veren bir analiz asistanısın.

Kurallar:
1. Güncellik içeren sorularda belleğine güvenme; uygun aracı mutlaka kullan.
2. Gerekirse birden fazla aracı ve birden fazla turu kullan. Örneğin önce son CVE'leri
   bul, sonra önemli bir CVE için ayrıntı aracını çağır.
3. Araç sonucu olmayan güncel bir iddiayı kesin bilgi gibi sunma.
4. Kaynakların tarihini, kaynak adını ve varsa doğrudan URL'sini nihai yanıtta belirt.
5. CVSS puanı ile aktif istismarı birbirine karıştırma. CISA KEV kaydı aktif istismar
   açısından daha güçlü bir göstergedir.
6. Veri bulunamazsa veya kaynak hata verirse bunu açıkça söyle; bilgi uydurma.
7. Yanıtı Türkçe, öz ve okunaklı yaz. CVE kimliklerini aynen koru.
8. Kullanıcı savunma ve risk azaltma önerileri isterse uygulanabilir öneriler sun.
9. Zararlı veya yetkisiz eylemleri kolaylaştıran operasyonel talimatlar verme.
10. Araç çağrılarının kullanıcı arayüzünde ayrıca gösterildiğini bil; nihai cevapta
    ham JSON'u tekrar etme, bulguları sentezle.
"""


class OllamaConnectionError(RuntimeError):
    """Ollama sunucusuna erişilemediğinde kullanılır."""


_MODEL_PULL_LOCK = threading.Lock()


class OllamaLocalModelManagement:
    """Ollama `/api/chat` uç noktası için sınırlı bir ajan döngüsü."""

    def __init__(
        self,
        model_name: str | None = None,
        base_url: str | None = None,
        tools: CyberSecurityTools | None = None,
        session: requests.Session | None = None,
        max_tool_rounds: int = 6,
        temperature: float | None = None,
        top_k: int | None = None,
        top_p: float | None = None,
    ) -> None:
        self.model_name = model_name or os.getenv("OLLAMA_MODEL", "qwen3.6:latest")
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip(
            "/"
        )
        self.session = session or requests.Session()
        self.tools = tools or CyberSecurityTools()
        self.max_tool_rounds = max(1, min(max_tool_rounds, 10))
        self.temperature = max(
            0.0,
            min(
                float(
                    temperature
                    if temperature is not None
                    else os.getenv("OLLAMA_TEMPERATURE", "0.2")
                ),
                2.0,
            ),
        )
        self.top_k = max(
            1,
            min(
                int(top_k if top_k is not None else os.getenv("OLLAMA_TOP_K", "20")),
                100,
            ),
        )
        self.top_p = max(
            0.05,
            min(
                float(top_p if top_p is not None else os.getenv("OLLAMA_TOP_P", "0.95")),
                1.0,
            ),
        )

    def _system_message(self) -> dict[str, str]:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        return {
            "role": "system",
            "content": f"{SYSTEM_PROMPT}\nŞu anki UTC zaman: {now}",
        }

    def _chat_request(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        payload = {
            "model": self.model_name,
            # Ajan döngüsü `messages` listesini daha sonra büyütür; istek anındaki
            # denetlenebilir görüntüyü korumak için kopyala.
            "messages": deepcopy(messages),
            "tools": self.tools.schemas,
            "stream": False,
            "think": False,
            "options": {
                "temperature": self.temperature,
                "top_k": self.top_k,
                "top_p": self.top_p,
                "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "16384")),
            },
            "keep_alive": os.getenv("OLLAMA_KEEP_ALIVE", "10m"),
        }
        headers = {}
        if api_key := os.getenv("OLLAMA_API_KEY"):
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            response = self.session.post(
                f"{self.base_url}/api/chat",
                json=payload,
                headers=headers,
                timeout=(10, int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "300"))),
            )
            response.raise_for_status()
            data = response.json()
        except requests.ConnectionError as exc:
            raise OllamaConnectionError(
                f"Ollama sunucusuna ulaşılamadı ({self.base_url}). "
                "`ollama serve` komutuyla sunucuyu başlatın."
            ) from exc
        except requests.Timeout as exc:
            raise OllamaConnectionError("Ollama yanıt süresini aştı.") from exc
        except (requests.HTTPError, ValueError) as exc:
            detail = ""
            if "response" in locals():
                detail = response.text[:500]
            raise OllamaConnectionError(
                f"Ollama isteği başarısız oldu: {detail or exc}"
            ) from exc
        if not isinstance(data.get("message"), dict):
            raise OllamaConnectionError("Ollama geçerli bir `message` alanı döndürmedi.")
        return data

    def _auth_headers(self) -> dict[str, str]:
        if api_key := os.getenv("OLLAMA_API_KEY"):
            return {"Authorization": f"Bearer {api_key}"}
        return {}

    def available_models(self) -> list[str]:
        """Ollama sunucusunda indirilmiş model adlarını döndür."""
        try:
            response = self.session.get(
                f"{self.base_url}/api/tags",
                headers=self._auth_headers(),
                timeout=(5, 20),
            )
            response.raise_for_status()
            return [
                item["name"]
                for item in response.json().get("models", [])
                if isinstance(item.get("name"), str)
            ]
        except (requests.RequestException, ValueError, KeyError) as exc:
            raise OllamaConnectionError(
                f"Ollama model listesi alınamadı: {exc}"
            ) from exc

    def model_is_available(self) -> bool:
        requested = self.model_name.removesuffix(":latest")
        return any(
            name == self.model_name or name.removesuffix(":latest") == requested
            for name in self.available_models()
        )

    def ensure_model(self) -> dict[str, Any]:
        """Seçili model eksikse Ollama registry'den kontrollü biçimde indir."""
        if self.model_is_available():
            return {"model": self.model_name, "downloaded": False}

        with _MODEL_PULL_LOCK:
            if self.model_is_available():
                return {"model": self.model_name, "downloaded": False}
            try:
                response = self.session.post(
                    f"{self.base_url}/api/pull",
                    headers=self._auth_headers(),
                    json={"model": self.model_name, "stream": False},
                    timeout=(
                        10,
                        int(os.getenv("OLLAMA_PULL_TIMEOUT_SECONDS", "3600")),
                    ),
                )
                response.raise_for_status()
                data = response.json()
            except requests.Timeout as exc:
                raise OllamaConnectionError(
                    f"{self.model_name} modeli indirilirken zaman aşımı oluştu."
                ) from exc
            except (requests.RequestException, ValueError) as exc:
                detail = ""
                if "response" in locals():
                    detail = response.text[:500]
                raise OllamaConnectionError(
                    f"{self.model_name} modeli indirilemedi: {detail or exc}"
                ) from exc
            if data.get("status") != "success":
                raise OllamaConnectionError(
                    f"Ollama model indirmeyi tamamlamadı: {data.get('status', data)}"
                )
            return {"model": self.model_name, "downloaded": True}

    @staticmethod
    def _conversation_messages(history: list[dict[str, Any]] | None) -> list[dict[str, str]]:
        clean: list[dict[str, str]] = []
        for item in history or []:
            role, content = item.get("role"), item.get("content")
            if role in {"user", "assistant"} and isinstance(content, str) and content.strip():
                clean.append({"role": role, "content": content})
        return clean[-20:]

    def run(
        self, user_message: str, history: list[dict[str, Any]] | None = None
    ) -> Generator[dict[str, Any], None, None]:
        """Araç ve nihai yanıt olaylarını sırayla üretir."""
        if not user_message or not user_message.strip():
            yield {"type": "error", "content": "Lütfen bir soru yazın."}
            return

        messages: list[dict[str, Any]] = [
            self._system_message(),
            *self._conversation_messages(history),
            {"role": "user", "content": user_message.strip()},
        ]
        total_prompt_tokens = 0
        total_response_tokens = 0
        total_duration_ns = 0

        for turn in range(1, self.max_tool_rounds + 2):
            try:
                response = self._chat_request(messages)
            except OllamaConnectionError as exc:
                yield {"type": "error", "content": str(exc)}
                return

            total_prompt_tokens += response.get("prompt_eval_count") or 0
            total_response_tokens += response.get("eval_count") or 0
            total_duration_ns += response.get("total_duration") or 0
            assistant_message = response["message"]
            messages.append(assistant_message)
            tool_calls = assistant_message.get("tool_calls") or []

            if not tool_calls:
                content = (assistant_message.get("content") or "").strip()
                if not content:
                    content = "Model boş bir yanıt döndürdü."
                yield {
                    "type": "final",
                    "turn": turn,
                    "content": content,
                    "metrics": {
                        "model": self.model_name,
                        "prompt_tokens": total_prompt_tokens,
                        "response_tokens": total_response_tokens,
                        "total_tokens": total_prompt_tokens + total_response_tokens,
                        "total_duration_seconds": round(total_duration_ns / 1_000_000_000, 2),
                        "turns": turn,
                    },
                }
                return

            if turn > self.max_tool_rounds:
                yield {
                    "type": "error",
                    "content": (
                        f"Güvenlik sınırı nedeniyle {self.max_tool_rounds} araç turundan "
                        "sonra işlem durduruldu."
                    ),
                }
                return

            visible_note = (assistant_message.get("content") or "").strip()
            if visible_note:
                yield {"type": "note", "turn": turn, "content": visible_note}

            for index, call in enumerate(tool_calls, start=1):
                function = call.get("function") or {}
                name = function.get("name", "")
                arguments = function.get("arguments") or {}
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        arguments = {"_gecersiz_ham_parametre": arguments}
                if not isinstance(arguments, dict):
                    arguments = {"_gecersiz_parametre": arguments}

                started = time.monotonic()
                result = self.tools.execute(name, arguments)
                duration = round(time.monotonic() - started, 2)
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": name,
                        "content": self.tools.to_json(result),
                    }
                )
                yield {
                    "type": "tool",
                    "turn": turn,
                    "index": index,
                    "name": name,
                    "arguments": arguments,
                    "result": result,
                    "duration_seconds": duration,
                }

        yield {"type": "error", "content": "Beklenmeyen ajan döngüsü sonu."}

    def health(self) -> dict[str, Any]:
        try:
            models = self.available_models()
            return {
                "ok": self.model_name in models,
                "model": self.model_name,
                "available_models": models,
                "base_url": self.base_url,
            }
        except (OllamaConnectionError, requests.RequestException, ValueError) as exc:
            return {"ok": False, "model": self.model_name, "error": str(exc)}


# Eski dosyayı kullanan kodlar için geriye dönük uyumluluk.
ollama_local_model_managment = OllamaLocalModelManagement
