"""Ollama üzerinde çok adımlı, araç kullanan siber güvenlik asistanı."""

from __future__ import annotations

import json
import os
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


class OllamaLocalModelManagement:
    """Ollama `/api/chat` uç noktası için sınırlı bir ajan döngüsü."""

    def __init__(
        self,
        model_name: str | None = None,
        base_url: str | None = None,
        tools: CyberSecurityTools | None = None,
        session: requests.Session | None = None,
        max_tool_rounds: int = 6,
    ) -> None:
        self.model_name = model_name or os.getenv("OLLAMA_MODEL", "qwen3.6:latest")
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip(
            "/"
        )
        self.session = session or requests.Session()
        self.tools = tools or CyberSecurityTools()
        self.max_tool_rounds = max(1, min(max_tool_rounds, 10))

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
                "temperature": float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
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

        for turn in range(1, self.max_tool_rounds + 2):
            try:
                response = self._chat_request(messages)
            except OllamaConnectionError as exc:
                yield {"type": "error", "content": str(exc)}
                return

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
                        "prompt_tokens": response.get("prompt_eval_count"),
                        "response_tokens": response.get("eval_count"),
                        "total_duration_seconds": round(
                            (response.get("total_duration") or 0) / 1_000_000_000, 2
                        ),
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
            headers = {}
            if api_key := os.getenv("OLLAMA_API_KEY"):
                headers["Authorization"] = f"Bearer {api_key}"
            response = self.session.get(
                f"{self.base_url}/api/tags", headers=headers, timeout=(3, 10)
            )
            response.raise_for_status()
            models = [item.get("name") for item in response.json().get("models", [])]
            return {
                "ok": self.model_name in models,
                "model": self.model_name,
                "available_models": models,
                "base_url": self.base_url,
            }
        except (requests.RequestException, ValueError) as exc:
            return {"ok": False, "model": self.model_name, "error": str(exc)}


# Eski dosyayı kullanan kodlar için geriye dönük uyumluluk.
ollama_local_model_managment = OllamaLocalModelManagement
