"""Gradio arayüzü ve Hugging Face Spaces giriş noktası."""

from __future__ import annotations

import json
import os
from typing import Any

import gradio as gr

from ollama import OllamaLocalModelManagement


MODEL = OllamaLocalModelManagement()

CSS = """
.gradio-container { max-width: 1120px !important; }
.hero { text-align: center; margin: 0 auto 1rem; }
.hero h1 { margin-bottom: .35rem; }
.hero p { color: var(--body-text-color-subdued); }
.status-card { border: 1px solid var(--border-color-primary); border-radius: 12px;
               padding: 12px 16px; background: var(--background-fill-secondary); }
"""


def _json_block(value: Any, max_chars: int = 14_000) -> str:
    text = json.dumps(value, ensure_ascii=False, indent=2, default=str)
    if len(text) > max_chars:
        text = f"{text[:max_chars]}\n… (arayüz için kısaltıldı)"
    return f"```json\n{text}\n```"


def _tool_message(event: dict[str, Any]) -> dict[str, Any]:
    name = event["name"]
    content = (
        f"**Çağrı**\n\n`{name}`\n\n"
        f"**Parametreler**\n\n{_json_block(event['arguments'])}\n\n"
        f"**Sonuç**\n\n{_json_block(event['result'])}"
    )
    return {
        "role": "assistant",
        "content": content,
        "metadata": {
            "title": f"🛠️ Tur {event['turn']} · {name}",
            "duration": event["duration_seconds"],
            "status": "done",
        },
    }


def respond(
    message: str,
    display_history: list[dict[str, Any]] | None,
    conversation: list[dict[str, str]] | None,
):
    """Kullanıcı sorusunu işle ve her araç eyleminden sonra arayüzü güncelle."""
    display = list(display_history or [])
    state = list(conversation or [])
    if not message or not message.strip():
        yield "", display, state
        return

    user_text = message.strip()
    display.append({"role": "user", "content": user_text})
    yield "", display, state

    final_text: str | None = None
    for event in MODEL.run(user_text, state):
        if event["type"] == "tool":
            display.append(_tool_message(event))
        elif event["type"] == "note":
            display.append(
                {
                    "role": "assistant",
                    "content": event["content"],
                    "metadata": {
                        "title": f"ℹ️ Tur {event['turn']} · Model notu",
                        "status": "done",
                    },
                }
            )
        elif event["type"] == "final":
            final_text = event["content"]
            metrics = event.get("metrics", {})
            metric_text = " · ".join(
                part
                for part in [
                    f"girdi: {metrics.get('prompt_tokens')} token"
                    if metrics.get("prompt_tokens") is not None
                    else "",
                    f"çıktı: {metrics.get('response_tokens')} token"
                    if metrics.get("response_tokens") is not None
                    else "",
                    f"{metrics.get('total_duration_seconds')} sn"
                    if metrics.get("total_duration_seconds")
                    else "",
                ]
                if part
            )
            display.append(
                {
                    "role": "assistant",
                    "content": final_text,
                    "metadata": (
                        {"title": f"✅ Nihai yanıt · Tur {event['turn']}", "log": metric_text}
                        if metric_text
                        else {"title": f"✅ Nihai yanıt · Tur {event['turn']}"}
                    ),
                }
            )
        elif event["type"] == "error":
            final_text = f"⚠️ {event['content']}"
            display.append(
                {
                    "role": "assistant",
                    "content": final_text,
                    "metadata": {"title": "Hata", "status": "done"},
                }
            )
        yield "", display, state

    if final_text:
        state.extend(
            [
                {"role": "user", "content": user_text},
                {"role": "assistant", "content": final_text},
            ]
        )
        state = state[-20:]
    yield "", display, state


def clear_chat():
    return [], []


def configuration_text() -> str:
    optional = {
        "NewsAPI": bool(os.getenv("NEWSAPI_KEY")),
        "NVD API anahtarı": bool(os.getenv("NVD_API_KEY")),
        "AlienVault OTX": bool(os.getenv("OTX_API_KEY")),
        "MISP": bool(os.getenv("MISP_BASE_URL") and os.getenv("MISP_API_KEY")),
    }
    lines = [
        f"**Model:** `{MODEL.model_name}`",
        f"**Ollama:** `{MODEL.base_url}`",
        "**Anahtarsız kaynaklar:** GDELT, CISA KEV, NVD, CISA RSS, CERT/CC, MITRE ATT&CK",
        "**İsteğe bağlı kaynaklar:** "
        + ", ".join(f"{name} {'✅' if enabled else '—'}" for name, enabled in optional.items()),
    ]
    return "\n\n".join(lines)


with gr.Blocks(title="Siber Güvenlik Haber Asistanı") as demo:
    gr.HTML(
        """
        <div class="hero">
          <h1>🛡️ Siber Güvenlik Haber Asistanı</h1>
          <p>Yerel Ollama modeli · Güncel CVE, KEV, haber ve tehdit istihbaratı</p>
        </div>
        """
    )
    conversation_state = gr.State([])
    with gr.Row():
        with gr.Column(scale=4):
            chatbot = gr.Chatbot(
                height=650,
                layout="panel",
                placeholder=(
                    "Bir soru sorun. Modelin yaptığı araç çağrıları ve aldığı sonuçlar "
                    "burada adım adım görünecek."
                ),
                show_label=False,
                buttons=["copy", "copy_all"],
            )
            with gr.Row():
                prompt = gr.Textbox(
                    placeholder="Örn. Son 24 saatteki önemli siber güvenlik haberleri neler?",
                    show_label=False,
                    lines=2,
                    max_lines=6,
                    scale=8,
                )
                send = gr.Button("Gönder", variant="primary", scale=1)
            clear = gr.Button("Sohbeti temizle", variant="secondary")
        with gr.Column(scale=1, min_width=260):
            gr.Markdown("### Yapılandırma")
            gr.Markdown(configuration_text(), elem_classes=["status-card"])
            gr.Markdown(
                """
                ### Örnek sorular

                - Son 24 saatteki önemli fidye yazılımı haberlerini özetle.
                - Son 7 günde yayımlanan kritik CVE'leri bul ve KEV durumlarını kontrol et.
                - CVE-2025-XXXX hakkında ne biliniyor?
                - Credential dumping için MITRE ATT&CK tekniklerini getir.

                > Kaynak sonuçları güncel olsa da kritik kararları özgün kaynaklardan doğrulayın.
                """
            )

    submit_event = prompt.submit(
        respond,
        inputs=[prompt, chatbot, conversation_state],
        outputs=[prompt, chatbot, conversation_state],
        api_name="sor",
    )
    send.click(
        respond,
        inputs=[prompt, chatbot, conversation_state],
        outputs=[prompt, chatbot, conversation_state],
        api_name=False,
    )
    clear.click(
        clear_chat,
        outputs=[chatbot, conversation_state],
        api_name=False,
        cancels=[submit_event],
    )


def launch_demo() -> None:
    """Yerel ve Docker Space ortamlarında Gradio sunucusunu başlat."""
    demo.queue(default_concurrency_limit=4).launch(
        css=CSS,
        theme=gr.themes.Soft(),
        server_name=os.getenv("GRADIO_SERVER_NAME", "127.0.0.1"),
        server_port=int(os.getenv("GRADIO_SERVER_PORT", "7860")),
    )


if __name__ == "__main__":
    launch_demo()
