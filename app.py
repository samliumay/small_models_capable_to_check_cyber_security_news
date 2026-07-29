"""Gradio arayüzü ve Hugging Face Spaces giriş noktası."""

from __future__ import annotations

import json
import os
from typing import Any

import gradio as gr

from ollama import OllamaLocalModelManagement


MODEL = OllamaLocalModelManagement()
MODEL_CHOICES = {
    "1B · Qwen3.5 0.8B — en hızlı": "qwen3.5:0.8b",
    "4B · Qwen3.5 — ekonomik": "qwen3.5:4b",
    "9B · Qwen3.5 — dengeli": "qwen3.5:9b",
    "35B · Qwen3.6 — en yüksek kalite": "qwen3.6:latest",
}
MODEL_LABELS = {value: label for label, value in MODEL_CHOICES.items()}
DEFAULT_MODEL = (
    MODEL.model_name
    if MODEL.model_name in MODEL_LABELS
    else MODEL_CHOICES["4B · Qwen3.5 — ekonomik"]
)
EMPTY_STATS = (
    "📊 **Son işlem:** Henüz istek yok · "
    "Token değerleri, tüm model ve araç turlarının toplamını gösterir."
)

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
    selected_model: str,
    top_k: int,
    top_p: float,
    temperature: float,
):
    """Kullanıcı sorusunu işle ve her araç eyleminden sonra arayüzü güncelle."""
    display = list(display_history or [])
    state = list(conversation or [])
    if not message or not message.strip():
        yield "", display, state, EMPTY_STATS
        return

    user_text = message.strip()
    display.append({"role": "user", "content": user_text})
    if selected_model not in MODEL_LABELS:
        selected_model = DEFAULT_MODEL
    model_label = MODEL_LABELS[selected_model]
    status_text = f"⏳ **Çalışıyor:** {model_label}"
    yield "", display, state, status_text

    agent = OllamaLocalModelManagement(
        model_name=selected_model,
        base_url=MODEL.base_url,
        tools=MODEL.tools,
        temperature=temperature,
        top_k=int(top_k),
        top_p=top_p,
    )

    try:
        model_ready = agent.model_is_available()
    except Exception as exc:
        error_text = f"⚠️ Model durumu kontrol edilemedi: {exc}"
        display.append(
            {
                "role": "assistant",
                "content": error_text,
                "metadata": {"title": "Model bağlantı hatası", "status": "done"},
            }
        )
        yield "", display, state, error_text
        return

    if not model_ready:
        display.append(
            {
                "role": "assistant",
                "content": (
                    f"`{selected_model}` ilk kullanım için Ollama registry'den indiriliyor. "
                    "Model boyutuna göre bu işlem birkaç dakika sürebilir."
                ),
                "metadata": {
                    "title": f"📦 Model hazırlanıyor · {model_label}",
                    "status": "pending",
                },
            }
        )
        yield "", display, state, f"📦 **Model indiriliyor:** {model_label}"
        try:
            agent.ensure_model()
        except Exception as exc:
            error_text = f"⚠️ Model indirilemedi: {exc}"
            display[-1] = {
                "role": "assistant",
                "content": error_text,
                "metadata": {
                    "title": f"Model indirilemedi · {model_label}",
                    "status": "done",
                },
            }
            yield "", display, state, error_text
            return
        display[-1] = {
            "role": "assistant",
            "content": f"`{selected_model}` indirildi ve kullanıma hazır.",
            "metadata": {
                "title": f"📦 Model hazır · {model_label}",
                "status": "done",
            },
        }
        yield "", display, state, status_text

    final_text: str | None = None
    final_stats = status_text
    for event in agent.run(user_text, state):
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
                    f"toplam: {metrics.get('total_tokens')} token"
                    if metrics.get("total_tokens") is not None
                    else "",
                    f"{metrics.get('turns')} tur"
                    if metrics.get("turns") is not None
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
            final_stats = (
                f"📊 **Son işlem:** {model_label} · "
                f"girdi **{metrics.get('prompt_tokens', 0)}** · "
                f"çıktı **{metrics.get('response_tokens', 0)}** · "
                f"toplam **{metrics.get('total_tokens', 0)} token** · "
                f"**{metrics.get('turns', 0)} tur** · "
                f"**{metrics.get('total_duration_seconds', 0)} sn**"
            )
        elif event["type"] == "error":
            final_text = f"⚠️ {event['content']}"
            final_stats = f"⚠️ **İşlem tamamlanamadı:** {model_label}"
            display.append(
                {
                    "role": "assistant",
                    "content": final_text,
                    "metadata": {"title": "Hata", "status": "done"},
                }
            )
        yield "", display, state, final_stats

    if final_text:
        state.extend(
            [
                {"role": "user", "content": user_text},
                {"role": "assistant", "content": final_text},
            ]
        )
        state = state[-20:]
    yield "", display, state, final_stats


def clear_chat():
    return [], [], EMPTY_STATS


def configuration_text() -> str:
    optional = {
        "NewsAPI": bool(os.getenv("NEWSAPI_KEY")),
        "NVD API anahtarı": bool(os.getenv("NVD_API_KEY")),
        "AlienVault OTX": bool(os.getenv("OTX_API_KEY")),
        "MISP": bool(os.getenv("MISP_BASE_URL") and os.getenv("MISP_API_KEY")),
    }
    lines = [
        f"**Ollama:** `{MODEL.base_url}`",
        "**Seçilebilir modeller:** 1B, 4B, 9B, 35B",
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
    stats = gr.Markdown(EMPTY_STATS, elem_classes=["status-card"])
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
            gr.Markdown("### Model")
            model_selector = gr.Dropdown(
                choices=list(MODEL_CHOICES.items()),
                value=DEFAULT_MODEL,
                label="Model seçimi",
                info="Eksik model ilk kullanımda otomatik indirilir.",
            )
            with gr.Accordion("Gelişmiş üretim ayarları", open=False):
                temperature_control = gr.Slider(
                    minimum=0.0,
                    maximum=2.0,
                    value=float(os.getenv("OLLAMA_TEMPERATURE", "0.2")),
                    step=0.05,
                    label="Temperature",
                    info="Düşük değer daha tutarlı, yüksek değer daha çeşitli yanıt üretir.",
                )
                top_k_control = gr.Slider(
                    minimum=1,
                    maximum=100,
                    value=int(os.getenv("OLLAMA_TOP_K", "20")),
                    step=1,
                    label="Top-K",
                    info="Her adımda değerlendirilecek en olası token sayısı.",
                )
                top_p_control = gr.Slider(
                    minimum=0.05,
                    maximum=1.0,
                    value=float(os.getenv("OLLAMA_TOP_P", "0.95")),
                    step=0.05,
                    label="Top-P",
                    info="Olasılık kütlesine göre dinamik token havuzu.",
                )
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
        inputs=[
            prompt,
            chatbot,
            conversation_state,
            model_selector,
            top_k_control,
            top_p_control,
            temperature_control,
        ],
        outputs=[prompt, chatbot, conversation_state, stats],
        api_name="sor",
    )
    send.click(
        respond,
        inputs=[
            prompt,
            chatbot,
            conversation_state,
            model_selector,
            top_k_control,
            top_p_control,
            temperature_control,
        ],
        outputs=[prompt, chatbot, conversation_state, stats],
        api_name=False,
    )
    clear.click(
        clear_chat,
        outputs=[chatbot, conversation_state, stats],
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
