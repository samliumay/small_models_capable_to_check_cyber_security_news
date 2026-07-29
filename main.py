"""Yerel çalıştırma giriş noktası."""

import gradio as gr

from app import CSS, demo


if __name__ == "__main__":
    demo.queue(default_concurrency_limit=4).launch(css=CSS, theme=gr.themes.Soft())
