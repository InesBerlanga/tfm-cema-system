"""Fábrica de clientes ChatOpenAI apuntando a los endpoints vLLM.

vLLM expone una API OpenAI-compatible, por lo que ChatOpenAI de langchain-openai
es válido para chat completions clásicas (system/user → texto). Nota: LangChain
avisa de que campos no estándar (p. ej. reasoning_content) podrían no extraerse;
en nuestro caso no nos afecta porque parseamos JSON de la respuesta manualmente.

Los endpoints y nombres de modelo se configuran en .env (ver .env.example).
"""

import os
from typing import Literal

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()

ModelKey = Literal["gpt", "gpt-oss-b", "gemma"]


def _endpoint_config(key: ModelKey) -> tuple[str, str]:
    """Devuelve (base_url, model_name) para una clave de endpoint."""
    if key == "gpt":
        return (
            os.getenv("GPT_OSS_URL", "http://localhost:8000/v1"),
            os.getenv("GPT_OSS_MODEL", "gpt-oss-20b"),
        )
    if key == "gpt-oss-b":
        return (
            os.getenv("GPT_OSS_URL_B", "http://localhost:8001/v1"),
            os.getenv("GPT_OSS_MODEL", "gpt-oss-20b"),
        )
    if key == "gemma":
        return (
            os.getenv("GEMMA_URL", "http://localhost:8003/v1"),
            os.getenv("GEMMA_MODEL", "gemma-4-26b-a4b"),
        )
    raise ValueError(f"Endpoint desconocido: {key}")


def get_llm(
    model: ModelKey, #= "gpt-oss",
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> ChatOpenAI:
    """Devuelve un ChatOpenAI listo para usar.

    temperature baja (0.1) ⇒ salida más determinista para clasificación.
    """
    base_url, model_name = _endpoint_config(model)
    return ChatOpenAI(
        base_url=base_url,
        api_key="not-needed",      # los endpoints locales no requieren key
        model=model_name,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=60,
        max_retries=2,
    )
