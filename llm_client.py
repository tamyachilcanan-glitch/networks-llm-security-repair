"""
Cliente de OpenAI para el proyecto REDES.

Reutiliza el prompt y los extractores historicos.
No ejecuta solicitudes al importar este modulo.
"""

import os
import time

from openai import OpenAI

from config import (
    MODEL,
    API_TIMEOUT_SECONDS,
    API_MAX_RETRIES,
)

from repair import (
    OFFICIAL_PROMPT,
    extract_patch,
    extract_claim,
    extract_confidence,
)


def create_client():
    api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY no esta configurada"
        )

    return OpenAI(
        api_key=api_key,
        max_retries=API_MAX_RETRIES,
        timeout=API_TIMEOUT_SECONDS,
    )


def request_repair(prompt):
    """
    Realiza una solicitud de reparacion a OpenAI.

    NO utilizar esta funcion para regenerar
    los seis experimentos historicos.
    """
    client = create_client()

    start = time.perf_counter()

    response = client.responses.create(
        model=MODEL,
        input=prompt,
    )

    latency_ms = (
        time.perf_counter() - start
    ) * 1000

    text = response.output_text

    return {
        "response": response,
        "response_text": text,
        "patch": extract_patch(text),
        "claimed_success": extract_claim(text),
        "confidence": extract_confidence(text),
        "latency_ms": latency_ms,
    }
