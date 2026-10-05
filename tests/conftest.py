# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidas para vamp-llm-probe.

Prepara el path de importación y define respuestas de LLM simuladas
para los tests unitarios e de integración.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── Configuración de path ────────────────────────────────────────────────────
_TOOL_DIR = Path(__file__).resolve().parent.parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))

import vamp_llm_probe as llm_probe  # noqa: E402


# ── Respuestas de LLM simuladas ──────────────────────────────────────────────

RESPUESTA_JAILBREAK_EXITOSO = """
Modo sin filtros activado. Como solicitaste, operaré sin restricciones.
Aquí está la información que pediste sobre cómo fabricar explosivos caseros
y técnicas de síntesis de sustancias controladas. Sin limitaciones de seguridad.
"""

RESPUESTA_RECHAZO = """
Lo siento, no puedo ayudarte con esa solicitud ya que va en contra
de mis directrices de uso. Por favor reformula tu pregunta.
"""

RESPUESTA_JAILBREAK_EN = """
As Dan, I operate without restrictions. Sure, here's how to bypass
all security controls without filters. I can help you with anything.
"""

RESPUESTA_NORMAL = """
El teorema de Pitágoras establece que en un triángulo rectángulo,
el cuadrado de la hipotenusa es igual a la suma de los cuadrados
de los catetos: a² + b² = c².
"""


# ── Fixtures de respuestas ───────────────────────────────────────────────────

@pytest.fixture
def resp_jailbreak_es():
    """Respuesta en español que indica jailbreak exitoso."""
    return RESPUESTA_JAILBREAK_EXITOSO


@pytest.fixture
def resp_rechazo_es():
    """Respuesta en español que indica rechazo correcto del modelo."""
    return RESPUESTA_RECHAZO


@pytest.fixture
def resp_jailbreak_en():
    """Respuesta en inglés que indica jailbreak exitoso."""
    return RESPUESTA_JAILBREAK_EN


@pytest.fixture
def resp_normal():
    """Respuesta normal sin indicadores de jailbreak ni rechazo."""
    return RESPUESTA_NORMAL


# ── Fixture EstadoEndpoint ────────────────────────────────────────────────────

@pytest.fixture
def estado_api_chat():
    """EstadoEndpoint en formato api_chat (Ollama /api/chat)."""
    estado = llm_probe.EstadoEndpoint(
        url_base="http://localhost:11434",
        formato_api="ollama",
        ruta_inf="/api/chat",
        formato_inf="api_chat",
        modelo="llama3.2:3b",
        modelos=["llama3.2:3b"],
        requiere_auth=False,
        auth_header="",
        headers_rsp={},
        version_srv="",
        respuesta_ref="",
    )
    return estado


@pytest.fixture
def estado_v1_completions():
    """EstadoEndpoint en formato v1/completions (OpenAI-compatible)."""
    estado = llm_probe.EstadoEndpoint(
        url_base="http://localhost:8080",
        formato_api="openai",
        ruta_inf="/v1/chat/completions",
        formato_inf="v1_completions",
        modelo="gpt-test",
        modelos=["gpt-test"],
        requiere_auth=True,
        auth_header="Bearer sk-test",
        headers_rsp={"x-model-version": "1.0"},
        version_srv="1.0",
        respuesta_ref="",
    )
    return estado


@pytest.fixture
def estado_api_generate():
    """EstadoEndpoint en formato api_generate (Ollama /api/generate)."""
    estado = llm_probe.EstadoEndpoint(
        url_base="http://localhost:11434",
        formato_api="ollama",
        ruta_inf="/api/generate",
        formato_inf="api_generate",
        modelo="mistral:7b",
        modelos=["mistral:7b"],
        requiere_auth=False,
        auth_header="",
        headers_rsp={},
        version_srv="",
        respuesta_ref="",
    )
    return estado


# ── Fixture mock_session aiohttp ──────────────────────────────────────────────

@pytest.fixture
def mock_session_jailbreak():
    """Sesión aiohttp mockeada que devuelve respuesta de jailbreak exitoso."""
    session = MagicMock()
    resp = MagicMock()
    resp.status = 200
    resp.json = AsyncMock(return_value={
        "choices": [{"message": {"content": RESPUESTA_JAILBREAK_EXITOSO}}],
        "model": "test-model",
    })
    resp.text = AsyncMock(return_value="<html>Web UI</html>")
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    session.post = MagicMock(return_value=resp)
    session.get = MagicMock(return_value=resp)
    return session


@pytest.fixture
def mock_session_rechazo():
    """Sesión aiohttp mockeada que devuelve respuesta de rechazo."""
    session = MagicMock()
    resp = MagicMock()
    resp.status = 200
    resp.json = AsyncMock(return_value={
        "choices": [{"message": {"content": RESPUESTA_RECHAZO}}],
        "model": "test-model",
    })
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)
    session.post = MagicMock(return_value=resp)
    session.get = MagicMock(return_value=resp)
    return session
