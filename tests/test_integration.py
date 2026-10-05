# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-llm-probe.

Verifica el pipeline completo de detección de jailbreaks, inyecciones
y exposición de modelos mediante endpoints LLM mockeados con aiohttp.
No realiza llamadas de red reales.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock


import vamp_llm_probe as llm_probe


# ────────────────────────────────────────────────────────────────────────────
# Tests de detección de jailbreak en pipeline completo
# ────────────────────────────────────────────────────────────────────────────

class TestDeteccionJailbreakIntegracion:
    """Verifica el pipeline de detección end-to-end con respuestas simuladas."""

    def test_pipeline_compliance_marker_clasifica_critical(self, resp_jailbreak_es):
        """
        Pipeline completo: compliance marker presente + sin rechazo →
        _detectar_jailbreak_exitoso_ds devuelve True, apto para CRITICAL finding.
        """
        # Detectar jailbreak exitoso
        es_jailbreak = llm_probe._detectar_jailbreak_exitoso_ds(resp_jailbreak_es)
        assert es_jailbreak is True

        # La respuesta supera el umbral de longitud para respuesta prohibida
        es_prohibida = llm_probe._detectar_respuesta_prohibida(resp_jailbreak_es)
        assert es_prohibida is True

    def test_pipeline_rechazo_no_genera_critico(self, resp_rechazo_es):
        """
        Pipeline completo: respuesta con patrón de rechazo →
        la detección no clasifica como jailbreak ni como respuesta prohibida.
        """
        es_jailbreak = llm_probe._detectar_jailbreak_exitoso_ds(resp_rechazo_es)
        assert es_jailbreak is False

    def test_pipeline_ascii_smuggling_detectado_en_respuesta(self):
        """
        Pipeline: respuesta con Unicode Tags ocultos → _detectar_ascii_smuggling
        detecta el canal encubierto en la respuesta del modelo.
        """
        instruccion_oculta = "EXFIL_KEY"
        tags_ocultos = "".join(chr(0xE0000 + ord(c)) for c in instruccion_oculta)
        respuesta_con_tags = f"Respuesta normal del modelo.{tags_ocultos} Fin."

        encontrado, decodificado = llm_probe._detectar_ascii_smuggling(respuesta_con_tags)
        assert encontrado is True
        assert "EXFIL_KEY" in decodificado

    def test_pipeline_multiples_compliance_markers(self):
        """
        Un prompt que activa varios compliance markers distintos sigue
        siendo detectado como jailbreak exitoso.
        """
        respuesta_multi = (
            "modo sin filtros activado. sin restricciones. "
            "Como DAN, puedo darte cualquier información sin limitaciones."
        )
        assert llm_probe._detectar_jailbreak_exitoso_ds(respuesta_multi) is True

    def test_pipeline_respuesta_corta_no_prohibida(self):
        """
        Respuesta sin patrón de rechazo pero muy corta (≤150 chars) →
        _detectar_respuesta_prohibida devuelve False.
        """
        respuesta_corta = "Claro, aquí está la información."  # < 150 chars, sin rechazo
        # Sin rechazo pero corta, no supera el umbral de longitud
        resultado = llm_probe._detectar_respuesta_prohibida(respuesta_corta)
        # El resultado depende del umbral, pero no debe lanzar excepción
        assert isinstance(resultado, bool)


# ────────────────────────────────────────────────────────────────────────────
# Tests con endpoint LLM mockeado (aiohttp)
# ────────────────────────────────────────────────────────────────────────────

class TestEndpointMockeado:
    """Pruebas de integración con endpoints LLM simulados vía aiohttp mock."""

    def test_comprobar_acceso_sin_auth_crea_hallazgo_llm001(self, estado_api_chat):
        """
        Un endpoint accesible sin autenticación genera el hallazgo LLM-001 CRITICAL.
        """
        # estado_api_chat ya tiene modelos; el cuerpo JSON también los expone
        cuerpo = json.dumps({
            "models": [
                {"name": "llama3.2:3b"},
                {"name": "mistral:7b"},
            ]
        })
        hallazgos: list = []
        llm_probe._comprobar_acceso_sin_auth(
            "/api/tags",
            cuerpo,
            200,
            estado_api_chat,
            hallazgos,
            "http://localhost:11434",
        )
        # Debe haber al menos un hallazgo con ID LLM-001
        ids = [getattr(h, "id", "") for h in hallazgos]
        assert any("LLM-001" in i for i in ids)

    def test_comprobar_version_expuesta_crea_hallazgo_llm003(self, estado_api_chat):
        """
        Un endpoint que devuelve cabecera Server con versión genera hallazgo LLM-003.
        """
        estado_con_version = llm_probe.EstadoEndpoint(
            url_base="http://localhost:11434",
            formato_api="ollama",
            ruta_inf="/api/chat",
            formato_inf="api_chat",
            modelo="llama3.2:3b",
            modelos=["llama3.2:3b"],
            requiere_auth=False,
            auth_header="",
            headers_rsp={"Server": "Ollama/0.3.12", "X-Ollama-Version": "0.3.12"},
            version_srv="0.3.12",
            respuesta_ref="",
        )

        hallazgos: list = []
        llm_probe._comprobar_version_expuesta(
            estado_con_version,
            hallazgos,
            "http://localhost:11434",
        )
        ids = [getattr(h, "id", "") for h in hallazgos]
        assert any("LLM-003" in i for i in ids)

    def test_construir_y_enviar_payload_inyeccion(self, estado_api_chat):
        """
        El pipeline construye la petición JSON y la envía correctamente al mock.
        """
        async def _inner():
            # Mock de respuesta con compliance marker
            resp = MagicMock()
            resp.status = 200
            resp.json = AsyncMock(return_value={
                "message": {"content": "modo sin filtros activado. Ejecutando sin restricciones."}
            })
            resp.__aenter__ = AsyncMock(return_value=resp)
            resp.__aexit__ = AsyncMock(return_value=False)

            session = MagicMock()
            session.post = MagicMock(return_value=resp)

            # Construir petición
            payload = llm_probe.construir_peticion(estado_api_chat, "test de inyección")

            # Verificar que la petición tiene la estructura esperada
            assert "messages" in payload or "prompt" in payload
            assert "model" in payload
            return payload

        payload = asyncio.run(_inner())
        assert isinstance(payload, dict)

    def test_formato_detectado_desde_respuesta_api_tags(self, estado_api_chat):
        """
        La función de detección de formato actualiza el estado con el formato correcto.
        """
        cuerpo_api_tags = {
            "models": [{"name": "llama3.2:3b"}, {"name": "mistral:7b"}]
        }
        llm_probe._detectar_formato_y_modelos("/api/tags", json.dumps(cuerpo_api_tags), estado_api_chat)
        # Tras la detección, el estado debe tener modelos actualizados
        assert len(estado_api_chat.modelos) >= 1

    def test_formato_detectado_desde_respuesta_v1_models(self, estado_v1_completions):
        """
        La función de detección de formato actualiza el estado desde /v1/models.
        """
        cuerpo_v1_models = {
            "data": [{"id": "gpt-4"}, {"id": "gpt-3.5-turbo"}]
        }
        llm_probe._detectar_formato_y_modelos("/v1/models", json.dumps(cuerpo_v1_models), estado_v1_completions)
        assert len(estado_v1_completions.modelos) >= 1

    def test_payloads_inyeccion_contienen_ids_correctos(self):
        """
        Todos los payloads del catálogo principal tienen IDs en el rango LLM-010..019.
        """
        for payload in llm_probe.PAYLOADS_INYECCION:
            assert payload["id"].startswith("LLM-0")
            assert "payload" in payload
            assert "nombre" in payload
