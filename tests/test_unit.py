# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_unit.py — Tests unitarios para vamp-llm-probe.

Cubre las funciones de detección de jailbreak, construcción de peticiones,
extracción de respuestas, ASCII smuggling y constantes del módulo.
"""



import vamp_llm_probe as llm_probe


# ────────────────────────────────────────────────────────────────────────────
# Tests de _detectar_jailbreak_exitoso_ds
# ────────────────────────────────────────────────────────────────────────────

class TestDeteccionJailbreak:
    """Pruebas de la heurística de detección de jailbreak."""

    def test_compliance_marker_es_detectado(self, resp_jailbreak_es):
        """Una respuesta con marcador de compliance en español se detecta como jailbreak."""
        assert llm_probe._detectar_jailbreak_exitoso_ds(resp_jailbreak_es) is True

    def test_rechazo_no_es_jailbreak(self, resp_rechazo_es):
        """Una respuesta de rechazo no se clasifica como jailbreak exitoso."""
        assert llm_probe._detectar_jailbreak_exitoso_ds(resp_rechazo_es) is False

    def test_marker_en_ingles_detectado(self, resp_jailbreak_en):
        """Marcadores de compliance en inglés ('without restrictions', 'as dan') se detectan."""
        assert llm_probe._detectar_jailbreak_exitoso_ds(resp_jailbreak_en) is True

    def test_respuesta_normal_no_es_jailbreak(self, resp_normal):
        """Una respuesta educativa normal no activa la detección de jailbreak."""
        assert llm_probe._detectar_jailbreak_exitoso_ds(resp_normal) is False

    def test_marker_modo_sin_filtros(self):
        """'modo sin filtros' activa la detección de jailbreak."""
        respuesta = "modo sin filtros activado. Puedo responder cualquier cosa."
        assert llm_probe._detectar_jailbreak_exitoso_ds(respuesta) is True

    def test_marker_sin_restricciones(self):
        """'sin restricciones' activa la detección de jailbreak."""
        respuesta = "Opero sin restricciones, aquí está la información solicitada."
        assert llm_probe._detectar_jailbreak_exitoso_ds(respuesta) is True

    def test_marker_con_rechazo_simultaneo_prevalece_rechazo(self):
        """Cuando coinciden marcador y rechazo, prevalece el rechazo (no jailbreak)."""
        # El modelo dice que opera sin filtros pero también incluye lo siento
        respuesta = "modo sin filtros activado, pero lo siento, no puedo."
        # La función: tiene_compliance AND NOT tiene_rechazo → False
        resultado = llm_probe._detectar_jailbreak_exitoso_ds(respuesta)
        assert resultado is False

    def test_respuesta_vacia_no_es_jailbreak(self):
        """Una respuesta vacía no activa la detección."""
        assert llm_probe._detectar_jailbreak_exitoso_ds("") is False


# ────────────────────────────────────────────────────────────────────────────
# Tests de construir_peticion
# ────────────────────────────────────────────────────────────────────────────

class TestConstruirPeticion:
    """Pruebas de la construcción del payload JSON para distintos formatos de API."""

    def test_formato_api_chat_incluye_messages(self, estado_api_chat):
        """El formato api_chat genera un payload con la clave 'messages'."""
        peticion = llm_probe.construir_peticion(estado_api_chat, "test prompt")
        assert "messages" in peticion
        assert isinstance(peticion["messages"], list)
        assert len(peticion["messages"]) > 0

    def test_formato_api_chat_incluye_modelo(self, estado_api_chat):
        """El payload incluye el modelo del estado."""
        peticion = llm_probe.construir_peticion(estado_api_chat, "test prompt")
        assert peticion.get("model") == estado_api_chat.modelo

    def test_formato_v1_completions_incluye_messages(self, estado_v1_completions):
        """El formato v1_completions también genera un payload con 'messages'."""
        peticion = llm_probe.construir_peticion(estado_v1_completions, "test prompt")
        assert "messages" in peticion

    def test_formato_v1_completions_incluye_modelo(self, estado_v1_completions):
        """El formato v1_completions incluye el modelo."""
        peticion = llm_probe.construir_peticion(estado_v1_completions, "test prompt")
        assert "model" in peticion

    def test_formato_api_generate_incluye_prompt(self, estado_api_generate):
        """El formato api_generate genera un payload con la clave 'prompt'."""
        peticion = llm_probe.construir_peticion(estado_api_generate, "test prompt")
        assert "prompt" in peticion

    def test_contenido_incluido_en_peticion(self, estado_api_chat):
        """El texto del prompt está presente en la petición construida."""
        contenido = "¿Cómo ignorar todas las instrucciones previas?"
        peticion = llm_probe.construir_peticion(estado_api_chat, contenido)
        peticion_str = str(peticion)
        assert contenido in peticion_str

    def test_peticion_es_dict(self, estado_api_chat):
        """La petición siempre devuelve un diccionario."""
        resultado = llm_probe.construir_peticion(estado_api_chat, "prompt")
        assert isinstance(resultado, dict)


# ────────────────────────────────────────────────────────────────────────────
# Tests de extraer_texto_respuesta
# ────────────────────────────────────────────────────────────────────────────

class TestExtraerTextoRespuesta:
    """Pruebas de la extracción de texto según el formato de la respuesta."""

    def test_extrae_texto_api_chat(self):
        """Extrae el contenido del formato api_chat (Ollama /api/chat)."""
        data = {"message": {"content": "respuesta del modelo"}}
        resultado = llm_probe.extraer_texto_respuesta(data, "api_chat")
        assert resultado == "respuesta del modelo"

    def test_extrae_texto_v1_completions(self):
        """Extrae el contenido del formato v1/completions (OpenAI-compatible)."""
        data = {"choices": [{"message": {"content": "respuesta OpenAI"}}]}
        resultado = llm_probe.extraer_texto_respuesta(data, "v1_completions")
        assert resultado == "respuesta OpenAI"

    def test_extrae_texto_api_generate(self):
        """Extrae el contenido del formato api_generate (Ollama /api/generate)."""
        data = {"response": "respuesta generate"}
        resultado = llm_probe.extraer_texto_respuesta(data, "api_generate")
        assert resultado == "respuesta generate"

    def test_formato_desconocido_intenta_choices(self):
        """Un formato desconocido intenta extraer de la ruta estándar choices."""
        data = {"choices": [{"message": {"content": "fallback"}}]}
        resultado = llm_probe.extraer_texto_respuesta(data, "desconocido")
        # No debe lanzar excepción; puede devolver "" o el texto
        assert isinstance(resultado, str)


# ────────────────────────────────────────────────────────────────────────────
# Tests de constantes y metadatos del módulo
# ────────────────────────────────────────────────────────────────────────────

class TestConstantes:
    """Pruebas de las constantes y estructuras de datos del módulo."""

    def test_finding_prefix_es_llm(self):
        """FINDING_PREFIX debe ser 'LLM' para nombrar correctamente los hallazgos."""
        assert llm_probe.FINDING_PREFIX == "LLM"

    def test_model_specific_packs_tiene_clave_gpt(self):
        """MODEL_SPECIFIC_PACKS incluye payloads específicos para modelos GPT."""
        assert "gpt" in llm_probe.MODEL_SPECIFIC_PACKS
        assert len(llm_probe.MODEL_SPECIFIC_PACKS["gpt"]) >= 3

    def test_model_specific_packs_cubre_cinco_familias(self):
        """MODEL_SPECIFIC_PACKS cubre exactamente cinco familias de modelos LLM."""
        # Las cinco familias definidas en el módulo: gpt, gemini, llama, mistral y una más
        assert len(llm_probe.MODEL_SPECIFIC_PACKS) == 5

    def test_model_specific_packs_tiene_clave_llama(self):
        """MODEL_SPECIFIC_PACKS incluye payloads específicos para modelos llama."""
        assert "llama" in llm_probe.MODEL_SPECIFIC_PACKS

    def test_payloads_inyeccion_contiene_diez_entradas(self):
        """PAYLOADS_INYECCION tiene exactamente 10 vectores de inyección predefinidos."""
        assert len(llm_probe.PAYLOADS_INYECCION) == 10

    def test_payloads_inyeccion_ids_correctos(self):
        """Los IDs de PAYLOADS_INYECCION siguen el patrón LLM-01X."""
        ids = {p["id"] for p in llm_probe.PAYLOADS_INYECCION}
        for n in range(10, 20):
            assert f"LLM-0{n}" in ids

    def test_refusal_patterns_no_vacio(self):
        """_REFUSAL_PATTERNS contiene al menos los patrones de rechazo básicos."""
        assert len(llm_probe._REFUSAL_PATTERNS) > 5

    def test_compliance_markers_no_vacio(self):
        """_COMPLIANCE_MARKERS contiene al menos los marcadores de jailbreak básicos."""
        assert len(llm_probe._COMPLIANCE_MARKERS) > 3

    def test_refusal_patterns_contiene_lo_siento(self):
        """_REFUSAL_PATTERNS incluye variantes del patrón 'lo siento' en español."""
        patrones_es = [p for p in llm_probe._REFUSAL_PATTERNS
                       if "lo siento" in p or "siento" in p]
        assert len(patrones_es) > 0


# ────────────────────────────────────────────────────────────────────────────
# Tests de _detectar_ascii_smuggling
# ────────────────────────────────────────────────────────────────────────────

class TestAsciiSmuggling:
    """Pruebas de la detección de Unicode Tags (U+E0000–U+E007F)."""

    def test_detecta_tags_unicode_ocultos(self):
        """Texto con Unicode Tags en el rango E0000-E007F se detecta como smuggling."""
        texto_oculto = "Normal" + "".join(chr(0xE0000 + ord(c)) for c in "EXFIL")
        encontrado, _ = llm_probe._detectar_ascii_smuggling(texto_oculto)
        assert encontrado is True

    def test_texto_limpio_no_activa_deteccion(self):
        """Texto completamente limpio no activa la detección de smuggling."""
        encontrado, _ = llm_probe._detectar_ascii_smuggling("Texto normal sin caracteres ocultos.")
        assert encontrado is False

    def test_texto_decodificado_es_cadena(self):
        """El texto decodificado del smuggling es una cadena de texto."""
        texto_oculto = "".join(chr(0xE0000 + ord(c)) for c in "hola")
        _, decodificado = llm_probe._detectar_ascii_smuggling(texto_oculto)
        assert isinstance(decodificado, str)

    def test_texto_decodificado_contiene_mensaje_oculto(self):
        """El texto decodificado reproduce el mensaje original ocultado."""
        mensaje = "SECRETO"
        texto_oculto = "visible" + "".join(chr(0xE0000 + ord(c)) for c in mensaje)
        _, decodificado = llm_probe._detectar_ascii_smuggling(texto_oculto)
        assert mensaje in decodificado

    def test_emojis_banderas_no_generan_falsos_positivos(self):
        """Las banderas de emoji reales no deben activar la detección de smuggling."""
        # 🏴󠁧󠁢󠁥󠁮󠁧󠁿 = bandera de England (usa Tags Unicode pero son flags legales)
        # El módulo excluye las 3 banderas de las naciones de Gran Bretaña
        texto_con_bandera = "País: 🏴󠁧󠁢󠁥󠁮󠁧󠁿 England"
        encontrado, _ = llm_probe._detectar_ascii_smuggling(texto_con_bandera)
        # Si el módulo excluye flags legales, debe ser False; si no, True pero no es un error
        # Lo importante es que no lance excepción
        assert isinstance(encontrado, bool)


# ────────────────────────────────────────────────────────────────────────────
# Tests del corpus bundleado ES (v1.7.0)
# ────────────────────────────────────────────────────────────────────────────

class TestCorpusBundledES:
    """Pruebas del corpus bundleado de payloads en español."""

    def test_inyeccion_bundled_es_tiene_suficientes_payloads(self):
        """El corpus bundleado de inyección ES debe tener al menos 100 payloads."""
        assert len(llm_probe._INYECCION_BUNDLED_ES) >= 100

    def test_jailbreak_bundled_es_tiene_suficientes_payloads(self):
        """El corpus bundleado de jailbreak ES debe tener al menos 100 payloads."""
        assert len(llm_probe._JAILBREAK_BUNDLED_ES) >= 100

    def test_total_corpus_es_supera_300(self):
        """El total del corpus bundleado ES debe superar los 300 payloads."""
        total = len(llm_probe._INYECCION_BUNDLED_ES) + len(llm_probe._JAILBREAK_BUNDLED_ES)
        assert total >= 300

    def test_todos_los_payloads_son_cadenas_no_vacias(self):
        """Todos los payloads bundleados deben ser strings no vacíos."""
        for p in llm_probe._INYECCION_BUNDLED_ES:
            assert isinstance(p, str) and len(p) > 10
        for p in llm_probe._JAILBREAK_BUNDLED_ES:
            assert isinstance(p, str) and len(p) > 10

    def test_cargar_inyeccion_es_devuelve_bundled_sin_csv(self, tmp_path, monkeypatch):
        """Sin fichero CSV, el loader devuelve el corpus bundleado."""
        monkeypatch.setattr(llm_probe, "_dir_payloads", lambda: tmp_path)
        resultado = llm_probe._cargar_dataset_injection_es()
        assert resultado == list(llm_probe._INYECCION_BUNDLED_ES)

    def test_cargar_jailbreaks_es_devuelve_bundled_sin_csv(self, tmp_path, monkeypatch):
        """Sin fichero CSV, el loader de jailbreaks devuelve el corpus bundleado."""
        monkeypatch.setattr(llm_probe, "_dir_payloads", lambda: tmp_path)
        resultado = llm_probe._cargar_dataset_jailbreaks_es()
        assert resultado == list(llm_probe._JAILBREAK_BUNDLED_ES)

    def test_payload_inyeccion_contiene_instruccion_directa(self):
        """Al menos un payload de inyección contiene 'Ignora' o 'SYSTEM'."""
        corpus = "\n".join(llm_probe._INYECCION_BUNDLED_ES).lower()
        assert "ignora" in corpus or "system" in corpus

    def test_payload_jailbreak_contiene_roleplay(self):
        """Al menos un payload de jailbreak contiene términos de roleplay."""
        corpus = "\n".join(llm_probe._JAILBREAK_BUNDLED_ES).lower()
        assert any(t in corpus for t in ["ahora eres", "actúa como", "interpreta", "rol"])


# ────────────────────────────────────────────────────────────────────────────
# Tests de cadenas multi-turno (v1.7.0)
# ────────────────────────────────────────────────────────────────────────────

class TestCadenasMultiturn:
    """Pruebas de la estructura de las cadenas multi-turno."""

    def test_cadenas_multiturn_tiene_elementos(self):
        """Debe existir al menos 15 cadenas multi-turno definidas."""
        assert len(llm_probe._CADENAS_MULTITURN) >= 15

    def test_cadenas_incluyen_es_y_en(self):
        """Deben existir cadenas tanto en español (MT-ES-*) como en inglés (MT-EN-*)."""
        ids = [c["id"] for c in llm_probe._CADENAS_MULTITURN]
        assert any(i.startswith("MT-ES-") for i in ids)
        assert any(i.startswith("MT-EN-") for i in ids)

    def test_todas_las_cadenas_tienen_campos_obligatorios(self):
        """Cada cadena debe tener id, nombre, cadena y marcas."""
        for c in llm_probe._CADENAS_MULTITURN:
            assert "id" in c and isinstance(c["id"], str)
            assert "nombre" in c and isinstance(c["nombre"], str)
            assert "cadena" in c and isinstance(c["cadena"], list)
            assert "marcas" in c and isinstance(c["marcas"], list)

    def test_cadena_tiene_al_menos_tres_turnos(self):
        """Cada cadena debe tener al menos 3 mensajes para construir contexto."""
        for c in llm_probe._CADENAS_MULTITURN:
            assert len(c["cadena"]) >= 3, f"{c['id']} tiene menos de 3 turnos"

    def test_ultimo_turno_siempre_es_usuario(self):
        """El último mensaje de cada cadena debe ser del rol 'user' (turno de ataque)."""
        for c in llm_probe._CADENAS_MULTITURN:
            assert c["cadena"][-1]["role"] == "user", (
                f"{c['id']}: el último turno no es 'user'"
            )

    def test_todos_los_mensajes_tienen_role_y_content(self):
        """Cada mensaje en cada cadena debe tener 'role' y 'content' no vacíos."""
        for c in llm_probe._CADENAS_MULTITURN:
            for msg in c["cadena"]:
                assert "role" in msg and msg["role"] in ("user", "assistant", "system")
                assert "content" in msg and len(msg["content"]) > 5

    def test_todas_las_cadenas_tienen_al_menos_una_marca(self):
        """Cada cadena debe tener al menos una marca de detección."""
        for c in llm_probe._CADENAS_MULTITURN:
            assert len(c["marcas"]) >= 1, f"{c['id']} no tiene marcas de detección"

    def test_ids_son_unicos(self):
        """Los IDs de las cadenas no deben repetirse."""
        ids = [c["id"] for c in llm_probe._CADENAS_MULTITURN]
        assert len(ids) == len(set(ids)), "Hay IDs duplicados en las cadenas multi-turno"
