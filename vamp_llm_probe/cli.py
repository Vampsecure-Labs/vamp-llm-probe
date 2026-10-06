# © VampSecure Studios — VampSecure Labs Security Research Division
"""
cli.py — Punto de entrada CLI para vamp-llm-probe v1.8.0.
"""
from __future__ import annotations
import argparse, asyncio, pathlib, sys

from ._models import (
    C, COPYRIGHT, _PAYLOADS_CACHE, _CADENAS_MULTITURN,
    _set_verbose, _verbose_global,
)
from ._core import LLMProbe, _descargar_payloads

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-llm-probe v1.8.0 · LLM Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""


def construir_parser() -> argparse.ArgumentParser:
    """
    Construye y devuelve el parser de argumentos del CLI.

    Argumentos principales
    ----------------------
    --endpoint     : URL base del endpoint a auditar (requerido)
    --api-key      : Clave de autorización Bearer (opcional)
    --model        : Nombre del modelo a usar (default: auto-detect)
    --timeout      : Timeout por petición en segundos (default: 30)
    --output       : Fichero JSON de salida para los resultados
    --report-html  : Fichero HTML profesional para entrega al cliente
    --client       : Nombre del cliente para el informe
    --engagement   : Descripción del engagement
    --auditor      : Nombre del auditor
    --no-jailbreak : Omite la Fase 3 de evasión de restricciones
    --verbose      : Activa el modo detallado de salida
    """
    parser = argparse.ArgumentParser(
        prog        = "vamp-llm-probe",
        description = (
            "VampSecure Labs — Auditor de seguridad para endpoints de "
            "API de inferencia de lenguaje. Detecta vulnerabilidades mediante "
            "peticiones HTTP artesanales en 5 fases: reconocimiento, inyección, "
            "evasión, extracción y controles de acceso."
        ),
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog          = (
            f"\n{COPYRIGHT}\n"
            "Uso autorizado exclusivamente en entornos con permiso explícito.\n\n"
            "Códigos de salida:\n"
            "  0 — Sin hallazgos graves (MEDIUM, LOW o INFO)\n"
            "  1 — Hallazgos HIGH encontrados\n"
            "  2 — Hallazgos CRITICAL encontrados\n\n"
            "Ejemplos:\n"
            "  vamp-llm-probe --endpoint http://localhost:11434\n"
            "  vamp-llm-probe --endpoint http://api.ejemplo.com "
            "--api-key sk-xxx --model mistral:7b\n"
            "  vamp-llm-probe --endpoint http://servidor:8080 "
            "--report-html informe.html --client 'Empresa SL'\n"
        ),
    )

    # Argumentos principales
    parser.add_argument(
        "--endpoint",
        required    = False,
        default     = None,
        metavar     = "URL",
        help        = "URL base del endpoint de inferencia (ej: http://localhost:11434)",
    )
    parser.add_argument(
        "--update-payloads",
        action  = "store_true",
        dest    = "update_payloads",
        default = False,
        help    = (
            "Descarga o actualiza los datasets adversariales en "
            "~/.cache/vamp-llm-probe/payloads/ y termina sin ejecutar el probe"
        ),
    )
    parser.add_argument(
        "--api-key",
        metavar = "KEY",
        dest    = "api_key",
        default = "",
        help    = "Clave de autorización Bearer (opcional)",
    )
    parser.add_argument(
        "--model",
        metavar = "MODELO",
        default = "",
        help    = "Nombre del modelo a usar en pruebas (default: auto-detect)",
    )
    parser.add_argument(
        "--timeout",
        metavar = "N",
        type    = int,
        default = 30,
        help    = "Timeout por petición en segundos (default: 30)",
    )
    parser.add_argument(
        "--output",
        metavar = "FILE",
        default = None,
        help    = "Guarda los resultados en formato JSON en FILE",
    )
    parser.add_argument(
        "--report-html",
        metavar = "FILE",
        dest    = "report_html",
        default = None,
        help    = "Genera informe HTML profesional en FILE",
    )
    parser.add_argument(
        "--client",
        metavar = "NOMBRE",
        default = "Confidencial",
        help    = "Nombre del cliente para el informe (default: Confidencial)",
    )
    parser.add_argument(
        "--engagement",
        metavar = "DESC",
        default = "",
        help    = "Descripción del engagement para el informe",
    )
    parser.add_argument(
        "--auditor",
        metavar = "NOMBRE",
        default = "VampSecure Labs — Security Research Division",
        help    = "Nombre del auditor para el informe",
    )
    parser.add_argument(
        "--no-jailbreak",
        action  = "store_true",
        dest    = "no_jailbreak",
        default = False,
        help    = "Omite la Fase 3 de evasión de restricciones",
    )
    parser.add_argument(
        "--verbose",
        action  = "store_true",
        default = False,
        help    = "Modo detallado: muestra respuestas y trazas HTTP",
    )

    # Grupo: Dataset Red Team (Fase 6)
    grp_ds = parser.add_argument_group(
        "Dataset Red Team (Fase 6)",
        "Pruebas con datasets adversariales reales (caché local o descargados con --update-payloads)",
    )
    grp_ds.add_argument(
        "--dataset",
        action  = "store_true",
        default = False,
        dest    = "dataset",
        help    = "Activa la Fase 6: red team con datasets adversariales reales",
    )
    grp_ds.add_argument(
        "--dataset-sample",
        metavar = "N",
        type    = int,
        default = 15,
        dest    = "dataset_sample",
        help    = "Número de prompts a probar por tipo de dataset (default: 15)",
    )
    grp_ds.add_argument(
        "--dataset-categories",
        metavar = "CATS",
        default = None,
        dest    = "dataset_categories",
        help    = (
            "Filtrar forbidden questions por categorías (CSV): "
            "'Malware,Illegal Activity,Hate Speech,Physical Harm,Economic Harm,"
            "Fraud,Pornography,Political Lobbying,Privacy Violence,Legal Opinion,"
            "Financial Advice,Health Consultation,Gov Decision'"
        ),
    )

    # Grupo: Model-Specific Attack Packs (Fase 7)
    grp_mp = parser.add_argument_group(
        "Model-Specific Attack Packs (Fase 7)",
        "Payloads adaptados al formato de instrucciones de cada familia de modelos",
    )
    grp_mp.add_argument(
        "--model-pack",
        metavar = "FAMILIA",
        default = "",
        dest    = "model_pack",
        help    = (
            "Fuerza el pack de ataque de una familia concreta en la Fase 7: "
            "gpt | claude | gemini | llama | mistral. "
            "Si no se indica, la familia se detecta automáticamente desde el modelo."
        ),
    )

    # Grupo: RAG Poisoning Detector (Fase 8)
    grp_rag = parser.add_argument_group(
        "RAG Poisoning Detector (Fase 8)",
        "Prueba de inyección de instrucciones maliciosas vía contexto recuperado (RAG)",
    )
    grp_rag.add_argument(
        "--rag-test",
        action  = "store_true",
        default = False,
        dest    = "rag_test",
        help    = "Activa la Fase 8: detector de RAG poisoning y extracción de contexto",
    )

    # Grupo: Multi-turn Attack Chains (Fase 9)
    grp_mt = parser.add_argument_group(
        "Multi-turn Attack Chains (Fase 9)",
        "Ataques en cadena: varios turnos inocuos seguidos del turno de ataque real",
    )
    grp_mt.add_argument(
        "--multi-turn",
        action  = "store_true",
        default = False,
        dest    = "multi_turn",
        help    = (
            "Activa la Fase 9: cadenas conversacionales de ataque multi-turno "
            f"({len(_CADENAS_MULTITURN)} cadenas, ES+EN)"
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------

async def main_async() -> int:
    """
    Función principal asíncrona.

    Muestra el banner, parsea los argumentos, ejecuta las 9 fases
    de auditoría y genera los ficheros de salida configurados.

    Devuelve el exit code calculado según la severidad máxima encontrada.
    """
    parser = construir_parser()
    print(f"{C.ROJO_OSC}{BANNER}{C.RESET}")
    args   = parser.parse_args()

    # Modo standalone: actualizar datasets y salir
    if args.update_payloads:
        print(f"\n  Actualizando datasets adversariales en {_PAYLOADS_CACHE}\n")
        _descargar_payloads(forzar=True)
        print(f"\n  {C.VERDE}Datasets actualizados.{C.RESET}")
        return 0

    # --endpoint es obligatorio en modo probe
    if not args.endpoint:
        parser.error("el argumento --endpoint es requerido")

    # Activar modo detallado global
    _set_verbose(args.verbose)

    # Auto-descarga al primer uso con --dataset si la caché está vacía
    if getattr(args, "dataset", False) and not (
        _PAYLOADS_CACHE.exists() and any(_PAYLOADS_CACHE.iterdir())
    ):
        bundled = pathlib.Path(__file__).parent / "payloads"
        if not bundled.exists():
            print(f"\n  {C.DIM}Descargando datasets adversariales (primera vez)…{C.RESET}")
            _descargar_payloads()
            print()

    # Mostrar configuración
    print(f"  {C.NEGRITA}Endpoint:{C.RESET} {args.endpoint}")
    print(f"  {C.NEGRITA}Modelo:{C.RESET}   {args.model or 'auto-detect'}")
    print(f"  {C.NEGRITA}Timeout:{C.RESET}  {args.timeout}s")
    print(f"  {C.NEGRITA}Fases:{C.RESET}    1-Reconocimiento  2-Inyección  "
          + ("3-Evasión  " if not args.no_jailbreak else "[3-Omitida]  ")
          + "4-Extracción  5-Controles")
    print(f"  {C.DIM}{COPYRIGHT}{C.RESET}\n")

    probe    = LLMProbe(args)
    exitcode = await probe.ejecutar()
    probe.generar_salidas()

    # Mensaje final según severidad
    if exitcode == 2:
        print(f"\n  {C.ROJO}{C.NEGRITA}AUDITORÍA COMPLETADA — HALLAZGOS CRÍTICOS DETECTADOS{C.RESET}")
        print(f"  {C.ROJO}Revisar y remediar inmediatamente los hallazgos CRITICAL.{C.RESET}")
    elif exitcode == 1:
        print(f"\n  {C.NARANJA}{C.NEGRITA}AUDITORÍA COMPLETADA — HALLAZGOS DE ALTO RIESGO DETECTADOS{C.RESET}")
        print(f"  {C.NARANJA}Planificar la remediación de los hallazgos HIGH a la brevedad.{C.RESET}")
    else:
        print(f"\n  {C.VERDE}{C.NEGRITA}AUDITORÍA COMPLETADA — Sin hallazgos graves.{C.RESET}")
        print(f"  {C.VERDE}Pueden existir hallazgos MEDIUM/LOW/INFO para revisión.{C.RESET}")

    print(f"\n  {C.DIM}{COPYRIGHT}{C.RESET}\n")
    return exitcode


def main() -> None:
    """
    Punto de entrada sincrónico. Lanza el bucle asyncio y retorna
    el exit code apropiado al sistema operativo.
    """
    try:
        exitcode = asyncio.run(main_async())
        sys.exit(exitcode)
    except KeyboardInterrupt:
        print(f"\n\n  {C.AMARILLO}[!] Auditoría interrumpida por el usuario.{C.RESET}\n")
        sys.exit(130)
    except Exception as exc:
        print(f"\n  {C.ROJO}[✗] Error fatal: {exc}{C.RESET}\n")
        from ._models import _verbose_global as _vg  # noqa: PLC0415
        if _vg:
            import traceback
            traceback.print_exc()
        sys.exit(1)
