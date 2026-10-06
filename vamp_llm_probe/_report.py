# © VampSecure Studios — VampSecure Labs Security Research Division
"""
_report.py — Re-exporta VampSecReport desde el paquete vampsec_report compartido.
"""
from vampsec_report import Finding, ReportMeta, VampSecReport  # noqa: F401

__all__ = ["Finding", "ReportMeta", "VampSecReport"]
