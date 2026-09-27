"""
Module logger.py
================
Gestion de la journalisation des alertes (JSON / Fichiers de log) et rapports d'incidents.
"""

import json
from pathlib import Path
from typing import List
from netguard.analyzer import Alert


class AlertLogger:
    """
    Enregistre les alertes de sécurité sous forme structurée (JSON) pour archivage ou SIEM.
    """

    def __init__(self, log_filepath: str = "alerts.json"):
        self.log_filepath = Path(log_filepath)

    def log_alert(self, alert: Alert):
        """Ajoute une alerte dans le fichier JSON d'historique."""
        alert_data = {
            "timestamp": alert.timestamp,
            "formatted_time": alert.formatted_time,
            "severity": alert.severity,
            "type": alert.alert_type,
            "source": alert.source,
            "target": alert.target,
            "description": alert.description
        }
        
        existing_alerts = []
        if self.log_filepath.exists():
            try:
                with open(self.log_filepath, "r", encoding="utf-8") as f:
                    existing_alerts = json.load(f)
            except Exception:
                existing_alerts = []

        existing_alerts.append(alert_data)

        with open(self.log_filepath, "w", encoding="utf-8") as f:
            json.dump(existing_alerts, f, indent=4, ensure_ascii=False)

    def export_summary(self, alerts: List[Alert], output_path: str = "report_summary.txt"):
        """Génère un rapport texte récapitulatif pour les équipes de sécurité (SOC)."""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("====================================================\n")
            f.write("      NETGUARD-CLI : RAPPORT D'INCIDENTS DE SÉCURITÉ\n")
            f.write("====================================================\n\n")
            f.write(f"Total alertes générées : {len(alerts)}\n\n")

            for idx, a in enumerate(alerts, 1):
                f.write(f"[{idx}] [{a.formatted_time}] SERVIABLE: {a.severity} | TYPE: {a.alert_type}\n")
                f.write(f"    Source      : {a.source}\n")
                f.write(f"    Cible       : {a.target}\n")
                f.write(f"    Description : {a.description}\n")
                f.write("----------------------------------------------------\n")
