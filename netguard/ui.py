"""
Module ui.py
============
Interface utilisateur en ligne de commande (CLI Dashboard) avec Rich.
Offre une vue dynamique en temps réel des statistiques et des alertes de sécurité.
"""

import sys
import os
from typing import List
from netguard.analyzer import Alert, TrafficAnalyzer

# Force UTF-8 output on Windows streams if possible
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


class TerminalUI:
    """
    Gestionnaire d'affichage terminal.
    Propose un affichage enrichi avec Rich ou un fallback texte basique.
    """

    def __init__(self):
        if HAS_RICH:
            self.console = Console(highlight=False)

    def render_header(self):
        """Affiche le bandeau d'en-tête du logiciel."""
        header_text = (
            "===========================================================\n"
            "  NETGUARD-CLI v1.0.0 | Network Intrusion Detection System\n"
            "  Développé par Elio Fabrizio | Cybersécurité & Réseaux UTBM\n"
            "==========================================================="
        )
        if HAS_RICH:
            try:
                self.console.print(Panel(
                    Text("NETGUARD-CLI v1.0.0 — Network Threat & Traffic Analyzer", style="bold cyan center"),
                    subtitle="UTBM Cybersecurity & Networks",
                    style="bold blue"
                ))
            except Exception:
                print(header_text)
        else:
            print(header_text)

    def display_live_summary(self, analyzer: TrafficAnalyzer, recent_alerts: List[Alert]):
        """Affiche un tableau récapitulatif des statistiques et dernières alertes."""
        if not HAS_RICH:
            print(f"\n--- Stats réseau: {analyzer.total_packets} paquets capturés ---")
            for proto, cnt in analyzer.protocol_counts.items():
                print(f"  {proto}: {cnt}")
            if recent_alerts:
                print(f"--- ALERTES ({len(recent_alerts)}) ---")
                for a in recent_alerts[-5:]:
                    print(f"  [{a.severity}] {a.alert_type} - {a.source} -> {a.description}")
            return

        try:
            # Construction du composant Rich Table pour les métriques
            table_stats = Table(title="Statistiques de Trafic", show_header=True, header_style="bold magenta")
            table_stats.add_column("Protocoles", style="cyan")
            table_stats.add_column("Nombre de Paquets", style="green")
            table_stats.add_column("% du Trafic", style="yellow")

            tot = max(analyzer.total_packets, 1)
            for proto, count in analyzer.protocol_counts.items():
                pct = (count / tot) * 100
                table_stats.add_row(proto, str(count), f"{pct:.1f}%")

            table_stats.add_row("TOTAL", str(analyzer.total_packets), "100.0%", style="bold white")

            # Table des alertes
            table_alerts = Table(title="Alertes de Securite Recentes", show_header=True, header_style="bold red")
            table_alerts.add_column("Heure", style="dim")
            table_alerts.add_column("Niveau", style="bold")
            table_alerts.add_column("Type", style="cyan")
            table_alerts.add_column("Source", style="yellow")
            table_alerts.add_column("Description", style="white")

            for alert in recent_alerts[-6:]:
                sev_color = "bold red" if alert.severity == "CRITICAL" else "red" if alert.severity == "HIGH" else "yellow"
                table_alerts.add_row(
                    alert.formatted_time,
                    f"[{sev_color}]{alert.severity}[/{sev_color}]",
                    alert.alert_type,
                    alert.source,
                    alert.description
                )

            self.console.clear()
            self.render_header()
            self.console.print(table_stats)
            self.console.print(table_alerts)
        except Exception:
            # Fallback en cas d'erreur d’encodage terminal Windows
            print(f"\n[NetGuard] Paquets capturés : {analyzer.total_packets} | Alertes : {len(recent_alerts)}")
            if recent_alerts:
                last_a = recent_alerts[-1]
                print(f"  [Derniere Alerte] [{last_a.severity}] {last_a.alert_type} de {last_a.source} : {last_a.description}")
