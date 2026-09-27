"""
Module analyzer.py
==================
Moteur de détection d'anomalies de sécurité et d'analyses statistiques en temps réel.
Détecte : Port Scan, SYN Flood (DoS), ARP Spoofing et Anomaly DNS Tunneling.
"""

import time
from dataclasses import dataclass
from collections import defaultdict, deque
from typing import List, Dict, Set, Optional
from netguard.packet_parser import ParsedPacket


@dataclass
class Alert:
    """Représente une alerte de sécurité déclenchée par l'analyseur."""
    timestamp: float
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    alert_type: str  # PORT_SCAN, SYN_FLOOD, ARP_SPOOF, DNS_ANOMALY
    source: str
    target: str
    description: str

    @property
    def formatted_time(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


class TrafficAnalyzer:
    """
    Moteur principal d'analyse comportementale sur le réseau.
    Utilise une fenêtre glissante (sliding window) pour évaluer l'activité des hôtes.
    """

    def __init__(
        self,
        port_scan_threshold: int = 15,
        port_scan_window: float = 10.0,
        syn_flood_threshold: int = 30,
        syn_flood_window: float = 5.0,
        dns_length_threshold: int = 60
    ):
        # Configuration des seuils de détection
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window
        self.dns_length_threshold = dns_length_threshold

        # Statistiques globales
        self.total_packets: int = 0
        self.protocol_counts: Dict[str, int] = defaultdict(int)
        self.top_sources: Dict[str, int] = defaultdict(int)
        self.top_destinations: Dict[str, int] = defaultdict(int)

        # Structures pour la détection en fenêtre glissante
        # src_ip -> deque of (timestamp, dst_port)
        self._port_scan_history: Dict[str, deque] = defaultdict(deque)
        
        # src_ip -> deque of timestamp for SYN packets
        self._syn_history: Dict[str, deque] = defaultdict(deque)
        
        # IP -> Set of MACs (pour la détection ARP Spoofing)
        self._ip_mac_table: Dict[str, str] = {}
        
        # Liste des alertes générées
        self.alerts: List[Alert] = []

    def process_packet(self, packet: ParsedPacket) -> List[Alert]:
        """
        Traite un paquet individuel, met à jour les métriques et vérifie les alertes.
        Retourne la liste des nouvelles alertes générées par ce paquet.
        """
        self.total_packets += 1
        self.protocol_counts[packet.protocol] += 1

        if packet.src_ip:
            self.top_sources[packet.src_ip] += 1
        if packet.dst_ip:
            self.top_destinations[packet.dst_ip] += 1

        new_alerts = []

        # 1. Vérification ARP Spoofing
        if packet.protocol == "ARP":
            arp_alert = self._check_arp_spoofing(packet)
            if arp_alert:
                new_alerts.append(arp_alert)

        # 2. Vérification Port Scan
        if packet.protocol in ("TCP", "UDP") and packet.src_ip and packet.dst_port:
            scan_alert = self._check_port_scan(packet)
            if scan_alert:
                new_alerts.append(scan_alert)

        # 3. Vérification SYN Flood (DoS)
        if packet.protocol == "TCP" and packet.tcp_flags.get("SYN") and not packet.tcp_flags.get("ACK"):
            syn_alert = self._check_syn_flood(packet)
            if syn_alert:
                new_alerts.append(syn_alert)

        # 4. Vérification Anomale DNS (Tunneling / Data Exfiltration)
        if packet.dns_query:
            dns_alert = self._check_dns_anomaly(packet)
            if dns_alert:
                new_alerts.append(dns_alert)

        self.alerts.extend(new_alerts)
        return new_alerts

    def _check_port_scan(self, packet: ParsedPacket) -> Optional[Alert]:
        """Détecte si un hôte tente de balayer plusieurs ports en peu de temps."""
        now = packet.timestamp
        src = packet.src_ip
        dst_port = packet.dst_port

        history = self._port_scan_history[src]
        history.append((now, dst_port))

        # Nettoyage des événements hors de la fenêtre glissante
        cutoff = now - self.port_scan_window
        while history and history[0][0] < cutoff:
            history.popleft()

        # Compter le nombre de ports uniques ciblés dans la fenêtre
        unique_ports: Set[int] = {port for t, port in history}
        if len(unique_ports) >= self.port_scan_threshold:
            # Éviter les alertes répétitives en boucle
            if len(unique_ports) == self.port_scan_threshold or len(unique_ports) % 20 == 0:
                return Alert(
                    timestamp=now,
                    severity="HIGH",
                    alert_type="PORT_SCAN",
                    source=src,
                    target=packet.dst_ip or "Multiple",
                    description=f"Scan de ports suspect : {len(unique_ports)} ports ciblés en <{self.port_scan_window}s"
                )
        return None

    def _check_syn_flood(self, packet: ParsedPacket) -> Optional[Alert]:
        """Détecte une inondation de paquets SYN (Attaque DoS SYN Flood)."""
        now = packet.timestamp
        src = packet.src_ip

        history = self._syn_history[src]
        history.append(now)

        cutoff = now - self.syn_flood_window
        while history and history[0] < cutoff:
            history.popleft()

        if len(history) >= self.syn_flood_threshold:
            if len(history) == self.syn_flood_threshold or len(history) % 50 == 0:
                return Alert(
                    timestamp=now,
                    severity="CRITICAL",
                    alert_type="SYN_FLOOD",
                    source=src,
                    target=packet.dst_ip or "Network",
                    description=f"Inondation TCP SYN détectée : {len(history)} paquets SYN en <{self.syn_flood_window}s"
                )
        return None

    def _check_arp_spoofing(self, packet: ParsedPacket) -> Optional[Alert]:
        """Détecte l'usurpation d'adresse MAC/IP via les requêtes/réponses ARP."""
        if not packet.src_ip or not packet.src_mac:
            return None

        ip = packet.src_ip
        mac = packet.src_mac.lower()

        if ip in self._ip_mac_table:
            old_mac = self._ip_mac_table[ip]
            if old_mac != mac:
                # Changement d'adresse MAC détecté pour la même IP !
                return Alert(
                    timestamp=packet.timestamp,
                    severity="CRITICAL",
                    alert_type="ARP_SPOOF",
                    source=f"{ip} ({mac})",
                    target=f"Original MAC: {old_mac}",
                    description=f"Tentative de Poisoning ARP ! L'IP {ip} a changé de MAC ({old_mac} -> {mac})"
                )
        else:
            self._ip_mac_table[ip] = mac

        return None

    def _check_dns_anomaly(self, packet: ParsedPacket) -> Optional[Alert]:
        """Détecte les noms de domaine anormalement longs (tunneling DNS / exfiltration)."""
        query = packet.dns_query or ""
        if len(query) >= self.dns_length_threshold:
            return Alert(
                timestamp=packet.timestamp,
                severity="MEDIUM",
                alert_type="DNS_ANOMALY",
                source=packet.src_ip or "Unknown",
                target=packet.dst_ip or "DNS Server",
                description=f"Requête DNS suspecte ({len(query)} caractères) : {query[:45]}..."
            )
        return None
