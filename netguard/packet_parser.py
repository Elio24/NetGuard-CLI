"""
Module packet_parser.py
======================
Responsabilité : Extraction et structuration des informations contenues dans les paquets réseau.
Transforme un paquet brut (Scapy) en un objet Python manipulable (ParsedPacket).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class ParsedPacket:
    """
    Structure de données représentant un paquet réseau décodé.
    Regroupe les informations clés des couches 2 (Lien), 3 (Réseau) et 4 (Transport).
    """
    timestamp: float
    length: int
    protocol: str  # TCP, UDP, ICMP, ARP, IP, OTHER
    
    # Couche 2 - Liaison de données
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    
    # Couche 3 - Réseau
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    
    # Couche 4 - Transport
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    
    # Flags TCP (SYN, ACK, FIN, RST, PSH, URG)
    tcp_flags: Dict[str, bool] = field(default_factory=dict)
    
    # Données ARP / DNS particulières
    arp_op: Optional[int] = None  # 1: Request, 2: Reply
    dns_query: Optional[str] = None
    
    @property
    def formatted_time(self) -> str:
        """Retourne l'horodatage sous forme de chaîne HH:MM:SS.mmm."""
        dt = datetime.fromtimestamp(self.timestamp)
        return dt.strftime("%H:%M:%S.%f")[:-3]

    @property
    def summary(self) -> str:
        """Génère un résumé textuel concis du paquet."""
        if self.protocol in ("TCP", "UDP"):
            return f"[{self.protocol}] {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.length} bytes)"
        elif self.protocol == "ARP":
            op_name = "REQ" if self.arp_op == 1 else "REPLY"
            return f"[ARP {op_name}] {self.src_mac} ({self.src_ip}) -> {self.dst_mac} ({self.dst_ip})"
        elif self.protocol == "ICMP":
            return f"[ICMP] {self.src_ip} -> {self.dst_ip} ({self.length} bytes)"
        else:
            return f"[{self.protocol}] {self.src_ip or self.src_mac} -> {self.dst_ip or self.dst_mac}"


class PacketParser:
    """
    Parseur principal s'appuyant sur Scapy pour extraire les métadonnées de sécurité.
    """
    
    @staticmethod
    def parse(scapy_pkt) -> ParsedPacket:
        """
        Extrait les informations d'un paquet Scapy et retourne un ParsedPacket.
        """
        pkt_time = float(getattr(scapy_pkt, 'time', datetime.now().timestamp()))
        pkt_len = len(scapy_pkt)
        
        parsed = ParsedPacket(
            timestamp=pkt_time,
            length=pkt_len,
            protocol="OTHER"
        )
        
        # 1. Extraction Couche 2 (Ethernet)
        if scapy_pkt.haslayer("Ether"):
            parsed.src_mac = scapy_pkt["Ether"].src
            parsed.dst_mac = scapy_pkt["Ether"].dst
            
        # 2. Extraction Couche ARP
        if scapy_pkt.haslayer("ARP"):
            parsed.protocol = "ARP"
            parsed.arp_op = scapy_pkt["ARP"].op
            parsed.src_ip = scapy_pkt["ARP"].psrc
            parsed.dst_ip = scapy_pkt["ARP"].pdst
            parsed.src_mac = scapy_pkt["Ether"].src if scapy_pkt.haslayer("Ether") else scapy_pkt["ARP"].hwsrc
            parsed.dst_mac = scapy_pkt["Ether"].dst if scapy_pkt.haslayer("Ether") else scapy_pkt["ARP"].hwdst
            return parsed

        # 3. Extraction Couche 3 (IPv4 / IPv6)
        if scapy_pkt.haslayer("IP"):
            parsed.src_ip = scapy_pkt["IP"].src
            parsed.dst_ip = scapy_pkt["IP"].dst
            parsed.ttl = scapy_pkt["IP"].ttl
            parsed.protocol = "IP"
        elif scapy_pkt.haslayer("IPv6"):
            parsed.src_ip = scapy_pkt["IPv6"].src
            parsed.dst_ip = scapy_pkt["IPv6"].dst
            parsed.ttl = scapy_pkt["IPv6"].hlim
            parsed.protocol = "IPv6"

        # 4. Extraction Couche 4 (TCP / UDP / ICMP)
        if scapy_pkt.haslayer("TCP"):
            parsed.protocol = "TCP"
            parsed.src_port = scapy_pkt["TCP"].sport
            parsed.dst_port = scapy_pkt["TCP"].dport
            
            # Extraction des drapeaux (flags) TCP
            flags_int = int(scapy_pkt["TCP"].flags)
            parsed.tcp_flags = {
                "FIN": bool(flags_int & 0x01),
                "SYN": bool(flags_int & 0x02),
                "RST": bool(flags_int & 0x04),
                "PSH": bool(flags_int & 0x08),
                "ACK": bool(flags_int & 0x10),
                "URG": bool(flags_int & 0x20),
            }
            
        elif scapy_pkt.haslayer("UDP"):
            parsed.protocol = "UDP"
            parsed.src_port = scapy_pkt["UDP"].sport
            parsed.dst_port = scapy_pkt["UDP"].dport
            
            # Détection de requêtes DNS
            if scapy_pkt.haslayer("DNS") and scapy_pkt.haslayer("DNSQR"):
                try:
                    qname = scapy_pkt["DNSQR"].qname
                    parsed.dns_query = qname.decode('utf-8') if isinstance(qname, bytes) else str(qname)
                except Exception:
                    pass

        elif scapy_pkt.haslayer("ICMP"):
            parsed.protocol = "ICMP"

        return parsed
