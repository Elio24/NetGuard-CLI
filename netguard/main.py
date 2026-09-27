"""
Module main.py
==============
Point d'entrée principal de l'application NetGuard-CLI.
Gère les arguments en ligne de commande, le mode Capture Live, Analyse PCAP et Mode Simulation.
"""

import argparse
import sys
import time
import random
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from netguard import __version__
from netguard.packet_parser import PacketParser, ParsedPacket
from netguard.analyzer import TrafficAnalyzer
from netguard.logger import AlertLogger
from netguard.ui import TerminalUI


def generate_simulated_packets():
    """
    Générateur de paquets synthétiques pour le mode Démo / Simulation.
    Simule du trafic légitime ainsi que des attaques (Scan de ports, SYN Flood, ARP Spoofing).
    """
    ips = ["192.168.1.10", "192.168.1.25", "10.0.0.4", "172.16.0.50", "45.33.32.156"]
    attacker_ip = "192.168.1.66"
    target_ip = "192.168.1.1"

    rnd = random.random()
    if rnd < 0.5:
        return ParsedPacket(
            timestamp=time.time(),
            length=random.randint(64, 1500),
            protocol="TCP",
            src_ip=random.choice(ips),
            dst_ip=target_ip,
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 22, 8080]),
            tcp_flags={"SYN": False, "ACK": True}
        )
    elif rnd < 0.75:
        return ParsedPacket(
            timestamp=time.time(),
            length=64,
            protocol="TCP",
            src_ip=attacker_ip,
            dst_ip=target_ip,
            src_port=random.randint(40000, 50000),
            dst_port=random.randint(1, 1000),
            tcp_flags={"SYN": True, "ACK": False}
        )
    elif rnd < 0.90:
        fake_mac = f"00:11:22:33:44:{random.randint(10, 99)}"
        return ParsedPacket(
            timestamp=time.time(),
            length=42,
            protocol="ARP",
            src_mac=fake_mac,
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip=target_ip,
            dst_ip="192.168.1.15",
            arp_op=2
        )
    else:
        return ParsedPacket(
            timestamp=time.time(),
            length=128,
            protocol="UDP",
            src_ip="192.168.1.45",
            dst_ip="8.8.8.8",
            src_port=53241,
            dst_port=53,
            dns_query="exfiltration-data-payload-chunk-98123791823791823.malicious-domain.com"
        )


def main():
    parser = argparse.ArgumentParser(
        description="NetGuard-CLI : Analyseur de trafic et système de détection d'intrusions réseau (NIDS)."
    )
    parser.add_argument("-i", "--interface", help="Interface réseau à écouter (ex: eth0, wlan0, Wi-Fi)", default=None)
    parser.add_argument("-r", "--pcap", help="Chemin vers un fichier .pcap à analyser hors-ligne", default=None)
    parser.add_argument("-s", "--simulate", action="store_true", help="Lancer le mode démo / simulation automatisé")
    parser.add_argument("-o", "--output", help="Fichier de sortie JSON des alertes", default="alerts.json")
    parser.add_argument("-v", "--version", action="version", version=f"NetGuard-CLI v{__version__}")

    args = parser.parse_args()

    ui = TerminalUI()
    analyzer = TrafficAnalyzer()
    logger = AlertLogger(log_filepath=args.output)

    ui.render_header()
    print("\n[+] Initialisation de NetGuard-CLI Engine...")
    time.sleep(0.5)

    if args.simulate or (not args.interface and not args.pcap):
        print("\n[Mode Simulation Active] (Generation de trafic d'essai avec attaques synthetiques)")
        print("[Press CTRL+C to stop]\n")
        try:
            for _ in range(40):
                pkt = generate_simulated_packets()
                new_alerts = analyzer.process_packet(pkt)
                for alert in new_alerts:
                    logger.log_alert(alert)
                
                ui.display_live_summary(analyzer, analyzer.alerts)
                time.sleep(0.05)
        except KeyboardInterrupt:
            print("\n\n[!] Simulation interrompue par l'utilisateur.")

    elif args.pcap:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(f"[Erreur] Le fichier pcap '{args.pcap}' est introuvable.")
            sys.exit(1)

        print(f"[+] Lecture du fichier PCAP : {args.pcap}")
        try:
            from scapy.all import rdpcap
            packets = rdpcap(str(pcap_path))
            print(f"[+] {len(packets)} paquets charges. Analyse en cours...")
            
            for scapy_pkt in packets:
                parsed = PacketParser.parse(scapy_pkt)
                alerts = analyzer.process_packet(parsed)
                for alert in alerts:
                    logger.log_alert(alert)

            ui.display_live_summary(analyzer, analyzer.alerts)
            print(f"\n[OK] Analyse terminee ! {len(analyzer.alerts)} alertes sauvegardees dans '{args.output}'.")
        except Exception as e:
            print(f"[Erreur d'analyse PCAP] : {e}")
            sys.exit(1)

    elif args.interface:
        print(f"[+] Demarrage de la capture en direct sur l'interface : {args.interface}")
        try:
            from scapy.all import sniff

            def packet_callback(scapy_pkt):
                parsed = PacketParser.parse(scapy_pkt)
                alerts = analyzer.process_packet(parsed)
                for alert in alerts:
                    logger.log_alert(alert)
                ui.display_live_summary(analyzer, analyzer.alerts)

            sniff(iface=args.interface, prn=packet_callback, store=0)
        except KeyboardInterrupt:
            print("\n[!] Capture terminee par l'utilisateur.")
        except Exception as e:
            print(f"[Erreur de capture Live] (Verifiez vos droits Administrateur/root ou Scapy) : {e}")
            sys.exit(1)

    logger.export_summary(analyzer.alerts, "report_summary.txt")
    print(f"\n[Rapport genere] : 'report_summary.txt' et '{args.output}'.")


if __name__ == "__main__":
    main()
