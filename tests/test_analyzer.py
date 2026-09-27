"""
Tests unitaires pour le moteur de détection d'intrusions (analyzer.py).
"""

import unittest
import time
from netguard.packet_parser import ParsedPacket
from netguard.analyzer import TrafficAnalyzer


class TestTrafficAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = TrafficAnalyzer(
            port_scan_threshold=5,
            syn_flood_threshold=5,
            port_scan_window=10.0,
            syn_flood_window=10.0
        )

    def test_port_scan_detection(self):
        now = time.time()
        alerts = []
        # Envoie 6 paquets vers des ports différents depuis la même IP
        for port in range(1, 7):
            pkt = ParsedPacket(
                timestamp=now,
                length=64,
                protocol="TCP",
                src_ip="10.0.0.99",
                dst_ip="192.168.1.1",
                src_port=50000,
                dst_port=port,
                tcp_flags={"SYN": True, "ACK": False}
            )
            new_alerts = self.analyzer.process_packet(pkt)
            alerts.extend(new_alerts)

        self.assertTrue(any(a.alert_type == "PORT_SCAN" for a in alerts))
        self.assertEqual(self.analyzer.total_packets, 6)

    def test_syn_flood_detection(self):
        now = time.time()
        alerts = []
        # Envoie 6 paquets SYN consécutifs
        for _ in range(6):
            pkt = ParsedPacket(
                timestamp=now,
                length=64,
                protocol="TCP",
                src_ip="10.0.0.88",
                dst_ip="192.168.1.1",
                src_port=40000,
                dst_port=80,
                tcp_flags={"SYN": True, "ACK": False}
            )
            new_alerts = self.analyzer.process_packet(pkt)
            alerts.extend(new_alerts)

        self.assertTrue(any(a.alert_type == "SYN_FLOOD" for a in alerts))

    def test_arp_spoofing_detection(self):
        now = time.time()
        # 1. Paquet légitime : IP 192.168.1.1 avec MAC A
        pkt1 = ParsedPacket(
            timestamp=now,
            length=42,
            protocol="ARP",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.50",
            arp_op=2
        )
        self.analyzer.process_packet(pkt1)

        # 2. Paquet frauduleux : Même IP 192.168.1.1 mais avec MAC B
        pkt2 = ParsedPacket(
            timestamp=now + 1,
            length=42,
            protocol="ARP",
            src_mac="AA:BB:CC:DD:EE:FF",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.50",
            arp_op=2
        )
        alerts = self.analyzer.process_packet(pkt2)
        self.assertTrue(any(a.alert_type == "ARP_SPOOF" for a in alerts))


if __name__ == "__main__":
    unittest.main()
