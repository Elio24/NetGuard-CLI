"""
Tests unitaires pour le parser de paquets (packet_parser.py).
"""

import unittest
from netguard.packet_parser import ParsedPacket


class TestPacketParser(unittest.TestCase):

    def test_parsed_packet_creation(self):
        pkt = ParsedPacket(
            timestamp=1600000000.0,
            length=100,
            protocol="TCP",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            src_port=12345,
            dst_port=80,
            tcp_flags={"SYN": True, "ACK": False}
        )
        self.assertEqual(pkt.protocol, "TCP")
        self.assertEqual(pkt.src_ip, "192.168.1.10")
        self.assertEqual(pkt.dst_port, 80)
        self.assertTrue(pkt.tcp_flags["SYN"])
        self.assertIn("192.168.1.10:12345 -> 192.168.1.1:80", pkt.summary)

    def test_arp_packet_summary(self):
        pkt = ParsedPacket(
            timestamp=1600000000.0,
            length=42,
            protocol="ARP",
            src_mac="00:11:22:33:44:55",
            dst_mac="ff:ff:ff:ff:ff:ff",
            src_ip="192.168.1.1",
            dst_ip="192.168.1.255",
            arp_op=1
        )
        self.assertEqual(pkt.protocol, "ARP")
        self.assertIn("[ARP REQ]", pkt.summary)


if __name__ == "__main__":
    unittest.main()
