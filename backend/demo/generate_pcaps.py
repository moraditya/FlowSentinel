#!/usr/bin/env python3
"""
Generate small demo PCAP files for replay testing.

Usage:
    python demo/generate_pcaps.py

Creates benign.pcap, port_scan.pcap, brute_force.pcap in the demo/ directory.
"""

from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, Raw, wrpcap

DEMO_DIR = Path(__file__).parent


def _benign_traffic() -> list:
    """Normal web browsing and DNS traffic."""
    packets = []
    base_time = 1700000000.0

    # DNS queries
    for i in range(20):
        pkt = (
            Ether()
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=50000 + i, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=f"example{i}.com"))
        )
        pkt.time = base_time + i * 0.5
        packets.append(pkt)

    # HTTP-like TCP connections (SYN, SYN-ACK, ACK, data, FIN)
    for i in range(30):
        t = base_time + 10 + i * 1.0
        src_port = 40000 + i
        dst_ip = f"93.184.216.{34 + (i % 5)}"

        syn = Ether() / IP(src="192.168.1.100", dst=dst_ip) / TCP(sport=src_port, dport=80, flags="S")
        syn.time = t

        syn_ack = Ether() / IP(src=dst_ip, dst="192.168.1.100") / TCP(sport=80, dport=src_port, flags="SA")
        syn_ack.time = t + 0.01

        ack = Ether() / IP(src="192.168.1.100", dst=dst_ip) / TCP(sport=src_port, dport=80, flags="A")
        ack.time = t + 0.02

        data = (
            Ether()
            / IP(src="192.168.1.100", dst=dst_ip)
            / TCP(sport=src_port, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
        data.time = t + 0.03

        fin = Ether() / IP(src="192.168.1.100", dst=dst_ip) / TCP(sport=src_port, dport=80, flags="FA")
        fin.time = t + 0.5

        packets.extend([syn, syn_ack, ack, data, fin])

    return packets


def _port_scan_traffic() -> list:
    """nmap-style SYN scan across many ports."""
    packets = []
    base_time = 1700000100.0
    target = "10.0.0.50"

    for i, port in enumerate(range(20, 1024, 5)):
        t = base_time + i * 0.02  # fast scan

        syn = Ether() / IP(src="192.168.1.200", dst=target) / TCP(sport=60000 + i, dport=port, flags="S")
        syn.time = t

        # Most ports: RST (closed)
        if port not in (22, 80, 443):
            rst = Ether() / IP(src=target, dst="192.168.1.200") / TCP(sport=port, dport=60000 + i, flags="RA")
            rst.time = t + 0.001
            packets.extend([syn, rst])
        else:
            # Open ports: SYN-ACK then RST from scanner
            sa = Ether() / IP(src=target, dst="192.168.1.200") / TCP(sport=port, dport=60000 + i, flags="SA")
            sa.time = t + 0.001
            rst = Ether() / IP(src="192.168.1.200", dst=target) / TCP(sport=60000 + i, dport=port, flags="R")
            rst.time = t + 0.002
            packets.extend([syn, sa, rst])

    return packets


def _brute_force_traffic() -> list:
    """Repeated short SSH connection attempts."""
    packets = []
    base_time = 1700000200.0
    target = "10.0.0.10"

    for i in range(50):
        t = base_time + i * 0.3
        src_port = 55000 + i

        syn = Ether() / IP(src="192.168.1.150", dst=target) / TCP(sport=src_port, dport=22, flags="S")
        syn.time = t

        sa = Ether() / IP(src=target, dst="192.168.1.150") / TCP(sport=22, dport=src_port, flags="SA")
        sa.time = t + 0.005

        ack = Ether() / IP(src="192.168.1.150", dst=target) / TCP(sport=src_port, dport=22, flags="A")
        ack.time = t + 0.01

        # Short data exchange then RST (failed auth)
        data = (
            Ether()
            / IP(src="192.168.1.150", dst=target)
            / TCP(sport=src_port, dport=22, flags="PA")
            / Raw(load=b"SSH-2.0-OpenSSH_8.9\r\n")
        )
        data.time = t + 0.02

        rst = Ether() / IP(src=target, dst="192.168.1.150") / TCP(sport=22, dport=src_port, flags="R")
        rst.time = t + 0.1

        packets.extend([syn, sa, ack, data, rst])

    return packets


def main():
    benign = _benign_traffic()
    port_scan = _port_scan_traffic()
    brute_force = _brute_force_traffic()

    wrpcap(str(DEMO_DIR / "benign.pcap"), benign)
    print(f"Created benign.pcap ({len(benign)} packets)")

    wrpcap(str(DEMO_DIR / "port_scan.pcap"), port_scan)
    print(f"Created port_scan.pcap ({len(port_scan)} packets)")

    wrpcap(str(DEMO_DIR / "brute_force.pcap"), brute_force)
    print(f"Created brute_force.pcap ({len(brute_force)} packets)")


if __name__ == "__main__":
    main()
