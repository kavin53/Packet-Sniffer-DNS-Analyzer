from scapy.all import sniff
from analyzer import analyze_packet


def start_sniffing():
    print("Starting sniffing...\n")

    sniff(
        prn=analyze_packet,
        store=False,
        filter = "ip"
    )