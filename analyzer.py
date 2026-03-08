from scapy.layers.inet import IP,TCP,UDP
from scapy.layers.dns import DNSQR,DNS

def analyze_packet(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(DNS):
        domain = packet[DNSQR].qname.decode()
        print(f"[DNS Request] {domain}")


    if packet.haslayer(IP):

        src = packet[IP].src
        dst = packet[IP].dst

        protocol = "other"
        sport = ""
        dport = ""

        if packet.haslayer(TCP):
            protocol = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        print(f"{src}:{sport} ---> {dst}:{dport} | Protocol: {protocol}")
