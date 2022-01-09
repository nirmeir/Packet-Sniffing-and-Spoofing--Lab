from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt=sniff(iface=['br-51a6dc77b85b','enp0s3','lo'],filter='icmp',prn=print_pkt)

