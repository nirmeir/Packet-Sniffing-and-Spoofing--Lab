from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt=sniff(iface=['br-51a6dc77b85b','enp0s3','lo'],filter='dst net 128.230.0.0/16',prn=print_pkt)