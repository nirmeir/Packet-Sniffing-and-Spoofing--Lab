from scapy.all import *

def print_pkt(pkt):

    if pkt[TCP] is not None:
            print("######TCP######")
            print(f"\tSrc: {pkt[IP].src}")
            print(f"\tDest: {pkt[IP].dst}")
            print(f"\tSrc port: {pkt[TCP].sport}")
            print(f"\tDest port: {pkt[TCP].dport}")


          
         
pkt=sniff(iface=['br-51a6dc77b85b','enp0s3','lo'],filter='tcp port 23 and src host 10.9.0.1',prn=print_pkt)



