from scapy.all import *

def print_pkt(pkt):

    if pkt[ICMP] is not None:
        if pkt[ICMP].type ==0 or pkt[ICMP].type==8:
            print("######ICMP######")
            print(f"\tSrc: {pkt[IP].src}")
            print(f"\tDest: {pkt[IP].dst}")

            if pkt[ICMP].type ==8 :
                print(f"\tICMP type: echo-request")
            if pkt[ICMP].type ==0 :
                print(f"\tICMP type: echo-reply")  


pkt=sniff(iface=['br-51a6dc77b85b','enp0s3','lo'],filter='icmp',prn=print_pkt)



