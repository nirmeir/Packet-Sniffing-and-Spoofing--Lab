from scapy.all import *

i = IP()

i.src='1.2.3.4'
i.dst='10.9.0.6'

send(i/ICMP())

ls(i)
