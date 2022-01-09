from scapy.all import *

Rounded = True
i=1

while Rounded:
    header = IP(dst='65.9.124.33', ttl=i)
    response = sr1(header/ICMP(),timeout=7,verbose=0)

    if response is None:
        print(f"{i} Request timed out.")
    elif response.type == 0:
        print(f"{i} {response.src}")
        Rounded=False
    else:
        print(f"{i} {response.src}")  

    i=i+1          

