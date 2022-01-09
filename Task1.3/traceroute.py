from scapy.all import *
a = IP()
a.dst = '8.8.8.8'
a.ttl = 10  # change the number from 1 to 10
b = ICMP()
send(a/b)
