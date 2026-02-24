from scapy.all import *

pkt1 = IP(dst="8.8.8.8")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")
pkt2 = IP(dst="1.1.1.1")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com"))

wrpcap("test.pcap", [pkt1, pkt2])

print("Real test.pcap generated successfully")
