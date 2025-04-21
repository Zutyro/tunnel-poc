from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.packet import ls


def construct_icmp_packet(src_ip, dst_ip):
    packet = IP(dst=dst_ip, src=src_ip)/ICMP()
    return packet

def construct_ipip_packet(src_ip, dst_ip, inner_packet):
    packet = IP(dst=dst_ip, src=src_ip)/inner_packet
    return packet





if __name__ == '__main__':
    inner_packet = construct_icmp_packet('192.168.2.2','192.168.1.2')
    tunnel_packet = construct_ipip_packet('192.168.1.2','192.168.2.2', inner_packet)
    print(tunnel_packet)


