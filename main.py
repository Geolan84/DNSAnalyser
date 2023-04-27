from scapy.all import IP, UDP, RandShort, sr1, sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from datetime import datetime

CONST_SERVER = "8.8.8.8"

dns_summary = []

def packet_sniff(packet):
    """Packet handler."""
    if packet.haslayer(DNS):
        print(f'\nВремя захвата пакета: {datetime.now()}\n')
        dns_summary.append(packet.summary())
        print(packet.show())
        print()

def listen_dns(limit: int):
    """Captures DNS packets, saves frames and summary."""
    dns_summary.clear()
    print("Now program captures packets. Press Ctrl+C to stop handling or wait.")
    sniff(filter='dst port 53 or src port 53', timeout=limit, prn=packet_sniff)
    print("\nОбщая сводка перехваченных пакетов:")
    print(*dns_summary, sep="\n")
    print()

def search_mx(domain: str) -> list:
    """Get mail-exchanger from MX-record."""
    result = sr1(IP(dst=CONST_SERVER)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="MX")), verbose=0)
    try:
        return [x.exchange for x in result.an.iterpayloads()]
    except Exception:
        return []
    

def get_ip_by_domain(domain: str):
    """Get all IP-addresses for domain name."""
    try:
        result = sr1(IP(dst=CONST_SERVER)/UDP(sport=RandShort(), dport=53)/DNS(rd=1, qd=DNSQR(qname=domain, qtype="A")), verbose=0)
        return [result[DNSRR][x].rdata for x in range(result[DNS].ancount)]
    except Exception:
        return "\nWARNING! Something went wrong, try later!\n"



CONST_MESSAGE = r"""It is the program for scanning DNS packets and it supports commands:
1) 'capture {timeout}' - handles all packets and prints their body with timeout in seconds;
2) 'ipmx {Domain}' - find ip-addresses of mx address of domain
3) 'getip {Domain}' - find ip-addresses of domain;
4) 'exit' - stops program"""

def main():
    while True:
        print(CONST_MESSAGE)
        commands = input().split(" ")
        if len(commands) == 2: 
            match commands[0]:
                case "capture":
                    try:
                        timeout = int(commands[1])
                        listen_dns(timeout)
                    except ValueError:
                        print("timeout should be a number!")
                case "ipmx":
                    service = search_mx(commands[1])
                    if service != []:
                        print(f"\nIP-addresses of mail service of {commands[1]} domain:", 
                                *get_ip_by_domain(service[0].decode("utf-8")), "", sep="\n")
                    else:
                        print("Mail-service not found:(")
                case "getip":
                    print(f"{commands[1]} has IP:",
                            *get_ip_by_domain(commands[1]), "", sep="\n")
                case default:
                    print("Incorrect command!")
        else:
            if commands[0] == 'exit':
                break
            print("Incorrect count of arguments")


        
if __name__ == "__main__":
    main()