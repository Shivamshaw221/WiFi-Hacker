import subprocess
import os
import argparse
from scapy.all import *
import time

def show_logo():
    logo = """
            _    _ _  __ _           _    _             _             
           | |  | (_)/ _(_)         | |  | |           | |            
           | |  | |_| |_ _  ___ __ _| |__| |_   _  __ _| |_ ___  _ __ 
           | |  | | |  _| |/ __/ _` |  __  | | | |/ _` | __/ _ \| '__|
           | |__| | | | | | (_| (_| | |  | | |_| | (_| | || (_) | |   
            \____/|_|_| |_|\___\__,_|_|  |_|\__,_|\__,_|\__\___/|_|   

                           WiFi Hacking Tool
                          Created by Shivam Kumar Shaw
    """
    print(logo)

def switch_mode(interface, mode):
    show_logo()
    """
    Switches the network interface to the specified mode (monitor/managed).
    """
    if mode not in ['monitor', 'managed']:
        print(f"[-] Invalid mode: {mode}. Choose 'monitor' or 'managed'.")
        return

    print(f"[+] Switching {interface} to {mode} mode")
   
