# WiFi Hacker
 _    _            _    
| |  | |          | |   
| |__| | __ _  ___| | __
|  __  |/ _` |/ __| |/ /
| |  | | (_| | (__|   < 
|_|  |_|\__,_|\___|_|\_\

## Features

- Switch network interface mode between monitor and managed.
- Scan for available WiFi networks.
- Capture WPA handshakes.
- Perform deauthentication attacks.
- Crack WPA handshakes using a wordlist.

## Requirements

- Python 3.x
- scapy
- hashcat

## Installation

1. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

2. Ensure you have `hashcat` installed on your system.

## Usage

1. **Display Help**:
    ```sh
    sudo python wifi_hacker.py -h
    ```

    This will display:
    ```text
    usage: wifi_hacker.py [-h] -i INTERFACE [-H HANDSHAKE] [-w WORDLIST] [-s {monitor,managed}] [-S] [-d] [--bssid BSSID] [--client CLIENT]

    WiFi Hacker: WPA Handshake Capture and Crack Tool

    optional arguments:
      -h, --help            show this help message and exit
      -i INTERFACE, --interface INTERFACE
                            Network interface to use for capturing handshake
      -H HANDSHAKE, --handshake HANDSHAKE
                            File to save the captured handshake
      -w WORDLIST, --wordlist WORDLIST
                            Wordlist file to use for cracking the handshake
      -s {monitor,managed}, --switch {monitor,managed}
                            Switch interface mode (monitor/managed)
      -S, --scan            Scan for available WiFi networks
      -d, --deauth          Perform deauth attack (requires --bssid and --client)
      --bssid BSSID         Target BSSID for deauth attack
      --client CLIENT       Target client MAC address for deauth attack
    ```

2. **Switch Interface to Monitor Mode**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -s monitor
    ```

3. **Switch Interface to Managed Mode**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -s managed
    ```

4. **Scan for Available WiFi Networks**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -S
    ```

5. **Perform Deauthentication Attack**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -d --bssid <target_bssid> --client <target_client_mac>
    ```

6. **Run the Script to Capture and Crack WPA Handshake**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -H handshake.cap -w /path/to/wordlist.txt
    ```

## Disclaimer

This tool is for educational purposes only. Unauthorized use of this tool to capture or crack WPA handshakes without explicit permission from the network owner is illegal. The author is not responsible for any misuse or damage caused by this tool.


