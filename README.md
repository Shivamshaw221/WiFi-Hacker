
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
```

## Usage

### Options
```
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
```

### Step-by-Step Guide

1. **Install Requirements**:
    ```sh
    pip install -r requirements.txt
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
    sudo python wifi_hacker.py -i <interface> -H handshake/handshake.cap -w /path/to/wordlist.txt
    ```

7. **Automatic Mode for Capturing Handshake**:
    ```sh
    sudo python wifi_hacker.py -i <interface> -a
    ```

## Example Usage
```sh
# Switch interface to monitor mode
sudo python wifi_hacker.py -i wlan0 -s monitor

# Scan for networks
sudo python wifi_hacker.py -i wlan0 -S

# Automatic mode for capturing handshake
sudo python wifi_hacker.py -i wlan0 -a

# Perform deauth attack manually
sudo python wifi_hacker.py -i wlan0 -d --bssid 00:11:22:33:44:55 --client AA:BB:CC:DD:EE:FF

# Crack WPA2 handshake
sudo python wifi_hacker.py -i wlan0 -H handshake/00-11-22-33-44-55.cap -w wordlist.txt
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.
