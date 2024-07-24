# WiFi Hacker

WiFi Hacker is a tool for capturing and cracking WPA handshakes. It includes features for scanning WiFi networks, performing deauthentication attacks, and capturing WPA handshakes.

## Features

- Scan for WiFi networks
- Perform deauthentication attacks
- Capture WPA handshakes
- Crack WPA handshakes using a wordlist

## Usage

```sh
python wifi_hacker.py -i <interface> -H <handshake> -w <wordlist>
Options
-i, --interface: Network interface to use for capturing handshake (required)
-H, --handshake: File to save the captured handshake (optional)
-w, --wordlist: Wordlist file to use for cracking the handshake (optional)
-s, --switch: Switch interface mode (monitor/managed) (optional)
-S, --scan: Scan for available WiFi networks (optional)
-d, --deauth: Perform deauth attack (requires --bssid and --client) (optional)
--bssid: Target BSSID for deauth attack
--client: Target client MAC address for deauth attack
