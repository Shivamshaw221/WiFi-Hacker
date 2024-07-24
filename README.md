# WiFi Hacker

WiFi Hacker is a Python script to automate the process of scanning WiFi networks, capturing WPA handshakes, and performing deauthentication attacks.

## Features

- WiFi Network Scanning
- Deauthentication Attack
- WPA Handshake Capture
- WPA Handshake Cracking

## Usage

1. Clone the repository
    ```sh
    git clone https://github.com/Shivamshaw221/wifi-hacking.git
    cd wifi_hacker
    ```

2. Install the required packages
    ```sh
    pip install -r requirements.txt
    ```

3. Run the script with the desired options
    ```sh
    python wifi_hacker.py -i wlan0 -s monitor
    python wifi_hacker.py -i wlan0 -S
    python wifi_hacker.py -i wlan0 -d --bssid xx:xx:xx:xx:xx:xx --client yy:yy:yy:yy:yy:yy
    python wifi_hacker.py -i wlan0 -H handshake.cap -w wordlist.txt
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
