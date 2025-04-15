#!/bin/bash

# CCTV Network Scanner Tool for Linux
# Created by ChatGPT for powerful local network CCTV discovery

# ========== Auto Install Dependencies ==========
echo "[*] Checking and installing dependencies..."
REQUIRED_TOOLS=(nmap arp-scan curl iproute2 coreutils grep awk sed)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &>/dev/null; then
        echo "[*] Installing missing package: $tool"
        sudo apt-get install -y $tool
    else
        echo "[+] $tool is already installed."
    fi
done

# ========== Configuration ==========
REPORT_DIR="$HOME/Desktop/cctv_scan_report"
REPORT_FILE="$REPORT_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
CAMERA_PORTS="554,80,8080,443,37777,8000,8899"
CAMERA_VENDORS="hikvision|dahua|axis|vivotek|tp-link|bosch|panasonic|sony|netatmo|arlo|unifi|hik|vivotek|trendnet|wansview|foscam|amcrest|reolink|sv3c|annke|zmodo|yicam|canary|ezviz|logitech|nintendo|samsung|mobotix|geovision|lorex|intellinet|avtech|arecont|sercomm|tenvis|acti|jvc|pelco|toshiba|grandstream|cisco|ubiquiti"

mkdir -p "$REPORT_DIR"

# ========== Global Interface Selector ==========
select_interface() {
    echo "[*] Available interfaces:"
    interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v lo))
    for i in "${!interfaces[@]}"; do
        echo "$((i+1))) ${interfaces[$i]}"
    done
    read -p "Select an interface [1-${#interfaces[@]}] or press enter for ALL: " choice
    if [[ -n "$choice" && "$choice" =~ ^[0-9]+$ && $choice -ge 1 && $choice -le ${#interfaces[@]} ]]; then
        SELECTED_INTERFACE="${interfaces[$((choice-1))]}"
        echo "[*] Using interface: $SELECTED_INTERFACE"
    else
        SELECTED_INTERFACE=""
        echo "[*] Using all interfaces."
    fi
}

# ========== Helper Functions ==========
get_all_subnets() {
    if [[ -n "$SELECTED_INTERFACE" ]]; then
        ip -o -f inet addr show dev "$SELECTED_INTERFACE" | awk '/scope global/ {print $4}'
    else
        ip -o -f inet addr show | awk '/scope global/ {print $4}'
    fi
}

print_banner() {
    echo "========================================"
    echo "      CCTV Network Scanner for Linux    "
    echo "========================================"
}

scan_network() {
    echo "[*] Scanning network interfaces..."
    > "$REPORT_DIR/live_hosts.txt"
    for subnet in $(get_all_subnets); do
        echo "[*] Scanning subnet: $subnet"
        sudo nmap -e "$SELECTED_INTERFACE" -p $CAMERA_PORTS --open -T4 -oG - $subnet \
            | awk '/Up$/{print $2}' >> "$REPORT_DIR/live_hosts.txt"
    done
    sort -u "$REPORT_DIR/live_hosts.txt" -o "$REPORT_DIR/live_hosts.txt"
    echo "[*] Found $(wc -l < "$REPORT_DIR/live_hosts.txt") unique live hosts with CCTV-related open ports."
}

mac_vendor_check() {
    echo "[*] Checking MAC vendors..."
    > "$REPORT_DIR/mac_vendors.txt"
    if [[ -n "$SELECTED_INTERFACE" ]]; then
        echo "[*] Interface: $SELECTED_INTERFACE"
        sudo arp-scan --interface=$SELECTED_INTERFACE --localnet 2>/dev/null \
            | grep -iE "$CAMERA_VENDORS" >> "$REPORT_DIR/mac_vendors.txt"
    else
        for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -v lo); do
            echo "[*] Interface: $iface"
            sudo arp-scan --interface=$iface --localnet 2>/dev/null \
                | grep -iE "$CAMERA_VENDORS" >> "$REPORT_DIR/mac_vendors.txt"
        done
    fi
    cat "$REPORT_DIR/mac_vendors.txt"
}

scan_rtsp() {
    echo "[*] Scanning for RTSP (port 554)"
    while read ip; do
        echo -n "[*] Checking $ip... "
        timeout 5 bash -c "</dev/tcp/$ip/554" &>/dev/null && echo "RTSP OPEN" || echo "No RTSP"
    done < "$REPORT_DIR/live_hosts.txt"
}

scan_web_interfaces() {
    echo "[*] Checking for web interfaces on ports 80/8080/443"
    while read ip; do
        for port in 80 8080 443; do
            echo -n "[*] $ip:$port -> "
            timeout 5 curl -s -k --head http://$ip:$port | grep -i "Server:" || echo "No response"
        done
    done < "$REPORT_DIR/live_hosts.txt"
}

export_report() {
    echo "[*] Consolidating results..."
    cat "$REPORT_DIR"/*.txt > "$REPORT_FILE"
    echo "[*] Report saved to: $REPORT_FILE"
}

# ========== Main Menu ==========
while true; do
    print_banner
    select_interface
    echo "1) Full Network CCTV Scan (all methods)"
    echo "2) Quick Camera Vendor Scan (MAC check)"
    echo "3) Scan for RTSP Streams"
    echo "4) Scan for Web Interfaces"
    echo "5) Export Report"
    echo "6) Exit"
    read -rp "Choose an option: " choice

    case $choice in
        1)
            scan_network
            mac_vendor_check
            scan_rtsp
            scan_web_interfaces
            export_report
            read -p "Press enter to continue...";;
        2)
            mac_vendor_check
            read -p "Press enter to continue...";;
        3)
            scan_rtsp
            read -p "Press enter to continue...";;
        4)
            scan_web_interfaces
            read -p "Press enter to continue...";;
        5)
            export_report
            read -p "Press enter to continue...";;
        6)
            echo "Bye!"; exit 0;;
        *)
            echo "Invalid option";;
    esac

done
