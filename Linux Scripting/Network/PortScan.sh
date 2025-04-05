#!/bin/bash

# Check if nmap is installed
if ! command -v nmap &> /dev/null; then
    echo "[!] Nmap is not installed. Install it with: sudo apt install nmap -y"
    exit 1
fi

# Get local subnet
subnet=$(ip route | grep -oP 'src \K[\d.]+')
base=$(echo "$subnet" | cut -d '.' -f1-3)
range="${base}.0/24"

echo "[*] Scanning $range for live devices..."
nmap -sn $range -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Temporary output file
output="lan_ports_clean.txt"
echo -e "IP_Address\tOpen_Ports" > "$output"

# Scan each live host
for ip in $(cat live_hosts.txt); do
    echo "[*] Scanning $ip for open ports..."
    ports=$(nmap -T4 -F "$ip" | awk '/^[0-9]+\/tcp/ {print $1}' | paste -sd "," -)
    [ -z "$ports" ] && ports="None"
    echo -e "$ip\t$ports" >> "$output"
done

# Display clean table
echo -e "\n[*] Scan complete. Table:"
column -t -s $'\t' "$output"
