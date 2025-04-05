#!/bin/bash

# Check for nmap
if ! command -v nmap &> /dev/null; then
    echo "[!] Nmap is not installed. Run: sudo apt install nmap -y"
    exit 1
fi

# Get subnet (e.g. 192.168.1.0/24)
subnet=$(ip route | grep -oP 'src \K[\d.]+')
base=$(echo "$subnet" | cut -d '.' -f1-3)
range="${base}.0/24"

echo "[*] Scanning $range for live hosts..."
nmap -sn $range -oG - | awk '/Up$/{print $2}' > live_hosts.txt

# Output file
output="lan_aggressive_scan.txt"
echo -e "IP_Address\t\tService_Versions\t\t\t\tOS_Detected" > "$output"

# Aggressive scan each host
for ip in $(cat live_hosts.txt); do
    echo "[*] Aggressively scanning $ip..."
    result=$(nmap -T4 -F -A "$ip")

    # Extract service version info
    services=$(echo "$result" | awk '/^[0-9]+\/tcp/ {
        $1=$1; print $0
    }' | paste -sd " | " -)

    [ -z "$services" ] && services="None"

    # Extract OS
    os=$(echo "$result" | grep -i "OS details:" | cut -d ':' -f2- | xargs)
    [ -z "$os" ] && os="Unknown"

    # Add to output
    printf "%-16s\t%-50s\t%s\n" "$ip" "$services" "$os" >> "$output"
done

# Show results in table
echo -e "\n[*] Scan complete. Final result:"
column -t -s $'\t' "$output"
