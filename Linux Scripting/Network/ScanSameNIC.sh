#!/bin/bash

# Get the subnet (like 192.168.1.0/24)
subnet=$(ip route | grep -oP 'src \K[\d.]+')
base=$(echo "$subnet" | cut -d '.' -f1-3)

echo "[*] Pinging all devices on $base.0/24 to populate ARP cache..."
for i in {1..254}; do
    (ping -c 1 -W 1 $base.$i > /dev/null &) 
done
wait

echo "[*] Gathering ARP table..."
arp -a > arp_raw.txt

echo "[*] Extracting MACs and resolving vendors..."
echo -e "IP Address\t\tMAC Address\t\tVendor" > network_vendors.txt

while read -r line; do
    ip=$(echo $line | awk '{print $2}' | tr -d '()')
    mac=$(echo $line | awk '{print $4}')
    if [[ $mac == *:*:* ]]; then
        vendor=$(curl -s "https://api.macvendors.com/$mac")
        printf "%-16s\t%-20s\t%s\n" "$ip" "$mac" "$vendor" >> network_vendors.txt
    fi
done < <(arp -a)

echo "[*] Done. Output saved to network_vendors.txt"
cat network_vendors.txt
