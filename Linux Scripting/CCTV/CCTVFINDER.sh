#!/bin/bash
IP="192.168.29.1"
echo "[*] Scanning for camera services on $IP..."

nmap -Pn -p 80,443,554,8000,8080,8888,5000,3702 -sV --script=http-title,http-headers,rtsp-methods $IP
