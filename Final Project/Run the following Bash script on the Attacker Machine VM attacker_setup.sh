#!/bin/bash

# Update and install tools
sudo apt update && sudo apt upgrade -y
sudo apt install -y nmap hydra python3 python3-pip

# Install Python libraries
pip3 install scapy pandas