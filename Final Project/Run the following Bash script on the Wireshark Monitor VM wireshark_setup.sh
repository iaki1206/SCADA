#!/bin/bash

# Install Wireshark and Python
sudo apt update && sudo apt upgrade -y
sudo apt install -y wireshark python3

# Configure Wireshark
sudo usermod -aG wireshark $USER
sudo reboot