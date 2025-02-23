#!/bin/bash

# Update and install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv sqlite3 wireshark git

# Clone OpenPLC for SCADA simulation
git clone https://github.com/thiagoralves/OpenPLC_v3.git
cd OpenPLC_v3 && ./install.sh

# Configure Wireshark for non-root capture
sudo usermod -aG wireshark $USER
sudo reboot
