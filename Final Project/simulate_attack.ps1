# Connect to SCADA Server
plink -ssh admin@192.168.1.10

# Test Modbus connectivity
Test-NetConnection -ComputerName 192.168.1.30 -Port 502