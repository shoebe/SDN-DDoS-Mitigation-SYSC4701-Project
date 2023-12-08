#!/usr/bin/env bash
mkdir logs

BCP38_ENABLED=1 DDOS_MITIGATION=1 ryu-manager ryu_controller.py &> logs/ryu-controller.log &
sudo python3 mininet-sim.py

killall ryu-manager
rm logs/*