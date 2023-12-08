#!/usr/bin/env bash

ryu-manager ryu_controller.py &> logs/ryu-controller.log &
sudo python3 mininet-sim.py

killall ryu-manager
