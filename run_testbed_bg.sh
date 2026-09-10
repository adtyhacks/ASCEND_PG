#!/bin/bash
# run_testbed_noninteractive.sh — Run testbed, execute attack cycle, exit
set -e

cd ~/ascend-pg-webapp

echo "=== Cleaning stale state ==="
echo 'adty' | sudo -S mn -c 2>/dev/null
echo 'adty' | sudo -S killall ovs-testcontroller 2>/dev/null || true

echo "=== Starting testbed in background ==="
echo 'adty' | sudo -S python3 scripts/start_testbed.py &
BGPID=$!
sleep 8

echo "=== Checking network ==="
echo 'adty' | sudo -S ovs-vsctl show | head -5

echo "=== Running attack cycle (option 1) ==="
# Send "1" then "6" to the menu
echo "1"
sleep 2
# The attack cycle runs inside attacker host, wait for it
sleep 30

echo "=== Testbed output complete ==="
