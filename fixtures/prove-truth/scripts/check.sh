#!/bin/sh
# Deterministic offline workload: passes iff provisioning ran first and
# the environment provides grep and awk (hide-executable truth targets).
set -e
grep -q "seed-material" data/seed.txt
awk 'NR==1 {exit 0}' data/seed.txt
echo "check: ok"
