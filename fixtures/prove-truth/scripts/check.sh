#!/bin/sh
# Deterministic offline workload: passes iff provisioning ran first.
set -e
grep -q "seed-material" data/seed.txt
echo "check: ok"
