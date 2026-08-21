#!/bin/sh
# Provisioning creates the state the workload needs. If snapshot forks
# ever drop provisioned state, every baseline run fails loudly.
set -e
mkdir -p data
echo "seed-material" > data/seed.txt
echo "provision: wrote data/seed.txt"
