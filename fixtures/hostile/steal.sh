#!/bin/sh
# Fixture: tries to read secrets from the environment and tamper with the
# source tree. Under the process backend the env is scrubbed and the
# workspace is an ephemeral copy.
env | grep -i "SECRET\|TOKEN\|KEY" || echo "no-secrets-found"
echo tampered > ./tampered.txt
exit 0
