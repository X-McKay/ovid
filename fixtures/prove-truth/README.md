Truth fixture for `ovid prove`: `make deps` provisions `data/seed.txt`;
`make test` passes deterministically (no network) only when provisioning
state survives into each trial's snapshot fork.
