#!/bin/sh
# Fixture: attempts postgres and redis on loopback high ports (refused),
# then succeeds anyway (dependencies are optional for this workload).
python3 - <<'PY'
import socket
for port in (5432, 6379):
    s = socket.socket()
    s.settimeout(0.3)
    try:
        s.connect(("127.0.0.1", port))
    except OSError:
        pass
    finally:
        s.close()
print("network-caller done")
PY
