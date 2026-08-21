"""Fixture app: attempts a config read and a database connection.

Both failures are tolerated: the app exits 0 so the failed boundaries are
observed as *optional* dependencies (natural counterfactual).
"""
import socket

def main() -> None:
    try:
        open("/etc/python-app/config.yaml")
    except OSError:
        pass
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", 5432))
    except OSError:
        pass
    finally:
        s.close()
    print("python-app done")

if __name__ == "__main__":
    main()
