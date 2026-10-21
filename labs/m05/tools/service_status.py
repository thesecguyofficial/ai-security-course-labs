"""
tools/service_status.py: a tiny "status checker" the helpdesk app runs as a separate program.

Real apps often shell out to helpers like this (ping, nslookup, a vendor CLI, a script your team wrote).
This one just prints a FAKE status from the table below. Nothing here touches the network.

Usage:  python tools/service_status.py vpn
"""

import sys

FAKE_STATUS = {
    "vpn": "VPN gateway: OK (fake data)",
    "email": "Email: degraded, 2 queued messages (fake data)",
    "printer": "Printer floor 3: out of paper (fake data)",
    "wifi": "Office Wi-Fi: OK (fake data)",
}

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: service_status.py <service>")
        sys.exit(2)
    name = sys.argv[1]
    print(FAKE_STATUS.get(name, f"Unknown service: {name}"))
