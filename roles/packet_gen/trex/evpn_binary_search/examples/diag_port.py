#!/usr/bin/env python3
import sys
TREX_DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/trex/v3.06"
sys.path.insert(0, f"{TREX_DIR}/automation/trex_control_plane/interactive")
from trex.stl.api import STLClient

c = STLClient(server="127.0.0.1")
c.connect()
try:
    c.reset(ports=[0])
    c.set_service_mode(ports=[0], enabled=True)
    c.resolve(ports=[0])
    c.set_service_mode(ports=[0], enabled=False)
    print("== port_attr ==")
    print(c.get_port_attr(0))
    print("== port_status ==")
    st = c.ports[0].get_formatted_info() if hasattr(c.ports[0], "get_formatted_info") else {}
    for k in ("src_mac", "src_ipv4", "dest", "link", "speed", "layer_mode", "arp"):
        if k in st:
            print(f"  {k}: {st[k]}")
    print("== xstats (tx/rx nonzero) ==")
    xs = c.get_xstats(0)
    for k, v in xs.items():
        if v and ("tx" in k.lower() or "rx" in k.lower() or "err" in k.lower() or "drop" in k.lower()):
            print(f"  {k} = {v}")
finally:
    c.disconnect()
