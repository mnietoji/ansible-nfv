#!/usr/bin/env python3
"""
Diagnostic: capture what actually arrives on the TRex PF (port 0) while we send
a low-rate EVPN Type-5 VXLAN stream, to tell apart real EVPN return traffic
(outer src = compute-1 VTEP 12.12.12.3, UDP dport 4789) from ARP / noise.
"""
import sys
import struct
import time

TREX_DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/trex/v3.06"
sys.path.insert(0, f"{TREX_DIR}/automation/trex_control_plane/interactive")
from trex.stl.api import (  # noqa: E402
    STLClient, STLStream, STLPktBuilder, STLTXCont, Ether, IP, UDP, Raw,
)

OUTER_SRC, OUTER_DST = "12.12.12.20", "12.12.12.3"
VXLAN_DPORT, VNI = 4789, 1001
INNER_RMAC, INNER_SRC, INNER_DST = "fa:16:3e:97:ca:bb", "192.168.99.10", "192.168.77.221"


def vxlan_hdr(vni):
    return b"\x08\x00\x00\x00" + struct.pack("!I", vni << 8)


pkt = (Ether() / IP(src=OUTER_SRC, dst=OUTER_DST) /
       UDP(sport=(1 << 15), dport=VXLAN_DPORT) / Raw(vxlan_hdr(VNI)) /
       Ether(dst=INNER_RMAC) / IP(src=INNER_SRC, dst=INNER_DST) /
       UDP(sport=1025, dport=7777) / Raw(b"\x00" * 64))  # NOT 53 (OVN DNS punt)

c = STLClient(server="127.0.0.1")
c.connect()
try:
    c.reset(ports=[0])
    c.set_service_mode(ports=[0], enabled=True)
    c.resolve(ports=[0])
    cap = c.start_capture(rx_ports=[0], limit=200)
    c.add_streams([STLStream(packet=STLPktBuilder(pkt=pkt),
                             mode=STLTXCont(pps=5000))], ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="5000pps", duration=5, force=True)
    c.wait_on_traffic(ports=[0])
    pkts = []
    c.stop_capture(cap["id"], output=pkts)
    s = c.get_stats()[0]
    print(f"opackets={s['opackets']} ipackets={s['ipackets']} captured={len(pkts)}")
    seen = {}
    for p in pkts[:200]:
        raw = p["binary"]
        et = struct.unpack("!H", raw[12:14])[0]
        if et == 0x0806:
            key = "ARP"
        elif et == 0x0800:
            proto = raw[23]
            src = ".".join(str(b) for b in raw[26:30])
            dst = ".".join(str(b) for b in raw[30:34])
            if proto == 17:
                dport = struct.unpack("!H", raw[36:38])[0]
                key = f"IP/UDP {src}->{dst} dport={dport}"
            elif proto == 1:
                key = f"IP/ICMP {src}->{dst}"
            else:
                key = f"IP proto={proto} {src}->{dst}"
        else:
            key = f"ethertype=0x{et:04x}"
        seen[key] = seen.get(key, 0) + 1
    print("---- RX packet classes ----")
    for k, v in sorted(seen.items(), key=lambda x: -x[1]):
        print(f"  {v:4d}  {k}")
finally:
    c.set_service_mode(ports=[0], enabled=False)
    c.disconnect()
