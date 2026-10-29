#!/usr/bin/env python3
"""
EVPN Type-5 dataplane smoke runner (TRex STL automation), self-contained.

Confirms the *return* VXLAN traffic (192.168.99.0/24 -> TRex PF 12.12.12.20)
comes back, i.e. the injected EVPN Type-5 route is used for the data path on
the OVN compute (DUT).

Self-contained on purpose: TRex's bundled scapy has no scapy.contrib.vxlan, so
we craft the 8-byte VXLAN header as raw bytes. For a smoke test the packets are
constant (no flow-var VM); the full iMIX+flows profile lives in
trex_evpn_type5_imix.py for the RFC2544 run.

TRex must already run interactively:
  cd /opt/trex/vX.YY && sudo ./t-rex-64 -i --cfg /etc/trex_cfg.yaml
Port 0 = DPDK PF (underlay/VXLAN), L3 mode in trex_cfg.yaml (ARPs gw 12.12.12.3
= compute-1 EVPN VTEP -- no compute-side change).

Usage:  sudo python3 smoke_run.py [TREX_DIR] [RATE] [DURATION_S]
"""
import sys
import struct

TREX_DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/trex/v3.06"
RATE = sys.argv[2] if len(sys.argv) > 2 else "1gbps"
DURATION = int(sys.argv[3]) if len(sys.argv) > 3 else 20

# ---- EVPN underlay/overlay parameters (match the injected Type-5 route) ----
OUTER_SRC = "12.12.12.20"           # TRex underlay / remote VTEP
OUTER_DST = "12.12.12.3"            # compute-1 EVPN VTEP
# L2: stateless TRex does NOT rewrite dst-MAC from the L3 resolve, so set it
# explicitly. SMAC = TRex PF MAC; DMAC = compute-1 vlan178 MAC (= ARP of .3).
OUTER_SMAC = "3c:fd:fe:33:a8:44"
OUTER_DMAC = "96:c4:26:ff:cf:ab"
VXLAN_DPORT = 4789                  # ovn-evpn-4789 OVS/DPDK dataplane tunnel (NOT 60010 kernel)
VNI = 1001
INNER_RMAC = "fa:16:3e:97:ca:bb"    # OVN tenant router-MAC (= Type-5 router's mac, inner DST)
INNER_SMAC = "3c:fd:fe:33:a8:44"    # TRex's own advertised RMAC (symmetric-IRB inner SRC)
INNER_SRC = "192.168.99.10"         # emulated remote-subnet host
INNER_DST = "192.168.77.221"        # tenant workload VM on compute-1
IMIX = [(64, 7), (590, 4), (1518, 1)]   # (on-wire frame size, pps weight)

sys.path.insert(0, f"{TREX_DIR}/automation/trex_control_plane/interactive")
from trex.stl.api import (  # noqa: E402
    STLClient, STLStream, STLPktBuilder, STLTXCont, Ether, IP, UDP, Raw,
)


def vxlan_hdr(vni):
    # flags(1)=0x08 | reserved(3)=0 | VNI(3) | reserved(1)=0
    return b"\x08\x00\x00\x00" + struct.pack("!I", vni << 8)


def build(size):
    base = (
        Ether(src=OUTER_SMAC, dst=OUTER_DMAC) /
        IP(src=OUTER_SRC, dst=OUTER_DST) /
        UDP(sport=(1 << 15), dport=VXLAN_DPORT, chksum=0) /   # outer csum 0 (VTEP-style)
        Raw(vxlan_hdr(VNI)) /
        Ether(src=INNER_SMAC, dst=INNER_RMAC) /
        IP(src=INNER_SRC, dst=INNER_DST) /
        UDP(sport=1025, dport=7777)   # NOT 53: OVN ls_in_dns_lookup punts every
                                      # udp/53 pkt to ovn-controller (per-packet
                                      # userspace punt -> ~30kpps forward cap).
    )
    pad = max(0, size - len(base) - 4)   # -4: FCS not counted by scapy
    return base / Raw(b"\x00" * pad)


c = STLClient(server="127.0.0.1")
c.connect()
try:
    c.reset(ports=[0])
    print("== resolving gateway ARP on port 0 ==")
    c.set_service_mode(ports=[0], enabled=True)
    c.resolve(ports=[0])
    c.set_service_mode(ports=[0], enabled=False)

    streams = [
        STLStream(packet=STLPktBuilder(pkt=build(sz)), mode=STLTXCont(pps=w))
        for sz, w in IMIX
    ]
    c.add_streams(streams, ports=[0])

    c.clear_stats()
    print(f"== start: {RATE} for {DURATION}s ==")
    c.start(ports=[0], mult=RATE, duration=DURATION)
    c.wait_on_traffic(ports=[0])

    s = c.get_stats()[0]
    print("---- port 0 results ----")
    print(f"opackets={s['opackets']}  ipackets={s['ipackets']}")
    print(f"obytes={s['obytes']}  ibytes={s['ibytes']}")
    print(f"tx_bps={s['tx_bps']:.0f}  rx_bps={s['rx_bps']:.0f}")
    print(f"tx_pps={s['tx_pps']:.0f}  rx_pps={s['rx_pps']:.0f}")
    if s["ipackets"] > 0:
        print("RESULT: RETURN TRAFFIC RECEIVED -> EVPN Type-5 data path OK")
    else:
        print("RESULT: no return traffic (ipackets=0)")
finally:
    c.disconnect()
