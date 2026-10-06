#!/usr/bin/env python3
"""
EVPN Type-5 (VXLAN) dataplane NDR runner for TRex STL -- self-contained.

This is the automated, binary-search version of smoke_run.py. It crafts the
VXLAN-encapsulated Type-5 flow (TRex's bundled scapy has no scapy.contrib.vxlan,
so the 8-byte VXLAN header is built as raw bytes) and finds the strict
zero-loss NDR (round-trip rx >= tx) that the OVN EVPN compute (DUT) can forward.

It exists because the bench-trafficgen binary-search / trex-txrx.py cannot
encapsulate VXLAN, so scenario 3 (tenant<->tenant via ToR, real Type-5
dataplane) cannot be driven by the stock trafficgen step. The ansible-nfv role
binary_search branches to this script when dut_type == 'evpn'.

It prints a result line that report_junitxml / gather_perf_info can parse:
field $4 is the per-direction NDR in pps with a trailing ',' (stripped, then x2
for the two directions), and the line contains the token 'tx_pps'. Example:

    EVPN_NDR tx_pps rx_pps 1575000,

TRex must already be running interactively (launch_trex role does this):
    cd /opt/trex/vX.YY && sudo ./t-rex-64 -i --cfg /etc/trex_cfg.yaml
Port 0 = DPDK PF (underlay/VXLAN), L3 mode in trex_cfg.yaml (ARPs gw
12.12.12.3 = compute-1 EVPN VTEP). No compute-side change.

Usage:
    sudo python3 ndr_evpn_vxlan.py [TREX_DIR] [FRAME] [DUR_S] [LO_pps] [HI_pps]
      FRAME    on-wire frame incl. tunnel, excl FCS (default 92 = EVPN floor)
      DUR_S    seconds per trial (default 30)
      LO/HI    binary-search bounds in pps (default 100000..2000000)
               LO == HI runs a single point (no search).
All encap constants below MUST match the injected Type-5 route (see smoke_run.py
and the evpn_return_path role).
"""
import sys
import struct
import time

TREX_DIR = sys.argv[1] if len(sys.argv) > 1 else "/opt/trex/v3.06"
FRAME    = int(sys.argv[2]) if len(sys.argv) > 2 else 92
DUR      = int(sys.argv[3]) if len(sys.argv) > 3 else 30
LO       = int(sys.argv[4]) if len(sys.argv) > 4 else 100000
HI       = int(sys.argv[5]) if len(sys.argv) > 5 else 2000000

# ---- EVPN underlay/overlay parameters (match the injected Type-5 route) ----
OUTER_SMAC  = "3c:fd:fe:33:a8:44"   # TRex PF MAC
OUTER_DMAC  = "96:c4:26:ff:cf:ab"   # compute-1 vlan178 MAC (ARP of 12.12.12.3)
OUTER_SRC   = "12.12.12.20"         # TRex underlay / remote VTEP
OUTER_DST   = "12.12.12.3"          # compute-1 EVPN VTEP
VXLAN_DPORT = 4789                  # ovn-evpn 4789 OVS/DPDK dataplane tunnel
VNI         = 1001
INNER_RMAC  = "fa:16:3e:97:ca:bb"   # OVN tenant router-MAC (inner DST)
INNER_SMAC  = "3c:fd:fe:33:a8:44"   # TRex advertised RMAC (inner SRC)
INNER_SRC   = "192.168.99.10"       # emulated remote-subnet host
INNER_DST   = "192.168.77.221"      # tenant workload VM on compute-1
INNER_DPORT = 7777                  # NOT 53/67/68/546/547 (OVN ls punt flows)

sys.path.insert(0, TREX_DIR + "/automation/trex_control_plane/interactive")
from trex.stl.api import (                       # noqa: E402
    STLClient, STLStream, STLTXCont, STLPktBuilder, STLError,
)
from scapy.layers.l2 import Ether                # noqa: E402
from scapy.layers.inet import IP, UDP            # noqa: E402
from scapy.packet import Raw                     # noqa: E402


def vxlan_hdr(vni):
    # 8-byte VXLAN: flags(I)=0x08, reserved(3B)=0, VNI(3B), reserved(1B)=0
    return struct.pack("!I", 0x08000000) + struct.pack("!I", (vni << 8))


def build(size):
    """Craft one VXLAN/Type-5 frame padded to `size` bytes on-wire (excl FCS)."""
    inner = (Ether(src=INNER_SMAC, dst=INNER_RMAC) /
             IP(src=INNER_SRC, dst=INNER_DST) /
             UDP(sport=1025, dport=INNER_DPORT))
    base = (Ether(src=OUTER_SMAC, dst=OUTER_DMAC) /
            IP(src=OUTER_SRC, dst=OUTER_DST) /
            UDP(sport=49152, dport=VXLAN_DPORT) /
            Raw(vxlan_hdr(VNI)) /
            inner)
    pad = max(0, size - len(base) - 4)            # -4 FCS accounting
    return base / Raw(b"\x00" * pad) if pad else base


def trial(c, pps, dur):
    pkt = STLPktBuilder(pkt=build(FRAME))
    c.reset(ports=[0])
    c.add_streams(STLStream(packet=pkt, mode=STLTXCont(pps=pps)), ports=[0])
    c.clear_stats()
    c.start(ports=[0], mult="1", duration=dur, force=True)
    c.wait_on_traffic(ports=[0])
    st = c.get_stats()
    tx = st[0]["opackets"]
    rx = st[0]["ipackets"]       # round-trip: reflected traffic back on port 0
    lost = tx - rx
    ok = rx >= tx
    print(f"  {pps//1000}kpps: tx={tx} rx={rx} lost={lost} -> "
          f"{'PASS' if ok else 'FAIL'}", flush=True)
    return ok


def main():
    c = STLClient()
    c.connect()
    try:
        c.acquire(ports=[0], force=True)
        onwire = len(build(FRAME))
        print(f"on-wire frame (excl FCS) = {onwire} B (+4 FCS = {onwire + 4}); "
              f"target {FRAME}", flush=True)

        # warm-up (avoids the cold-start binary-search artifact)
        trial(c, LO, 10)

        if LO == HI:
            ndr = LO if trial(c, LO, DUR) else 0
        else:
            lo, hi, ndr = LO, HI, 0
            while hi - lo > 10000:
                mid = (lo + hi) // 2
                if trial(c, mid, DUR):
                    ndr, lo = mid, mid
                else:
                    hi = mid
        # result line parsed by report_junitxml / gather_perf_info (field $4):
        print(f"EVPN_NDR tx_pps rx_pps {ndr},", flush=True)
    finally:
        try:
            c.stop(ports=[0])
        except STLError:
            pass
        c.release(ports=[0])
        c.disconnect()


if __name__ == "__main__":
    main()
