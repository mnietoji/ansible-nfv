"""
TRex STL profile: EVPN Type-5 dataplane (VXLAN VNI 1001) with iMIX.

Why a custom profile: bench-trafficgen / trex-txrx cannot craft VXLAN, and the
EVPN Type-5 path requires the underlay side to be VXLAN-encapsulated so that the
OVN compute (DUT) performs VXLAN decap + L3 route (+ re-encap on the return).

TRex here emulates the *remote VTEP* on vlan178:
  outer:  IP(12.12.12.20 -> 12.12.12.3) / UDP(dport=4789)     # ovn-evpn-vxlan-ports
  vxlan:  VNI 1001
  inner:  Ether(dst = OVN router-MAC) / IP(remote_subnet -> tenant_subnet)

The inner dst-MAC MUST be the OVN tenant router-MAC or the packet is bridged,
not routed, and EVPN is never exercised.

iMIX = 64 / 590 / 1518 B frames at the RFC packet-count ratio 7:4:1 (expressed
as per-stream relative pps weights; set the absolute rate with `start -m ...`).

Usage (on the TRex VM):
  trex> start -f profiles/trex_evpn_type5_imix.py -p 0 -m 10gbps
  # tunables:
  trex> start -f profiles/trex_evpn_type5_imix.py -t direction=tx,vni=1001

For scenario 3 bidirectional, run this on port 0 (underlay/VXLAN) and a plain
L3 profile on port 1 (tenant arm) with the tenant gateway MAC.
"""

from trex.stl.api import *
from scapy.contrib.vxlan import VXLAN


# ---- defaults (override via -t k=v,k=v) ----
DEFAULTS = dict(
    direction="tx",                 # tx = TRex-as-remote-VTEP (VXLAN encap)
    vni=1001,
    vxlan_dport=4789,               # == ovn-evpn-vxlan-ports (NOT 60010)
    outer_src="12.12.12.20",        # TRex underlay / remote VTEP IP
    outer_dst="12.12.12.3",         # compute-1 EVPN VTEP IP
    inner_router_mac="fa:16:3e:97:ca:bb",   # OVN tenant router-MAC (verify!)
    inner_src="192.168.99.10",      # remote subnet host (emulated)
    inner_dst="192.168.77.221",     # tenant workload VM on compute-1
    inner_dport=7777,               # inner L4 dst port. MUST NOT be 53: OVN's
                                    # ls_in_dns_lookup punts every udp/53 packet
                                    # to ovn-controller (per-packet userspace
                                    # punt), which silently caps the forward
                                    # rate at ~30kpps. Any non-special port is
                                    # fine; avoid 53/67/68/546/547.
    flows=1000,                     # spread inner src IPs to create N flows
)

# iMIX: frame size (outer, on-wire) -> relative pps weight
IMIX = [(64, 7), (590, 4), (1518, 1)]


def _int(v):
    return int(v)


class STLS1(object):

    def _stream(self, kw, size, weight):
        vni = _int(kw["vni"])
        dport = _int(kw["vxlan_dport"])
        inner_dport = _int(kw["inner_dport"])
        flows = _int(kw["flows"])

        base = (
            Ether() /
            IP(src=kw["outer_src"], dst=kw["outer_dst"]) /
            UDP(sport=(1 << 15), dport=dport) /
            VXLAN(vni=vni, flags=0x08) /
            Ether(dst=kw["inner_router_mac"]) /
            IP(src=kw["inner_src"], dst=kw["inner_dst"]) /
            UDP(sport=1025, dport=inner_dport)   # NOT 53 (OVN DNS-lookup punt)
        )
        pad = max(0, size - len(base) - 4)   # -4: FCS not counted by scapy
        pkt_bytes = base / (b"\x00" * pad)

        # spread inner source IP over `flows` addresses (RSS / multiqueue)
        vm = STLScVmRaw([
            STLVmFlowVar(name="isrc", min_value=0, max_value=flows - 1,
                         size=4, op="inc"),
            STLVmWrFlowVar(fv_name="isrc", pkt_offset="inner_IP.src"),
            STLVmFixChecksumHw(l3_offset="inner_IP", l4_offset="inner_UDP",
                               l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP),
        ])

        return STLStream(
            packet=STLPktBuilder(pkt=pkt_bytes, vm=vm),
            mode=STLTXCont(pps=weight),
        )

    def get_streams(self, tunables, **kw):
        p = dict(DEFAULTS)
        p.update(tunables or {})
        return [self._stream(p, size, weight) for size, weight in IMIX]


def register():
    return STLS1()
