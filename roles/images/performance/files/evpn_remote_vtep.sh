#!/usr/bin/env bash
#
# evpn_remote_vtep.sh   --  run INSIDE the OpenStack VM "evpn-remote"
# -----------------------------------------------------------------------------
# Turns an ordinary OpenStack instance (booted on a *provider VLAN* network that
# sits on vlan178) into a standalone software EVPN Type-5 VTEP, so it can act as
# an external "remote site" and exercise the EVPN *dataplane* against the OVN
# VTEP on compute-1.
#
# Why a provider-VLAN VM works as an external VTEP:
#   - a provider VLAN net is just L2-bridged to the physnet; OVN does NOT route
#     for it, so this VM is OUTSIDE OVN's logical L3 topology.
#   - OVN delivers the provider-vlan frames UNTAGGED to the guest NIC, so the
#     guest just sees 12.12.12.x directly (no .178 subinterface needed here,
#     unlike a host-based VTEP on the compute underlay).
#
# Topology built here:
#
#   ToR route-reflector (RR 12.12.12.2, AS 64999)
#      |  BGP l2vpn-evpn (control)  +  VXLAN VNI 1001 (data)  -- all on vlan178
#      +-- compute-1  12.12.12.3   OVN tenant subnet 192.168.77.0/24  (Type-5 by OVN)
#      +-- evpn-remote 12.12.12.20 remote subnet   192.168.99.0/24    (THIS VM)
#
# A ping / iperf3 between netns(192.168.99.10) and OVN-VM(192.168.77.x) proves
# traffic crossed VXLAN VNI 1001 between the two VTEPs = real Type-5 dataplane.
#
# Modes:  setup | status | verify [target_ip] | perf-server | perf [target_ip] | frr | cleanup
# -----------------------------------------------------------------------------
set -euo pipefail

### ---- config (edit if the scenario differs) ----
UNDERLAY_IF="${UNDERLAY_IF:-}"   # provider-vlan NIC; auto-detected if empty
VTEP_IP="${VTEP_IP:-}"           # our VTEP/BGP source; auto-detected from UNDERLAY_IF if empty
RR=12.12.12.2                    # ToR route-reflector
ASN=64999
VNI=1001
RT="64999:1001"                  # matches OVN/compute-1 (AS:VNI)
VRF=vrf-evpn
TABLE=1001
DPORT=4789                       # EVPN VXLAN UDP port (OVN ovn-evpn-vxlan-ports default)
BR=br1001                        # L3VNI transit bridge (SVI, in VRF, no IP)
VXDEV=vxlan1001
TENANT_SUBNET=192.168.99.0/24    # our "remote site" subnet, advertised as Type-5
GW_IP=192.168.99.1               # gateway, lives in the VRF (host side of veth)
NS_IP=192.168.99.10              # test endpoint inside the netns
NS_PLEN=24
NS_MTU="${NS_MTU:-1400}"         # < underlay MTU - VXLAN(50) ; 1400 is safe for 1500
NETNS=evpn-test
VETH_H=veth-evpn                 # host side of the veth (in VRF)
VETH_NS=eth0                     # netns side
FRR_CONF=/etc/frr/frr.conf

### ---- helpers ----
c_blue=$'\e[1;34m'; c_grn=$'\e[1;32m'; c_yel=$'\e[1;33m'; c_red=$'\e[1;31m'; c_off=$'\e[0m'
log()  { echo "${c_blue}[*]${c_off} $*"; }
ok()   { echo "${c_grn}[ok]${c_off} $*"; }
warn() { echo "${c_yel}[!]${c_off} $*"; }
err()  { echo "${c_red}[x]${c_off} $*" >&2; }
require_root(){ [ "$(id -u)" -eq 0 ] || { err "run as root (sudo)"; exit 1; }; }

detect_underlay(){
    if [ -z "$UNDERLAY_IF" ]; then
        # the NIC that carries a 12.12.12.0/24 address
        UNDERLAY_IF=$(ip -o -4 addr show | awk '/12\.12\.12\./{print $2; exit}')
    fi
    [ -n "$UNDERLAY_IF" ] || { err "could not find the provider-vlan NIC (no 12.12.12.x addr). Set UNDERLAY_IF="; exit 1; }
    if [ -z "$VTEP_IP" ]; then
        VTEP_IP=$(ip -o -4 addr show dev "$UNDERLAY_IF" | awk '{print $4}' | cut -d/ -f1 | head -1)
    fi
    [ -n "$VTEP_IP" ] || { err "no IPv4 on $UNDERLAY_IF"; exit 1; }
    log "underlay NIC=$UNDERLAY_IF  VTEP_IP=$VTEP_IP"
}

### ---- setup ----
setup(){
    require_root
    detect_underlay

    if ping -c1 -W2 "$RR" &>/dev/null; then
        ok "RR $RR reachable on the underlay"
    else
        warn "RR $RR not reachable (check the provider net is really on vlan178 and the ToR trunk allows it)"
    fi

    # 1) VRF
    ip link show "$VRF" &>/dev/null || ip link add "$VRF" type vrf table "$TABLE"
    ip link set "$VRF" up

    # 2) L3VNI transit bridge = SVI, enslaved to the VRF, no IP
    ip link show "$BR" &>/dev/null || ip link add "$BR" type bridge
    ip link set "$BR" master "$VRF"
    ip link set "$BR" up

    # 3) L3VNI VXLAN device (same VNI/local/dstport as OVN)
    ip link show "$VXDEV" &>/dev/null || \
        ip link add "$VXDEV" type vxlan id "$VNI" local "$VTEP_IP" dstport "$DPORT" nolearning
    ip link set "$VXDEV" master "$BR"
    bridge link set dev "$VXDEV" neigh_suppress on learning off 2>/dev/null || true
    ip link set "$VXDEV" up
    log "L3VNI $VNI: $VXDEV (local $VTEP_IP dstport $DPORT) -> $BR -> $VRF"

    # 4) test endpoint: netns + veth, gateway lives in the VRF (this /24 -> Type-5)
    ip netns list | grep -qw "$NETNS" || ip netns add "$NETNS"
    ip link show "$VETH_H" &>/dev/null || \
        ip link add "$VETH_H" type veth peer name "$VETH_NS" netns "$NETNS"
    ip link set "$VETH_H" master "$VRF"
    ip addr replace "${GW_IP}/${NS_PLEN}" dev "$VETH_H"
    ip link set "$VETH_H" mtu "$NS_MTU" up
    ip -n "$NETNS" addr replace "${NS_IP}/${NS_PLEN}" dev "$VETH_NS"
    ip -n "$NETNS" link set "$VETH_NS" mtu "$NS_MTU" up
    ip -n "$NETNS" link set lo up
    ip -n "$NETNS" route replace default via "$GW_IP"
    log "netns $NETNS: ${NS_IP}/${NS_PLEN} gw ${GW_IP} mtu ${NS_MTU}  (subnet ${TENANT_SUBNET})"

    # 5) forwarding / rp_filter
    sysctl -qw net.ipv4.ip_forward=1
    sysctl -qw net.ipv4.conf.all.rp_filter=0

    # 6) FRR
    ensure_frr && apply_frr

    ok "setup complete"
    cat <<EOF

${c_yel}NEXT STEPS${c_off}
  1) Locate the OVN VM IP on 192.168.77.0/24 and open its security group for
     ICMP + TCP 5201 (iperf3) from ${TENANT_SUBNET}.
  2) Functional:  sudo $0 verify <OVN_VM_IP>
  3) Perf (this side is client):
       - on the OVN VM:   iperf3 -s
       - here:            sudo $0 perf <OVN_VM_IP>
EOF
}

### ---- FRR ----
ensure_frr(){
    if ! command -v vtysh &>/dev/null; then
        warn "FRR not installed; trying: dnf install -y frr frr-pythontools"
        dnf install -y frr frr-pythontools || { err "FRR install failed; install it then run '$0 frr'"; return 1; }
    fi
    sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons 2>/dev/null || true
    systemctl enable frr &>/dev/null || true
}

apply_frr(){
    detect_underlay
    [ -f "$FRR_CONF" ] && cp -a "$FRR_CONF" "${FRR_CONF}.bak.$(date +%s)" && warn "backed up existing $FRR_CONF"
    cat > "$FRR_CONF" <<EOF
frr defaults traditional
hostname evpn-remote-vtep
log syslog informational
service integrated-vtysh-config
!
vrf ${VRF}
 vni ${VNI}
exit-vrf
!
router bgp ${ASN}
 bgp router-id ${VTEP_IP}
 no bgp default ipv4-unicast
 neighbor ${RR} remote-as ${ASN}
 neighbor ${RR} update-source ${VTEP_IP}
 !
 address-family l2vpn evpn
  neighbor ${RR} activate
  advertise-all-vni
 exit-address-family
!
router bgp ${ASN} vrf ${VRF}
 bgp router-id ${VTEP_IP}
 !
 address-family ipv4 unicast
  redistribute connected
 exit-address-family
 !
 address-family l2vpn evpn
  advertise ipv4 unicast
  route-target import ${RT}
  route-target export ${RT}
 exit-address-family
!
EOF
    systemctl restart frr
    ok "FRR up (peer ${RR} AS ${ASN}, L3VNI ${VNI}, RT ${RT}, originating ${TENANT_SUBNET})"
}

### ---- status ----
status(){
    detect_underlay || true
    echo "== links =="
    ip -br addr show "$UNDERLAY_IF" 2>/dev/null || true
    ip -br link show "$VRF" 2>/dev/null || true
    ip -br link show "$BR" 2>/dev/null || true
    ip -br link show "$VXDEV" 2>/dev/null || true
    ip -br link show "$VETH_H" 2>/dev/null || true
    echo "== vxlan detail =="
    ip -d link show "$VXDEV" 2>/dev/null | sed -n '2p' || true
    echo "== VRF routes (table $TABLE) =="
    ip route show vrf "$VRF" 2>/dev/null || true
    echo "== netns $NETNS =="
    ip -n "$NETNS" -br addr show "$VETH_NS" 2>/dev/null || true
    if command -v vtysh &>/dev/null; then
        echo "== bgp l2vpn evpn summary =="
        vtysh -c "show bgp l2vpn evpn summary" 2>/dev/null | sed -n '1,14p' || true
        echo "== evpn vni =="
        vtysh -c "show evpn vni" 2>/dev/null || true
    fi
}

### ---- verify (functional: routes + connectivity) ----
verify(){
    local target="${1:-}"
    echo "== EVPN routes we ORIGINATE (our ${TENANT_SUBNET}) =="
    vtysh -c "show bgp l2vpn evpn route type prefix" 2>/dev/null | grep -E "192.168.99|Route Distinguisher" | sed -n '1,20p' || true
    echo "== EVPN routes we RECEIVE (OVN's 192.168.77.0/24) =="
    vtysh -c "show bgp l2vpn evpn route type prefix" 2>/dev/null | grep -E "192.168.77" || warn "no OVN Type-5 received yet"
    echo "== routes installed in VRF $VRF =="
    ip route show vrf "$VRF" 2>/dev/null || true
    echo "== remote VTEPs learned =="
    vtysh -c "show evpn vni ${VNI}" 2>/dev/null | grep -iE "vtep|remote" || true
    if [ -n "$target" ]; then
        echo "== ping $target from netns $NETNS (should cross VXLAN VNI $VNI) =="
        ip netns exec "$NETNS" ping -c4 -W2 "$target" || warn "ping failed - check OVN import (Learned_Route) / RR neighbor / VM security group"
        echo "== on the wire you should see VXLAN encap: =="
        echo "   sudo tcpdump -ni ${UNDERLAY_IF} udp port ${DPORT}"
    else
        echo "(pass the OVN VM IP: $0 verify 192.168.77.x)"
    fi
}

### ---- performance ----
# perf-server: run this ON the OVN VM instead (iperf3 -s). Provided here for symmetry.
perf_server(){
    command -v iperf3 &>/dev/null || { require_root; dnf install -y iperf3; }
    ip netns exec "$NETNS" iperf3 -s
}

# perf: this VM is the client, driving traffic from the netns endpoint across VXLAN.
# Runs the standard matrix we will re-run verbatim on the non-DPDK deployment.
perf(){
    local target="${1:-}"
    [ -n "$target" ] || { err "usage: $0 perf <OVN_VM_IP>  (with 'iperf3 -s' running on the OVN VM)"; exit 1; }
    command -v iperf3 &>/dev/null || { require_root; dnf install -y iperf3; }
    local ns="ip netns exec ${NETNS}"
    local ts
    ts=$(date +%Y%m%d-%H%M%S)
    local out="/root/evpn-perf-${ts}.log"
    {
        echo "### EVPN VXLAN dataplane perf  $(date)  src=${NS_IP} dst=${target} VNI=${VNI}"
        echo "### fill in scenario tag: DPDK   (compare later vs kernel-OVS)"
        echo
        echo "== latency (ping, 20 pkts) =="
        $ns ping -c20 -i0.2 "$target" | tail -4
        echo
        echo "== TCP throughput, single stream, 30s =="
        $ns iperf3 -c "$target" -t 30
        echo
        echo "== TCP throughput, 8 parallel streams, 30s =="
        $ns iperf3 -c "$target" -t 30 -P 8
        echo
        echo "== UDP, 1500B, target 10G (line-rate / loss) =="
        $ns iperf3 -c "$target" -u -b 10G -t 30 -l 1450
        echo
        echo "== UDP, 64B (small-packet / PPS ceiling), target 5G =="
        $ns iperf3 -c "$target" -u -b 5G -t 30 -l 64
    } 2>&1 | tee "$out"
    ok "perf log saved to $out  (re-run identically on the non-DPDK deployment and diff)"
}

### ---- cleanup ----
cleanup(){
    require_root
    systemctl stop frr 2>/dev/null || true
    ip netns list | grep -qw "$NETNS" && ip netns del "$NETNS" || true
    for d in "$VETH_H" "$VXDEV" "$BR" "$VRF"; do
        ip link show "$d" &>/dev/null && ip link del "$d" && log "deleted $d" || true
    done
    ok "cleanup done (underlay NIC untouched; frr.conf backups kept as ${FRR_CONF}.bak.*)"
}

### ---- dispatch ----
case "${1:-}" in
    setup)        setup ;;
    status)       status ;;
    verify)       verify "${2:-}" ;;
    perf-server)  perf_server ;;
    perf)         perf "${2:-}" ;;
    frr)          require_root; ensure_frr && apply_frr ;;
    cleanup)      cleanup ;;
    *) echo "usage: $0 {setup|status|verify [ip]|perf-server|perf <ip>|frr|cleanup}"; exit 1 ;;
esac
