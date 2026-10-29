# evpn_return_path

Sets up the EVPN Type-5 **return path** (VM &rarr; remote VTEP) so the TRex
closed-loop NDR test (`evpn_binary_search`) can measure both directions of the
`nfv-ovs-dpdk-sriov-fdp-evpn` scenario.

The forward direction (remote &rarr; VM) works out of the box once the compute
has the EVPN VNI wired. The return direction needs two pieces:

| Piece | Where it runs | What it does |
|---|---|---|
| gobgp Type-5 inject (`evpn_return_path_gobgp`, `true`) | TRex VM | Brings up the inject VF, starts `gobgpd`, waits for the BGP session to the RR, then injects the Type-5 route with the next-hop **overridden to the TRex DPDK PF** so the compute installs a VRF route back to the generator. **This role only does this piece.** |
| `Static_MAC_Binding` + tenant port-security | controller-0 (tofu) | Pins the remote VTEP MAC on the EVPN LRP and disables port-security on the tenant port. **Not done here** &mdash; see below. |

## Why the compute / NB side is not here

The OVN **Northbound DB is centralized in OCP**, not on the compute (verified:
the compute has no `ovnnb_db.sock`; it only runs `ovn_controller` + `ovn_agent`,
which talk to the central SB). So the `Static_MAC_Binding` (an NB write) and the
tenant port-security **cannot** be set from this ansible-nfv run &mdash; the
test-operator pod has no OCP/NB access. They live in tofu instead
(`performance/main.tf`), which runs on controller-0 where `oc` and the overcloud
client are available:

* tenant port `port_security_enabled = false` &rarr; port resource attribute.
* `Static_MAC_Binding` (remote VTEP MAC pin) &rarr; a `null_resource` whose
  `local-exec` runs `oc rsh -n openstack ovsdbserver-nb-0 ovn-nbctl create
  Static_MAC_Binding` on apply and removes it on destroy.

This role therefore needs no OCP access and only touches the SSH-reachable
TRex VM.

## Where it plugs in

Included from `playbooks/packet_gen/trex/performance_scenario.yml` in the TRex
play, guarded by `dut_type == 'evpn'`, **after** `launch_trex` and **before**
`evpn_binary_search`. See that playbook for the exact wiring.

## Key variables

All encap / underlay constants (`evpn_trex_pf_ip`, `evpn_trex_vf_ip`,
`evpn_trex_pf_mac`, `evpn_vni`, `evpn_rt`, `evpn_rd`, `evpn_remote_subnet`,
`evpn_rr_ip`, &hellip;) live in `defaults/main.yml` and **must match** the TRex
profile (`ndr_evpn_vxlan.py`), the injected route, and the deployed OVN EVPN
config. Override per-environment from the scenario `var_files`.

`evpn_inject_ifname` is empty by default: the role auto-detects the kernel VF
netdev (the one already carrying `evpn_trex_vf_ip`, else the lone kernel netdev
with no IPv4). Set it explicitly if auto-detection is ambiguous.
