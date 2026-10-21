# EVPN TRex profiles — manual / reference

These are hands-on TRex STL profiles for the EVPN Type-5 VXLAN work. They are
**not** run by the `evpn_binary_search` role — the automated, strict zero-loss
binary-search runner is `../files/ndr_evpn_vxlan.py`, which the role stages onto
the TRex VM and drives. Use the files here when iterating by hand on the TRex
console (`./t-rex-64 -i`, then `start -f <profile>`).

| File | Purpose |
|------|---------|
| `smoke_run.py` | Manual single-rate VXLAN Type-5 smoke test — the hand-run precursor of `ndr_evpn_vxlan.py`. The encap constants here are the source of truth both share. |
| `trex_evpn_type5_imix.py` | iMIX / tunable-direction Type-5 profile for manual uni- or bi-directional runs. |
| `diag_port.py` | Minimal per-port diagnostic profile (link / counter sanity). |
| `rx_capture.py` | RX-side capture profile for inspecting the decapped / returned frames. |

Keep the encap fields (VNI, VTEP IPs, inner/outer MACs, VXLAN dst port 4789) in
sync with `../files/ndr_evpn_vxlan.py` and the `evpn_return_path` role.
