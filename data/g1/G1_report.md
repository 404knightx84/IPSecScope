# Gate G1 report (2026-10-03)

Setup: Kali VM (VirtualBox), Docker Compose, strongSwan 5.9.13, two gateway containers on
10.0.0.0/24 (WAN). Offloads (gro, gso, tso, lro) disabled on container, bridge and veth
interfaces. Captures with tcpdump -s 0 on the WAN bridge, 0 packets dropped.
L = IP total length - outer IP header length (20 IPv4, 40 IPv6), minus 8 if UDP-encapsulated.

| Flow | Packets | Distinct L | Rule | Result |
|---|---|---|---|---|
| CBC+SHA256, IPv4, transport | 48 | 7 | (L-40) mod 16 = 0 | pass |
| CBC+SHA256, IPv4, tunnel | 48 | 8 | (L-40) mod 16 = 0 | pass |
| GCM-256, IPv4, transport | 48 | 8 | L mod 4 = 0 | pass |
| GCM-256, IPv4, tunnel | 48 | 8 | L mod 4 = 0 | pass |
| CBC+SHA256, IPv6, tunnel | 48 | 8 | (L-40) mod 16 = 0 | pass |

Mode twin pairs (same ping sizes, same endpoints):
- GCM: tunnel is exactly 20 bytes larger than transport for all 8 sizes.
- CBC: tunnel is 16 or 32 bytes larger than transport (block padding).

Findings:
- ESP was raw (IP protocol 50) in all captures, no UDP 4500 encapsulation, so the minus-8 case
  was not exercised here.
- IKE_AUTH moved to UDP 4500 (MOBIKE), so the parser still needs the non-ESP marker rule.
- Several GCM lengths also satisfy the CBC rule, so cipher family must require all pooled
  lengths to fit and report low confidence when few distinct lengths are seen.
- Child vs IKE rekey separation by SPI is not tested yet (done in S4).

Decision table outcome: CBC and GCM residues hold on IPv4 and IPv6, mode twin pair shows a
separable shift. Continue as planned.
