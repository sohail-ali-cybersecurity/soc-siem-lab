# Incident Report — NetSupport Manager RAT C2 Activity

**Analyst:** Sohail Ali
**Date of analysis:** 2026-02-28
**Source:** SIEM alert → packet capture (PCAP) analysis via Wireshark

---

## Summary

The SIEM flagged repeated signature hits for **NetSupport Manager RAT** (a known Remote Access Trojan commonly abused as a Command & Control tool) communicating with external IP `45.131.214.85` over TCP port 443. Packet capture analysis confirmed active C2 beaconing from an internal host and identified the affected machine and user.

## Timeline

- **19:55 UTC** — First signature hit recorded by SIEM for traffic to `45.131.214.85`.
- **19:55:51** — First outbound POST request observed in PCAP from internal host to C2 server.
- **Ongoing** — Beacon traffic repeats at a consistent ~60-second interval following the initial burst, indicating an active, periodic check-in pattern typical of C2 malware.

## Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| C2 server IP | `45.131.214.85` |
| C2 port | `443` (TCP — traffic was unencrypted HTTP, not real TLS) |
| C2 endpoint | `/fakeurl.htm` |
| Beacon interval | ~60 seconds |
| Request method | HTTP POST (`application/x-www-form-urlencoded`) |

**Why this traffic was flagged as malicious rather than normal HTTPS:**
- Port 443 traffic was observed as **plaintext HTTP**, not encrypted TLS — a common technique malware uses to blend in with normal "secure" traffic at a glance.
- The endpoint name `/fakeurl.htm` is not consistent with any legitimate service.
- The strict ~60-second beacon interval is characteristic of automated C2 check-in behavior, not human browsing.

## Affected Host

| Field | Value | Source |
|---|---|---|
| IP address | `10.2.28.88` | TCP handshake source in C2 traffic |
| MAC address | `00:19:d1:b2:4d:ad` | Ethernet header (DHCP ACK / NBNS packets) |
| Hostname | `DESKTOP-TEYQ2NR` | NBNS (NetBIOS Name Service) registration broadcast |
| Windows username | `brolf` | Kerberos AS-REQ (CNameString field) |
| Full name | `Becka Rolf` | SMB/SAMR QueryUserInfo response |

## Methodology

1. Filtered the PCAP on `ip.addr == 45.131.214.85` to isolate all traffic to/from the known-malicious IP, confirming the internal source (`10.2.28.88`) and the beacon pattern.
2. Filtered on `ip.addr == 10.2.28.88 && nbns` to recover the Windows hostname from a NetBIOS name registration broadcast.
3. Filtered on `ip.addr == 10.2.28.88 && kerberos.msg_type == 10` (AS-REQ) to recover the plaintext Windows username from the Kerberos authentication request.
4. Cross-referenced the username against SMB/SAMR traffic to recover the account's full display name.
5. Verified all findings against the exercise's published answer key — 100% match on IP, MAC, hostname, and username.

## Recommended Remediation

1. Isolate host `DESKTOP-TEYQ2NR` (`10.2.28.88`) from the network immediately.
2. Block outbound traffic to `45.131.214.85` at the firewall/proxy.
3. Initiate malware removal / re-image the affected endpoint.
4. Reset credentials for user `brolf` (Becka Rolf) and review recent account activity for signs of lateral movement.
5. Review other hosts on the `10.2.28.0/24` segment for the same IOC (`45.131.214.85`) to rule out further compromise.

---
*Analysis performed as part of a self-directed SOC training lab using a publicly available training PCAP from malware-traffic-analysis.net.*
