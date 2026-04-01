# Harpoon Stateful Pentest Report

**Target:** cybee.ai
**Date:** 2026-04-01 02:30

---

## Executive Summary

Assessment executed through a stateful 10-phase black-box pipeline with adaptive WAF policy and deterministic PoC generation.

**Overall Risk Rating:** LOW

## Toolchain Procedure (1 -> 10)

1. Passive recon (subfinder, crt.sh, amass)
2. Active DNS + infra filtering (dnsx + conditional nmap)
3. HTTP probing + WAF detection (httpx + behavioral probe)
4. Visual recon (gowitness)
5. Directory/vhost fuzzing (ffuf primary, gobuster targeted)
6. Advanced crawling + historical mining (katana + archives)
7. JS analysis (endpoint + entropy secret detection)
8. Parameter discovery (paramspider/arjun/ffuf params)
9. Validation (nuclei, sqlmap, nikto conditional)
10. Manual exploitation handoff + PoC statements

---

## Findings Snapshot

- Nmap open services: 5
- ffuf dir findings: 1828
- ffuf vhost findings: 0
- ffuf params findings: 24
- Nuclei findings: 0
- Generated PoCs: 0

## Actionable Proof of Exploitation

*No deterministic PoCs generated from current validation outputs.*
