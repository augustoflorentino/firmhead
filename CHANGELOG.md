# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.1.0 - 2026-05-21

First release.

- Header parsing for uImage (single and multi), TRX v1/v2, OpenWrt fwtool trailer, TP-Link safeloader, Xiaomi HDR1, MikroTik NPK, Netgear CHK, Reolink PAK, FIT and DTB.
- Checksum verification with three states: ok, bad and unverifiable.
- FIT signing audit: weak algorithms, image-only signatures, partial configurations, optional keys and ambiguous node names.
- CRC32, MD5, SHA-1 and SHA-2 built in; no dependencies beyond the C library.
- Checked against 32 official images, U-Boot dumpimage and mkimage-signed FITs.
