# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.4.0 - 2026-05-21

### Added

- `fwh_signature_t` now says where the signature bytes are (`value_offset`, `value_size`) for
  fwtool, TP-Link safeloader, Xiaomi HDR1 and MikroTik NPK, and which contiguous range a usign
  signature covers (`signed_offset`, `signed_size`), so the caller can hand both to `usign` or
  its own verifier.
- usign signatures report the key fingerprint in `key_hint` (`usign key 0123456789abcdef`).
- `firmhead-info` prints the signature value, the signed range and the key.

### Fixed

- OpenWrt image metadata came out empty on real sysupgrade images: the JSON follows alignment
  padding of NUL bytes, which are now skipped.

### Upgrading

- `fwh_signature_t` grew four fields. Code that only reads the struct through
  `fwh_signature_get` needs a rebuild and no change.

## 0.1.0 - 2026-05-21

First release.

- Header parsing for uImage (single and multi), TRX v1/v2, OpenWrt fwtool trailer, TP-Link safeloader, Xiaomi HDR1, MikroTik NPK, Netgear CHK, Reolink PAK, FIT and DTB.
- Checksum verification with three states: ok, bad and unverifiable.
- FIT signing audit: weak algorithms, image-only signatures, partial configurations, optional keys and ambiguous node names.
- CRC32, MD5, SHA-1 and SHA-2 built in; no dependencies beyond the C library.
- Checked against 32 official images, U-Boot dumpimage and mkimage-signed FITs.
