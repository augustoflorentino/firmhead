# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 0.7.0 - 2026-05-21

### Added

- Android boot images, header versions 0 to 4: kernel, ramdisk, second stage, recovery DTBO,
  DTB and the v4 boot signature as parts, the command line and board name as metadata, and the
  header id checked as SHA-1 (or SHA-256) over the parts and their sizes, the way `mkbootimg`
  writes it.
- D-Link SEAMA images and envelopes: the `key=value` metadata, the payload and its MD5. Tested on
  the OpenWrt factory images for the DIR-842 C2 and DIR-860L B1.
- `FWH_FMT_ANDROID` and `FWH_FMT_SEAMA`, their magics in `fwh_magics`, and fuzz targets for both.

### Upgrading

- `FWH_FMT_COUNT` went from 11 to 13. Arrays sized by it need a rebuild.

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
