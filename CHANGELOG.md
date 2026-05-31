# Changelog

Each release lists what changed, what updating means for existing code, and every security fix.

## Unreleased

## 1.2.0 - 2026-05-31

### Added

- TP-Link v1 factory images (`FWH_FMT_TPLINK`): vendor, version, hardware id, load and entry
  addresses as metadata, kernel, rootfs and bootloader as parts, and the salted MD5 over the
  whole image, with both the firmware and the bootloader salt. Tested on the OpenWrt factory
  images for the Archer C5 v1, Archer C7 v2 and TL-WDR4300 v1.
- `FWH_FMT_COUNT` is now 14; existing format numbers are unchanged.

### Fixed

- The internal multi-buffer digest used by the Android boot id produced big-endian MD5 output;
  it now matches `fwh_digest`. No released parser used MD5 through it.

## 1.0.0 - 2026-05-24

The API is now stable: it changes incompatibly only with a new major version and soname.

### Changed

- `fwh_open` takes the allocator as one `const fwh_allocator_t *` (`alloc`, `free`, `ctx`)
  instead of three separate arguments. `NULL` still means `malloc` and `free`.
- The shared library is now `libfirmhead.so.1`.

### Added

- `FWH_VERSION_MAJOR`, `FWH_VERSION_MINOR`, `FWH_VERSION_PATCH`, `FWH_VERSION_STRING` and
  `fwh_version()`. The CMake project version is read from the header.

### Upgrading

- Replace `fwh_open(buf, len, offset, format, NULL, NULL, NULL, &image, &at)` with
  `fwh_open(buf, len, offset, format, NULL, &image, &at)`.
- With a custom allocator, fill a `fwh_allocator_t` and pass its address:

  ```c
  fwh_allocator_t allocator = {my_alloc, my_free, my_ctx};
  fwh_open(buf, len, offset, format, &allocator, &image, &at);
  ```

- Relink against `libfirmhead.so.1`; binaries built against 0.x will not load it.

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
