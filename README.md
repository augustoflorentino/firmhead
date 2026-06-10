# firmhead

Reads the container headers that wrap router and embedded firmware, from an in-memory buffer:
uImage (legacy, including multi-file), TRX v1/v2, OpenWrt fwtool trailers, TP-Link v1 and safeloader,
Xiaomi HDR1, MikroTik NPK, Netgear CHK, Reolink PAK, D-Link SEAMA, Ubiquiti, Android boot images
(header v0 to v4), U-Boot FIT and plain device trees.

For each image it reports the parts (offset, size, role, compression), the metadata, every
checksum with its state (`ok`, `bad`, or `unverifiable` when the format gives no way to check),
signatures and verification keys (with where the signature bytes sit and, when the format signs a
contiguous range, which bytes it covers, so the caller can verify with its own crypto), and, through `fwh_audit`, the known FIT signing mistakes:
weak algorithms or keys, images signed without the configuration, signed configurations that
load unsigned images, keys that are present but not required, and ambiguous node names.

It never decompresses, never reads files and never trusts a size field: every offset it returns
lies inside the buffer it was given.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/map-dark.svg">
    <img src="docs/map-light.svg" alt="Three vendor firmware files mapped by firmhead: a TP-Link safeloader with three uImages inside, a Reolink PAK with a device tree and a kernel, a Xiaomi HDR1 with its kernel and an RSA signature over the whole file" width="1000">
  </picture>
</p>

## Build and install

```sh
cmake -S . -B build -DBUILD_SHARED_LIBS=ON
cmake --build build
cmake --install build --prefix /usr/local
```

Use it from CMake:

```cmake
find_package(firmhead REQUIRED)
target_link_libraries(app PRIVATE firmhead::firmhead)
```

Or with pkg-config:

```sh
cc app.c $(pkg-config --cflags --libs firmhead)
```

## Single-file form

`scripts/amalgamate.sh` writes `dist/firmhead/firmhead.h`. Copy it into your project and, in exactly
one `.c` file:

```c
#define FWH_IMPLEMENTATION
#include "firmhead/firmhead.h"
```

Define `FWH_STATIC` as well to keep every function private to that file.

## Usage

See [`examples/firmhead-info.c`](examples/firmhead-info.c), a small tool that scans a file and prints
every header it finds (`-j` prints one JSON object per file instead). The header
`include/firmhead/firmhead.h` is the API reference.

Conventions:

- every function that can fail returns `FWH_OK` or an error code; `fwh_strerror` describes it
- what `fwh_open` returns is released only by `fwh_image_destroy`, which accepts `NULL`
- functions never take ownership of their arguments; returned pointers belong to the library
- pass a `fwh_allocator_t` to `fwh_open`, or `NULL` for `malloc`/`free`
- the image borrows the buffer: keep it alive and unchanged until `fwh_image_destroy`

## Versioning

Semantic Versioning. Compatible releases bump the minor version; incompatible ones bump the
major version and the soname. `FWH_VERSION_STRING` gives the version compiled against and
`fwh_version()` the one linked at run time. See [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).
