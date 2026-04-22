import hashlib
import struct
import sys
import zlib
from pathlib import Path

from tests.corpus.scenarios import kernel_payload
from tests.corpus.writers.fit import (
    configuration,
    fit_with,
    image_node,
    signature_node,
    signed_image,
)
from tests.corpus.writers.uimage import uimage

SALT = bytes.fromhex("7a2b15ed9b98596de504ab44ac2a9f4e")

def fwtool(body: bytes, kind: int, data: bytes) -> bytes:
    size = len(data) + 16
    return body + data + b"FWx0" + struct.pack(">I", 1) + bytes([kind, 0, 0, 0]) + struct.pack(">I", size)

def sysupgrade() -> bytes:
    image = uimage(kernel_payload(), "OpenWrt kernel", compression="lzma")
    meta = b'{"metadata_version":"1.1","supported_devices":["corpus,board"]}'
    signed = fwtool(image, 1, meta)
    return fwtool(signed, 0, b"untrusted comment: signed by key 0123\n" + b"R" * 96 + b"\n")

def placeholder() -> bytes:
    return fwtool(uimage(kernel_payload(), "OpenWrt kernel"), 0, b"# fake certificate\n")

def multi() -> bytes:
    parts = [kernel_payload(), b"\x11" * 61, b"\x22" * 300]
    table = b"".join(struct.pack(">I", len(p)) for p in parts) + b"\0\0\0\0"
    body = table
    for p in parts:
        body += p + b"\0" * (-len(p) % 4)
    return uimage(body, "multi", image_type="multi")

def trx_v2() -> bytes:
    parts = [b"\x33" * 1000, b"\x44" * 2000, b"\x55" * 512]
    header = 16 + 16
    offsets, body = [], b""
    for p in parts:
        offsets.append(header + len(body))
        body += p
    offsets.append(0)
    rest = struct.pack("<HH4I", 0, 2, *offsets) + body
    length = 12 + len(rest)
    crc = zlib.crc32(rest) ^ 0xFFFFFFFF
    return b"HDR0" + struct.pack("<II", length, crc) + rest

def external_fit() -> bytes:
    kernel = kernel_payload()
    fdt_blob = b"\xd0" * 96
    images = []
    offset = 0
    for name, data, kind in (("kernel-1", kernel, "kernel"), ("fdt-1", fdt_blob, "flat_dt")):
        node = image_node(name, data, kind)
        del node.properties["data"]
        node.properties["data-size"] = struct.pack(">I", len(data))
        node.properties["data-offset"] = struct.pack(">I", offset)
        images.append(node)
        offset += len(data) + (-len(data) % 4)
    signature = signature_node("sha256,rsa2048", sign_images=("kernel", "fdt"))
    tree = fit_with(images, [configuration("conf-1", {"kernel": "kernel-1", "fdt": "fdt-1"}, signature)])
    tree += b"\0" * (-len(tree) % 4)
    return tree + kernel + b"\0" * (-len(kernel) % 4) + fdt_blob

def ambiguous_fit() -> bytes:
    images = [signed_image("kernel@1", kernel_payload()), image_node("fdt-1", b"\xd0" * 96, "flat_dt")]
    configs = [
        configuration("conf-1", {"kernel": "kernel@1", "fdt": "fdt-1"}),
        configuration("conf-1", {"kernel": "kernel@1"}),
    ]
    return fit_with(images, configs)

def salted_safeloader() -> bytes:
    from tests.corpus.writers.vendor import safeloader

    image = bytearray(safeloader({"os-image": b"\x66" * 700, "file-system": b"\x77" * 900}))
    size = struct.unpack(">I", image[:4])[0]
    image[4:20] = hashlib.md5(SALT + bytes(image[0x14:size])).digest()
    return bytes(image)

SAMPLES = {
    "fwtool_signed.bin": sysupgrade,
    "fwtool_placeholder.bin": placeholder,
    "uimage_multi.bin": multi,
    "trx_v2.bin": trx_v2,
    "fit_external.bin": external_fit,
    "fit_ambiguous.bin": ambiguous_fit,
    "safeloader_salted.bin": salted_safeloader,
}

def main() -> None:
    out = Path(sys.argv[1])
    for name, make in SAMPLES.items():
        (out / name).write_bytes(make())

if __name__ == "__main__":
    main()
