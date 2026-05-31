import base64
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
    blob = base64.b64encode(b"Ed" + bytes.fromhex("0123456789abcdef") + b"\x5a" * 64)
    return fwtool(signed, 0, b"untrusted comment: signed by key 0123456789abcdef\n" + blob + b"\n")

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

def pad(data: bytes, page: int) -> bytes:
    return data + bytes(-len(data) % page)

def android(version: int) -> bytes:
    page = 2048
    parts = [bytes(range(256)) * 12, b"ramdisk" * 150, b"second" * 70]
    if version >= 1:
        parts.append(b"\xd0\x0d\xfe\xed" + bytes(300))
    if version >= 2:
        parts.append(b"\xd0\x0d\xfe\xed" + bytes(500))
    sha = hashlib.sha1()
    for part in parts:
        sha.update(part + struct.pack("<I", len(part)))
    head = b"ANDROID!" + struct.pack("<10I", len(parts[0]), 0x10008000, len(parts[1]), 0x11000000,
                                     len(parts[2]), 0x10F00000, 0x10000100, page, version, 0)
    head += b"board".ljust(16, b"\0") + b"console=ttyS0".ljust(512, b"\0") + sha.digest().ljust(32, b"\0")
    head += bytes(1024)
    if version >= 1:
        head += struct.pack("<IQI", len(parts[3]), page + sum(len(pad(p, page)) for p in parts[:3]), 1660)
    if version >= 2:
        head += struct.pack("<IQ", len(parts[4]), 0x11F00000)
    return b"".join(pad(p, page) for p in [head] + parts)

def seama() -> bytes:
    payload = b"\x27\x05\x19\x56" + b"payload" * 200
    meta = b"dev=/dev/mtdblock/5\0type=firmware\0\0\0"
    envelope = b"signature=wrgac65_dlink.2015_dir842\0"
    image = struct.pack(">IHHI", 0x5EA3A417, 0, len(meta), len(payload)) + hashlib.md5(payload).digest() + meta
    return struct.pack(">IHHI", 0x5EA3A417, 0, len(envelope), 0) + envelope + image + payload

def tplink_v1() -> bytes:
    kernel, rootfs = b"\x5d\x00\x00\x80" + b"kernel" * 300, b"hsqs" + b"rootfs" * 400
    total = 0x200 + len(kernel) + len(rootfs) + 0x100
    head = bytearray(0x200)
    struct.pack_into(">I", head, 0, 0x01000000)
    head[4:12] = b"OpenWrt\0"
    head[0x1C:0x2D] = b"r33311-981c978eff"
    struct.pack_into(">III", head, 0x40, 0xC7000002, 1, 0)
    struct.pack_into(">IIIIIIIII", head, 0x74, 0x80060000, 0x80060000, total, 0x200, len(kernel),
                     0x200 + len(kernel), len(rootfs), 0, 0)
    salt = bytes.fromhex("dcd73aa5c39598fbddf9e7f40eae4738")
    image = bytearray(head + kernel + rootfs + b"\xff" * 0x100)
    image[0x4C:0x5C] = salt
    image[0x4C:0x5C] = hashlib.md5(image).digest()
    return bytes(image)

SAMPLES = {
    "fwtool_signed.bin": sysupgrade,
    "fwtool_placeholder.bin": placeholder,
    "uimage_multi.bin": multi,
    "trx_v2.bin": trx_v2,
    "fit_external.bin": external_fit,
    "fit_ambiguous.bin": ambiguous_fit,
    "safeloader_salted.bin": salted_safeloader,
    "android_v0.bin": lambda: android(0),
    "android_v2.bin": lambda: android(2),
    "seama.bin": seama,
    "tplink_v1.bin": tplink_v1,
}

def main() -> None:
    out = Path(sys.argv[1])
    for name, make in SAMPLES.items():
        (out / name).write_bytes(make())

if __name__ == "__main__":
    main()
