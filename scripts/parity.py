import re
import subprocess
import sys
from pathlib import Path

from fwtriage.formats import REGISTRY
from fwtriage.model import Limits
from fwtriage.model.budget import Budget

NAMES = {
    "uimage": "uimage",
    "trx": "trx",
    "fwtool": "fwtool",
    "safeloader": "tplink",
    "hdr1": "xiaomi",
    "npk": "npk",
    "chk": "chk",
    "pak": "pak",
    "fit": "fit",
    "dtb": "dtb",
}
SKIP_ROLES = {"signature", "metadata"}
HEAD = re.compile(r"^(\w+)@0x([0-9a-f]+) size (\d+):")
PART = re.compile(r"^  part  (\S+)\s+0x([0-9a-f]+)\s+(\d+) (\w+)")
CHECK = re.compile(r"^  check \S+\s+.*?\s(ok|bad|unverifiable)\s")
SIG = re.compile(r"^  sig   (\S+) (\S+)")

def c_side(info: str, path: Path) -> list[dict]:
    images, current = [], None
    for line in subprocess.run([info, str(path)], capture_output=True, text=True, check=True).stdout.splitlines():
        if m := HEAD.match(line):
            current = {"format": m[1], "offset": int(m[2], 16), "size": int(m[3]), "parts": [], "checks": [], "sigs": []}
            images.append(current)
        elif current and (m := PART.match(line)):
            if m[4] not in SKIP_ROLES:
                current["parts"].append((m[1], int(m[2], 16), int(m[3])))
        elif current and (m := CHECK.match(line)):
            current["checks"].append(m[1])
        elif current and (m := SIG.match(line)):
            current["sigs"].append(m[1])
    return images

def python_format(name: str):
    wanted = NAMES[name]
    for fmt in REGISTRY:
        if fmt.name == wanted:
            return fmt
    raise SystemExit(f"no fwtriage format {wanted}")

def py_side(view: memoryview, image: dict, trailer: bool = False) -> dict | None:
    fmt = python_format(image["format"])
    region = fmt.probe(view, image["offset"] + image["size"] - 16 if trailer else image["offset"])
    if region is None:
        return None
    unpacked = fmt.unpack(view, region, Budget(Limits()))
    base = image["offset"]
    parts = [(s.name, base + s.offset if s.offset < base else s.offset, len(s.data)) for s in unpacked.streams]
    signing = unpacked.signing
    return {
        "offset": region.offset,
        "size": region.size,
        "parts": parts,
        "checksum_ok": unpacked.checksum_ok,
        "sigs": sorted(s.node for s in signing.signatures) if signing else [],
    }

def py_regions(view: memoryview) -> set[tuple[str, int]]:
    found = set()
    for name in NAMES:
        fmt = python_format(name)
        for magic, at in fmt.magics:
            start = 0
            while (hit := bytes(view).find(magic, start)) != -1:
                start = hit + 1
                offset = hit - at
                region = fmt.probe(view, offset) if offset >= 0 else None
                if region is not None:
                    found.add((name, region.offset))
    return found

def compare(path: Path, info: str) -> list[str]:
    view = memoryview(path.read_bytes())
    problems = []
    images = c_side(info, path)
    seen = {(i["format"], i["offset"]) for i in images}
    seen |= {("dtb", offset) for name, offset in seen if name == "fit"}
    for name, offset in sorted(py_regions(view) - seen):
        problems.append(f"{path.name} {name}@0x{offset:x}: firmhead does not see it")
    for image in images:
        where = f"{path.name} {image['format']}@0x{image['offset']:x}"
        py = py_side(view, image, image["format"] == "fwtool")
        if py is None:
            problems.append(f"{where}: fwtriage does not see it")
            continue
        if (py["offset"], py["size"]) != (image["offset"], image["size"]):
            problems.append(f"{where}: region {py['offset']}+{py['size']} vs {image['offset']}+{image['size']}")
        if py["parts"] and sorted(py["parts"]) != sorted(image["parts"]):
            problems.append(f"{where}: parts {py['parts']} vs {image['parts']}")
        if py["checksum_ok"] != ("bad" not in image["checks"]):
            problems.append(f"{where}: checksum_ok {py['checksum_ok']} vs {image['checks']}")
        if py["sigs"] != sorted(image["sigs"]):
            problems.append(f"{where}: signatures {py['sigs']} vs {image['sigs']}")
    return problems

def main() -> int:
    info, files = sys.argv[1], [Path(p) for p in sys.argv[2:]]
    problems = [p for f in files for p in compare(f, info)]
    for p in problems:
        print(p)
    print(f"{len(files)} files, {len(problems)} differences")
    return 1 if problems else 0

if __name__ == "__main__":
    sys.exit(main())
