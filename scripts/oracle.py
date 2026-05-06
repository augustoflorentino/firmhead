import re
import subprocess
import sys

TYPES = {
    "Kernel Image": "kernel",
    "Flat Device Tree": "flat_dt",
    "RAMDisk Image": "ramdisk",
    "Firmware": "firmware",
    "Script": "script",
    "Filesystem Image": "filesystem",
    "Standalone Program": "standalone",
}
COMPRESSION = {"uncompressed": "none"}

def run(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True).stdout

def firmhead(info: str, path: str) -> dict:
    out = {"parts": [], "checks": {}, "meta": {}, "sigs": [], "size": None}
    first = True
    for line in run(info, path).splitlines():
        if re.match(r"^\w+@0x", line):
            if not first:
                break
            first = False
            out["size"] = int(re.search(r"size (\d+)", line)[1])
        elif m := re.match(r"^  part  (\S+)\s+0x[0-9a-f]+\s+(\d+) (\w+)\s*(\S*)", line):
            if m[3] != "signature":
                out["parts"].append((m[1], int(m[2]), m[4]))
        elif m := re.match(r"^  meta  (\S+) = (.*)$", line):
            out["meta"][m[1]] = m[2]
        elif line.startswith("  check "):
            out.setdefault("states", []).append(line.split()[3])
            if m := re.match(r"^  check (\S+)\s+image\s+\w+\s+(\S+)\s+([0-9a-f]+)$", line):
                out["checks"].setdefault(m[2], (m[1], m[3]))
        elif m := re.match(r"^  sig   (\S+) (\S+) configuration", line):
            out["sigs"].append((m[1].split("/")[0], m[2]))
    return out

def fit(text: str) -> dict:
    out = {"parts": [], "checks": {}, "sigs": []}
    section, name, fields = None, None, {}

    def flush():
        if section == "image":
            kind = TYPES.get(fields.get("Type", ""), fields.get("Type", ""))
            comp = fields.get("Compression", "").removesuffix(" compressed")
            comp = COMPRESSION.get(comp, comp)
            out["parts"].append((name, int(fields["Data Size"].split()[0]), comp, kind))
            if "Hash value" in fields:
                out["checks"][name] = (fields["Hash algo"], fields["Hash value"])
        elif section == "conf" and "Sign algo" in fields:
            out["sigs"].append((name, fields["Sign algo"].split(":")[0]))

    for line in text.splitlines():
        if m := re.match(r"^ (Image|Configuration) \d+ \((.+)\)$", line):
            flush()
            section, name, fields = ("image" if m[1] == "Image" else "conf"), m[2], {}
        elif m := re.match(r"^  ([A-Za-z ]+):\s+(.*)$", line):
            fields.setdefault(m[1], m[2])
    flush()
    return out

def compare_fit(info: str, path: str) -> list[str] | None:
    text = run("dumpimage", "-l", path)
    if "FIT description" not in text:
        return None
    ref, got = fit(text), firmhead(info, path)
    problems = []
    parts = [(n, s, c) for n, s, c, _ in ref["parts"]]
    if parts != got["parts"]:
        problems.append(f"parts dumpimage {parts} firmhead {got['parts']}")
    if ref["checks"] != got["checks"]:
        problems.append(f"hashes dumpimage {ref['checks']} firmhead {got['checks']}")
    if sorted(ref["sigs"]) != sorted(got["sigs"]):
        problems.append(f"signatures dumpimage {ref['sigs']} firmhead {got['sigs']}")
    return problems

def compare_uimage(info: str, path: str) -> list[str]:
    text, got = run("dumpimage", "-l", path), firmhead(info, path)
    problems = []
    if "Image Name:" not in text:
        return [] if any(state == "bad" for state in got.get("states", [])) else ["dumpimage refuses it"]
    name = re.search(r"^Image Name:\s+(.*)$", text, re.M)[1].rstrip()
    size = int(re.search(r"^Data Size:\s+(\d+)", text, re.M)[1])
    load = int(re.search(r"^Load Address:\s+([0-9a-fA-F]+)", text, re.M)[1], 16)
    entry = int(re.search(r"^Entry Point:\s+([0-9a-fA-F]+)", text, re.M)[1], 16)
    contents = [int(x) for x in re.findall(r"^   Image \d+: (\d+) Bytes", text, re.M)]
    if name != got["meta"].get("name"):
        problems.append(f"name {name!r} vs {got['meta'].get('name')!r}")
    if size + 64 != got["size"]:
        problems.append(f"size {size} vs {got['size']}")
    if load != int(got["meta"]["load"], 16) or entry != int(got["meta"]["entry"], 16):
        problems.append("load/entry")
    sizes = [s for _, s, _ in got["parts"]]
    if contents and contents != sizes:
        problems.append(f"multi {contents} vs {sizes}")
    if not contents and sizes != [size]:
        problems.append(f"payload {size} vs {sizes}")
    return problems

def main() -> int:
    info, failures = sys.argv[1], 0
    for path in sys.argv[2:]:
        head = open(path, "rb").read(4)
        if head == b"\x27\x05\x19\x56":
            problems = compare_uimage(info, path)
        elif head == b"\xd0\x0d\xfe\xed":
            problems = compare_fit(info, path)
        else:
            continue
        if problems is None:
            print(f"skip {path} (dumpimage rejects it: FIT without timestamp)")
            continue
        failures += bool(problems)
        print(f"{'DIFF' if problems else 'ok  '} {path}")
        for p in problems:
            print(f"     {p}")
    return 1 if failures else 0

if __name__ == "__main__":
    sys.exit(main())
