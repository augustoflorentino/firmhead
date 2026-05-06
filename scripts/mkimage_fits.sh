#!/usr/bin/env bash
set -euo pipefail

out=${1:?usage: $0 out-dir}
mkdir -p "$out/keys"
cd "$out"
head -c 4096 /dev/urandom > kernel.bin
head -c 512 /dev/urandom > fdt.bin

key() {
    [ -f "keys/$1.key" ] && return
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$2" -out "keys/$1.key" 2>/dev/null
    openssl req -batch -new -x509 -key "keys/$1.key" -out "keys/$1.crt" -subj "/CN=$1" 2>/dev/null
}

control() {
    printf '/dts-v1/;\n/ { model = "control"; };\n' | dtc -I dts -O dtb -o "$1" - 2>/dev/null
}

its() {
    local name=$1 kernel=$2 algo=$3 keyname=$4 where=$5 sign=$6
    local image_sig="" conf_sig=""
    if [ "$where" = image ]; then
        image_sig="signature-1 { algo = \"$algo\"; key-name-hint = \"$keyname\"; };"
    else
        conf_sig="signature-1 { algo = \"$algo\"; key-name-hint = \"$keyname\"; sign-images = $sign; };"
    fi
    cat > "$name.its" <<ITS
/dts-v1/;
/ {
    description = "firmhead $name";
    images {
        $kernel {
            data = /incbin/("kernel.bin");
            type = "kernel"; arch = "arm"; os = "linux"; compression = "none";
            load = <0x80008000>; entry = <0x80008000>;
            hash-1 { algo = "sha256"; };
            $image_sig
        };
        fdt-1 {
            data = /incbin/("fdt.bin");
            type = "flat_dt"; arch = "arm"; compression = "none";
            hash-1 { algo = "sha256"; };
        };
    };
    configurations {
        default = "conf-1";
        conf-1 {
            kernel = "$kernel";
            fdt = "fdt-1";
            $conf_sig
        };
    };
};
ITS
}

build() {
    local name=$1 bits=$2 required=$3
    shift 3
    key "k$bits" "$bits"
    its "$name" "$@"
    control "$name.control.dtb"
    mkimage -f "$name.its" -k keys -K "$name.control.dtb" $required "$name.itb" > "$name.log"
}

build weak-hash 2048 -r kernel-1 sha1,rsa2048 k2048 conf '"kernel", "fdt"'
build images-only 2048 -r kernel-1 sha256,rsa2048 k2048 image ''
build partial 2048 -r kernel-1 sha256,rsa2048 k2048 conf '"kernel"'
build optional-key 2048 "" kernel-1 sha256,rsa2048 k2048 conf '"kernel", "fdt"'
build unit-address 2048 -r kernel@1 sha256,rsa2048 k2048 conf '"kernel", "fdt"'
build good-2048 2048 -r kernel-1 sha256,rsa2048 k2048 conf '"kernel", "fdt"'
build good-4096 4096 -r kernel-1 sha256,rsa4096 k4096 conf '"kernel", "fdt"'
ls *.itb *.control.dtb
