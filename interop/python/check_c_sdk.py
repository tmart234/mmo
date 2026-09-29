#!/usr/bin/env python3
"""Check objects signed through the C SDK (crates/fpp-ffi) against the golden
vectors: byte-for-byte equality with the golden object of the same name, and
independent verification by fpp_interop.

Usage: check_c_sdk.py <conformance-output.jsonl> [interop/vectors/fpp1.json]
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fpp_interop  # noqa: E402


def main(output_path, vectors_path):
    vectors = json.loads(Path(vectors_path).read_text())
    golden = {o["name"]: o for o in vectors["objects"]}
    keys = {}
    for k in vectors["keys"]:
        if k["known"]:
            public = bytes.fromhex(k["public"])
            keys[fpp_interop.key_digest(public)[:16]] = {
                "role": k["role"], "alg": k["alg"], "public": public, "name": k["name"],
            }

    failures = checked = 0
    for line in Path(output_path).read_text().splitlines():
        obj = json.loads(line)
        name, cose = obj["name"], bytes.fromhex(obj["cose"])
        want = golden.get(name)
        checked += 1
        if want is None:
            print(f"FAIL {name}: no golden object with this name")
            failures += 1
            continue
        if cose.hex() != want["cose"]:
            print(f"FAIL {name}: C SDK output differs from the golden vector")
            failures += 1
        try:
            fpp_interop.verify(cose, want["type"], keys)
        except fpp_interop.Reject as e:
            print(f"FAIL {name}: independent verifier rejected it ({e})")
            failures += 1
    if checked == 0:
        print("FAIL no objects in C conformance output")
        failures += 1
    print(f"C SDK objects: {checked - failures}/{checked} identical to golden vectors and independently verified")
    return failures == 0


if __name__ == "__main__":
    default = Path(__file__).resolve().parents[1] / "vectors" / "fpp1.json"
    sys.exit(0 if main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else default) else 1)
