import json
import os
import re
from pathlib import Path

from web3 import Web3

REPO_ROOT = Path(__file__).resolve().parents[2]

# Colon-separated list of directories to scan (recursively) for abi*.json
# files. Not set by default: this repo does not vendor any external ABI
# corpus, so callers must point this at one (e.g. a directory of verified
# contract ABIs) before running this tool.
_abi_roots_env = os.environ.get("SCOBELIX_ABI_ROOTS", "")
ABI_ROOTS = [Path(p) for p in _abi_roots_env.split(":") if p]

OUT_PATH = Path(
    os.environ.get(
        "SCOBELIX_SIGS_OUT", str(REPO_ROOT / "scobelix" / "data" / "local_sigs.json")
    )
)


def load_abi(path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []

    if isinstance(data, list):
        return data

    if isinstance(data, dict):
        if "abi" in data and isinstance(data["abi"], list):
            return data["abi"]
        if "result" in data and isinstance(data["result"], dict):
            res = data["result"]
            if "abi" in res and isinstance(res["abi"], list):
                return res["abi"]
        return data

    return []


def is_supported_type(type_str: str) -> bool:
    base = type_str
    while re.search(r"\[[0-9]*\]$", base):
        base = re.sub(r"\[[0-9]*\]$", "", base)
    if base in ("uint", "int"):
        return True
    if re.fullmatch(
        r"u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)",
        base,
    ):
        return True
    if base in ("address", "bool", "string", "bytes", "function"):
        return True
    if re.fullmatch(r"bytes(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)", base):
        return True
    if re.fullmatch(
        r"fixed(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)x(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)",
        base,
    ):
        return True
    if re.fullmatch(
        r"ufixed(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)x(1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32)",
        base,
    ):
        return True
    return False


def format_type(entry):
    t = entry.get("type")
    if not t:
        return None
    if t.startswith("tuple"):
        suffix = t[5:]
        components = entry.get("components") or []
        inner = ",".join(filter(None, (format_type(c) for c in components)))
        if not inner and components:
            return None
        return f"({inner}){suffix}"
    if is_supported_type(t):
        return t
    return None


def abi_functions(abi_items):
    for item in abi_items:
        if not isinstance(item, dict):
            continue
        if item.get("type") != "function":
            continue
        name = item.get("name")
        inputs = item.get("inputs") or []
        if not name:
            continue
        types = []
        for inp in inputs:
            t = format_type(inp)
            if not t:
                types = []
                break
            types.append(t)
        if not types and inputs:
            continue
        yield name, inputs, types


def signature(name, types):
    return f"{name}({','.join(types)})"


def parse_signature_string(text: str):
    if not text:
        return None
    if ":" in text and "function" not in text and "(" not in text:
        parts = text.split(":", 1)
        if len(parts) == 2:
            type_part = parts[0].strip()
            name = parts[1].strip()
            if is_supported_type(type_part) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                return f"{name}()"
    m = re.search(r"function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", text)
    if not m:
        m = re.search(r"([A-Za-z_]\w*)\s*\(([^)]*)\)", text)
    if not m:
        return None
    name = m.group(1)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return None
    if name == "function":
        return None
    params = m.group(2).strip()
    if not params:
        return f"{name}()"
    types = []
    for raw in params.split(","):
        t = raw.strip().split(" ")[0]
        if t:
            types.append(t)
    if not types:
        return None
    return f"{name}({','.join(types)})"


def walk_misc_signatures(data):
    res = []
    if isinstance(data, str):
        sig = parse_signature_string(data)
        if sig:
            res.append(sig)
        return res
    if isinstance(data, dict):
        for v in data.values():
            res.extend(walk_misc_signatures(v))
        return res
    if isinstance(data, list):
        for v in data:
            res.extend(walk_misc_signatures(v))
        return res
    return res


def compute_selector(sig: str) -> str:
    """4-byte function selector, computed directly with keccak256 - no solc
    (or any other external binary) required."""
    digest = bytes(Web3.keccak(text=sig))[:4]
    return "0x" + digest.hex()


def main():
    if not ABI_ROOTS:
        print(
            "SCOBELIX_ABI_ROOTS is not set - nothing to scan. Set it to a "
            "':'-separated list of directories containing abi*.json files "
            "and re-run, e.g.:\n"
            "  SCOBELIX_ABI_ROOTS=/path/to/abis python -m scobelix.tools.build_local_sigs"
        )
        return

    abi_paths = []
    for root in ABI_ROOTS:
        if not root.exists():
            print(f"warning: {root} does not exist, skipping")
            continue
        abi_paths.extend(root.rglob("abi*.json"))

    abi_paths = sorted({p.resolve() for p in abi_paths})

    sig_inputs = {}
    for path in abi_paths:
        abi = load_abi(path)
        if isinstance(abi, list):
            for name, inputs, types in abi_functions(abi):
                sig = signature(name, types)
                if sig not in sig_inputs:
                    cleaned = []
                    for idx, inp in enumerate(inputs):
                        t = format_type(inp) or "bytes"
                        n = inp.get("name") or f"param{idx+1}"
                        cleaned.append({"type": t, "name": n})
                    sig_inputs[sig] = cleaned
        else:
            for sig in walk_misc_signatures(abi):
                if sig in sig_inputs:
                    continue
                name, types = sig.split("(", 1)
                type_list = types[:-1]
                inputs = []
                if type_list:
                    for idx, t in enumerate(type_list.split(",")):
                        if not is_supported_type(t):
                            inputs = []
                            break
                        inputs.append({"type": t, "name": f"param{idx+1}"})
                    if not inputs:
                        continue
                sig_inputs[sig] = inputs

    out = {}
    conflicts = 0
    for sig, inputs in sig_inputs.items():
        selector = compute_selector(sig)
        name = sig.split("(", 1)[0]
        if selector in out:
            if out[selector]["name"] != name:
                conflicts += 1
            continue
        out[selector] = {"name": name, "inputs": inputs}

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {OUT_PATH} with {len(out)} signatures ({conflicts} conflicts skipped)")


if __name__ == "__main__":
    main()
