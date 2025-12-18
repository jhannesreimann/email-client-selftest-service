#!/usr/bin/env python3

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"default_mode": "baseline", "overrides": []}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", default="/var/lib/nsip-selftest/mode.json")
    ap.add_argument("--mode", choices=["baseline", "t1", "t2", "t3", "t4"], required=True)
    ap.add_argument("--ip", help="Client public IP to override (if omitted, sets default_mode)")
    ap.add_argument("--ttl", type=int, default=600, help="Override TTL in seconds")
    ap.add_argument("--show", action="store_true", help="Print the resulting store JSON")
    args = ap.parse_args()

    path = Path(args.store)
    data = _load(path)

    now = int(time.time())
    overrides = [o for o in data.get("overrides", []) if int(o.get("expires", 0)) >= now]

    if args.ip:
        overrides = [o for o in overrides if o.get("ip") != args.ip]
        overrides.append({"ip": args.ip, "mode": args.mode, "expires": now + args.ttl})
        data["overrides"] = overrides
    else:
        data["default_mode"] = args.mode
        data["overrides"] = overrides

    _save(path, data)

    if args.show:
        print(json.dumps(data, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
