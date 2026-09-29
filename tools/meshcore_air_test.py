#!/usr/bin/env python3
"""
Over-the-air test for the MeshCore decoder, using a USB-connected MeshCore companion.

Runs with the `meshcore` Python package (e.g. a venv with `pip install meshcore`):

    PY=~/code/meshcore/.venv/bin/python
    $PY tools/meshcore_air_test.py setup --port /dev/ttyACM1 --config config.jsonc
    ./loraspy.py listen --protocol meshcore --jsonl mc.jsonl &      # (re)start after setup
    $PY tools/meshcore_air_test.py send --port /dev/ttyACM1 --jsonl mc.jsonl

What it does:
  1. names the node and exports its private key into the config's meshcore.identities
     (so the monitor can decrypt DMs as the sender),
  2. creates a local peer identity, adds it to the node as a contact and to the config
     (so the monitor can also decrypt as the recipient),
  3. adds the #test hashtag channel on the node,
  4. sends: zero-hop advert, flood advert, Public message, #test message, DM to the peer,
     waiting after each until the monitor's JSONL shows it (or a timeout).
Steps 1-3 are `setup` (the monitor only loads keys at start), step 4 is `send`.
"""

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from meshcore import EventType, MeshCore  # noqa: E402

from meshsdr.config import load_jsonc  # noqa: E402


def make_identity():
    seed = os.urandom(32)
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw,
                                                                                ser.PublicFormat.Raw)
    h = bytearray(hashlib.sha512(seed).digest())  # MeshCore (orlp ed25519) 64-byte private key
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return pub, bytes(h)


def update_config(path: str, identities: list[dict], channels: list[dict]):
    """Rewrite the meshcore section of a JSONC config (comments elsewhere are kept)."""
    text = Path(path).read_text()
    raw = load_jsonc(path)
    mc = raw.get("meshcore", {})
    ids = [i for i in mc.get("identities", []) if i["name"] not in {x["name"] for x in identities}] + identities
    chans = mc.get("channels", [{"name": "Public", "secret": "8b3387e9c5cdea6ac9e5edbaa115cd72"}])
    for c in channels:
        if c["name"] not in {x["name"] for x in chans}:
            chans.append(c)
    new = {"channels": chans, "identities": ids, "public_keys": mc.get("public_keys", {})}
    block = '"meshcore": ' + json.dumps(new, indent=2).replace("\n", "\n  ") + ","
    if '"meshcore":' in text:
        # replace the existing object (balanced braces from its opening '{')
        i = text.index('"meshcore":')
        j = text.index("{", i)
        depth = 0
        for k in range(j, len(text)):
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            if depth == 0:
                break
        end = k + 1
        if text[end:end + 1] == ",":
            end += 1
        text = text[:i] + block + text[end:]
    else:
        i = text.rindex("}")
        text = text[:i] + "  " + block + "\n" + text[i:]
    Path(path).write_text(text)


class Watch:
    def __init__(self, path):
        self.path = path
        self.pos = Path(path).stat().st_size if Path(path).exists() else 0

    async def wait(self, pred, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if Path(self.path).exists():
                with open(self.path, encoding="utf-8") as f:
                    f.seek(self.pos)
                    for line in f:
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            continue
                        if rec.get("protocol") == "meshcore" and pred(rec):
                            return rec
            await asyncio.sleep(0.5)
        return None


def describe(rec):
    if rec is None:
        return "NOT heard"
    f = rec.get("fields", {})
    what = f.get("text") or f.get("name") or ""
    how = rec.get("channel") or (f"DM via identity {rec['identity']}" if rec.get("identity") else "")
    sig = "" if "signature_ok" not in f else (" signature OK" if f["signature_ok"] else " BAD SIGNATURE")
    return f"heard ({rec['type']}, {rec['route']}, SNR≈{rec['snr_db']:.1f}) {how} {what!r}{sig}"


async def setup(mc, args) -> dict:
    run = os.urandom(2).hex()
    await mc.commands.set_name(args.name)
    my_pub = bytes.fromhex(mc.self_info["public_key"])
    ev = await mc.commands.export_private_key()
    if ev.type == EventType.ERROR:
        raise SystemExit(f"export_private_key failed: {ev.payload} (firmware built without ENABLE_PRIVATE_KEY_EXPORT?)")
    my_prv = ev.payload["private_key"] if isinstance(ev.payload, dict) else ev.payload
    my_prv = bytes.fromhex(my_prv) if isinstance(my_prv, str) else bytes(my_prv)

    peer_pub, peer_prv = make_identity()
    contact = {"public_key": peer_pub.hex(), "type": 1, "flags": 0, "out_path": "", "out_path_len": -1,
               "out_path_hash_mode": 0, "adv_name": f"sdrpeer-{run}", "last_advert": int(time.time()),
               "adv_lat": 0.0, "adv_lon": 0.0}
    print("add_contact:", (await mc.commands.add_contact(contact)).type.name)
    print("set_channel 1 #test:", (await mc.commands.set_channel(1, "#test", hashlib.sha256(b"#test").digest()[:16])).type.name)
    update_config(args.config,
                  [{"name": args.name, "private_key": my_prv.hex()},
                   {"name": contact["adv_name"], "private_key": peer_prv.hex()}],
                  [{"name": "#test"}])
    print(f"node {args.name} pub {my_pub.hex()[:16]}…, peer {contact['adv_name']} pub {peer_pub.hex()[:16]}…; "
          f"keys written to {args.config} — restart the monitor before 'send'")
    return {"run": run, "my_pub": my_pub.hex(), "contact": contact}


async def send(mc, args, state):
    watch = Watch(args.jsonl)
    run, my_pub, contact = state["run"], state["my_pub"], state["contact"]
    steps = []

    async def step(name, coro, pred):
        t0 = time.time()
        ev = await coro
        rec = await watch.wait(pred, args.timeout)
        took = f" after {time.time() - t0:.1f} s" if rec else ""
        print(f"  {name:<18} node:{ev.type.name:<10} {describe(rec)}{took}", flush=True)
        steps.append((name, rec))
        await asyncio.sleep(3)

    def our_advert(route=None):
        return lambda r: r["type"] == "ADVERT" and r.get("fields", {}).get("public_key") == my_pub and \
            (route is None or r["route"] == route)

    await step("advert (zero-hop)", mc.commands.send_advert(flood=False), our_advert())
    await step("advert (flood)", mc.commands.send_advert(flood=True), our_advert("FLOOD"))
    pub_txt, tag_txt, dm_txt = f"sdrtest {run} public", f"sdrtest {run} hashtag", f"sdrtest {run} dm"
    await step("Public channel", mc.commands.send_chan_msg(0, pub_txt),
               lambda r: r.get("fields", {}).get("text", "").endswith(pub_txt))
    await step("#test channel", mc.commands.send_chan_msg(1, tag_txt),
               lambda r: r.get("fields", {}).get("text", "").endswith(tag_txt))
    await step("DM to peer", mc.commands.send_msg(contact, dm_txt),
               lambda r: r.get("fields", {}).get("text") == dm_txt)
    ok = sum(1 for _, r in steps if r)
    print(f"\n{ok}/{len(steps)} heard and decoded")


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("phase", choices=["setup", "send"])
    ap.add_argument("--port", default="/dev/ttyACM1")
    ap.add_argument("--jsonl", help="LoRaSpy JSONL to watch (send)")
    ap.add_argument("--config", help="LoRaSpy config to add the keys to (setup)")
    ap.add_argument("--state", default="meshcore_test_state.json", help="written by setup, read by send")
    ap.add_argument("--name", default="sdrtest-t3s3")
    ap.add_argument("--timeout", type=float, default=45)
    args = ap.parse_args()

    mc = await MeshCore.create_serial(args.port, 115200)
    try:
        if args.phase == "setup":
            if not args.config:
                raise SystemExit("setup needs --config")
            Path(args.state).write_text(json.dumps(await setup(mc, args)))
        else:
            if not args.jsonl:
                raise SystemExit("send needs --jsonl")
            await send(mc, args, json.loads(Path(args.state).read_text()))
    finally:
        await mc.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
