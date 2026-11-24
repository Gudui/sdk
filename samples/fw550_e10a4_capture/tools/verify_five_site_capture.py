#!/usr/bin/env python3
"""Strict E10A.4 offline validator: validates ten exact SYS_read receipts.
Run on a manually captured console log or an archived JSON capture. No network I/O.
The persistent SDK pipe has NO per-read cleanup or enforceable timeout guarantee.
"""
import argparse
import json
import re
from pathlib import Path

MANIFEST = Path(__file__).resolve().parents[1] / "evidence" / "stage_b_windows.json"
PREFIX = "E10A4 "

class CaptureError(ValueError):
    pass

def number(value):
    if isinstance(value, bool):
        raise CaptureError("boolean where integer expected")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise CaptureError("missing/invalid integer: %r" % (value,))

def parse_fields(line):
    return dict(re.findall(r"([a-z_]+)=([^\s]+)", line))

def from_klog(text):
    start = []
    begins = {}
    dones = {}
    byte_lines = {}
    passes = []
    for line in text.splitlines():
        if PREFIX not in line:
            continue
        tail = line.split(PREFIX, 1)[1].strip()
        if tail.startswith("START "):
            start.append(parse_fields(tail))
        elif tail.startswith("READ_BEGIN "):
            info = parse_fields(tail)
            index = number(info["index"])
            if index in begins:
                raise CaptureError("duplicate READ_BEGIN")
            begins[index] = info
        elif tail.startswith("READ_DONE "):
            info = parse_fields(tail)
            index = number(info["index"])
            if index in dones:
                raise CaptureError("duplicate READ_DONE")
            dones[index] = info
        elif tail.startswith("READ_BYTES "):
            info = parse_fields(tail)
            index = number(info["index"])
            if index in byte_lines:
                raise CaptureError("duplicate READ_BYTES")
            byte_lines[index] = info
        elif tail.startswith("PASS "):
            passes.append(parse_fields(tail))
        elif tail.startswith("ABORT "):
            raise CaptureError("diagnostic reported ABORT: "+tail)
    if len(start) != 1 or len(passes) != 1:
        raise CaptureError("missing/duplicate START or PASS")
    if any(set(collection) != set(range(10)) for collection in (begins,dones,byte_lines)):
        raise CaptureError("missing, extra, or out-of-range window records")
    if number(passes[0].get("count")) != 10 or number(passes[0].get("bytes")) != 134 or number(passes[0].get("complete")) != 1:
        raise CaptureError("invalid final PASS")
    s = start[0]
    data = {"firmware_raw":number(s["fw"]), "read_contract":s.get("contract"),
            "ktext_base":number(s["ktext"]), "kdata_base":number(s["kdata"]),
            "cleanup_policy":"persistent_pipe_no_per_read_cleanup",
            "timeout_policy":"no_enforced_timeout",
            "sites":[]}
    for i in range(10):
        b,d,x = begins[i],dones[i],byte_lines[i]
        if any(number(v["index"]) != i for v in (b,d,x)):
            raise CaptureError("window index mismatch")
        data["sites"].append({
            "name":b["name"],"stage":b["stage"],
            "va":number(b["va"]),"requested":number(b["requested"]),
            "returned":number(d["signed_returned"]),
            "transferred":number(d["transferred"]),
            "read_errno":number(d["errno"]),
            "syscall_attempted":number(d["syscall_attempted"]),
            "read_stage":number(d["stage"]),"read_rc":number(d["rc"]),
            "data_hex":x["data"],"initial_hex":x["initial"],
            "timed_out":False, "cleanup_rc":0
        })
    return data

def validate(manifest,capture):
    if capture.get("read_contract") != "checked_pipe_v1":
        raise CaptureError("unverified transfer contract")
    if number(capture.get("firmware_raw")) & 0xffff0000 != 0x05500000:
        raise CaptureError("firmware is not FW550")
    if capture.get("cleanup_policy") != "persistent_pipe_no_per_read_cleanup":
        raise CaptureError("unrecognized cleanup semantics")
    if capture.get("timeout_policy") != "no_enforced_timeout":
        raise CaptureError("unrecognized timeout semantics")
    text, data = number(capture.get("ktext_base")),number(capture.get("kdata_base"))
    if text < 0xffff800000000000 or data-text != 0xc40000:
        raise CaptureError("runtime base mismatch")
    expected = []
    for site in manifest["sites"]:
        for stage,offset,hexd in [
            ("site","start","original_hex"),
            ("predecessor","original_044f_prebranch_start","original_044f_prebranch_hex")]:
            expected.append((site["site"],stage,number(site[offset]),bytes.fromhex(site[hexd])))
    if len(expected)!=10 or sum(len(x[3]) for x in expected)!=134:
        raise CaptureError("invalid original Stage B manifest")
    if len(capture.get("sites",[])) != 10:
        raise CaptureError("missing or extra read receipts")
    for i,((name,stage,off,original),receipt) in enumerate(zip(expected,capture["sites"])):
        if receipt.get("name")!=name or receipt.get("stage")!=stage:
            raise CaptureError("wrong window order at index %d" % i)
        if number(receipt.get("va"))!=text+off or number(receipt.get("requested"))!=len(original):
            raise CaptureError("wrong address/length at index %d" % i)
        if receipt.get("timed_out") is not False:
            raise CaptureError("asserted/missing timeout field at index %d" % i)
        if number(receipt.get("cleanup_rc"))!=0:
            raise CaptureError("failed cleanup at index %d" % i)
        if (number(receipt.get("read_rc"))!=0 or number(receipt.get("read_stage"))!=0 or
            number(receipt.get("read_errno"))!=0 or number(receipt.get("syscall_attempted"))!=1):
            raise CaptureError("read setup/syscall failed at index %d" % i)
        if number(receipt.get("returned"))!=len(original) or number(receipt.get("transferred"))!=len(original):
            raise CaptureError("short/negative read at index %d" % i)
        actual, initial = bytes.fromhex(receipt.get("data_hex","")),bytes.fromhex(receipt.get("initial_hex",""))
        if len(actual)!=len(original) or initial!=bytes(x^255 for x in original):
            raise CaptureError("invalid byte record/initial buffer at index %d" % i)
        if actual!=original or actual==initial:
            raise CaptureError("live-original byte mismatch at index %d" % i)
    return True

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture",type=Path)
    parser.add_argument("--format",choices=["log","json"],default="log")
    parser.add_argument("--write-json",type=Path)
    args=parser.parse_args()
    try:
        manifest=json.loads(MANIFEST.read_text())
        raw=args.capture.read_text()
        capture=from_klog(raw) if args.format=="log" else json.loads(raw)
        validate(manifest,capture)
        if args.write_json:
            args.write_json.write_text(json.dumps(capture,indent=2)+"\n")
    except (CaptureError,KeyError,TypeError,ValueError,OSError) as exc:
        parser.exit(1,"FAIL: %s\n" % exc)
    print("PASS: ten exact SDK SYS_read receipts, 134/134 original FW550 bytes")
    print("NOT PROVEN: firmware data-read fault containment, timeout, exclusive pipe ownership, read/write protections")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
