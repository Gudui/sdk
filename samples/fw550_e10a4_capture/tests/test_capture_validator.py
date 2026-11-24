#!/usr/bin/env python3
import copy
import json
import sys
from pathlib import Path
BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE/"tools"))
from verify_five_site_capture import validate,from_klog,CaptureError

manifest=json.loads((BASE/"evidence/stage_b_windows.json").read_text())
ktext=0xffffffff994e0000
capture={
    "firmware_raw":0x5500008, "read_contract":"checked_pipe_v1",
    "ktext_base":ktext, "kdata_base":ktext+0xc40000,
    "cleanup_policy":"persistent_pipe_no_per_read_cleanup",
    "timeout_policy":"no_enforced_timeout", "sites":[]}
for site in manifest["sites"]:
    for stage,offset,hexd in [
        ("site","start","original_hex"),
        ("predecessor","original_044f_prebranch_start","original_044f_prebranch_hex")]:
        raw=bytes.fromhex(site[hexd])
        capture["sites"].append({
            "name":site["site"],"stage":stage,
            "va":ktext+int(site[offset],0),"requested":len(raw),
            "returned":len(raw),"transferred":len(raw),
            "read_errno":0,"syscall_attempted":1,"read_stage":0,"read_rc":0,
            "cleanup_rc":0,"timed_out":False,
            "data_hex":raw.hex(),"initial_hex":bytes(x^255 for x in raw).hex()})
assert validate(manifest,capture)
cases={
 "failed cleanup":lambda x:x["sites"][0].update(cleanup_rc=-1),
 "asserted timeout":lambda x:x["sites"][4].update(timed_out=True),
 "missing cleanup":lambda x:x["sites"][0].pop("cleanup_rc"),
 "missing timeout":lambda x:x["sites"][0].pop("timed_out"),
 "short read":lambda x:x["sites"][0].update(returned=20,transferred=20),
 "negative read":lambda x:x["sites"][0].update(returned=-1,read_rc=-1),
 "failed setup":lambda x:x["sites"][0].update(read_stage=2,read_rc=-1),
 "missing syscall":lambda x:x["sites"][0].update(syscall_attempted=0),
 "wrong firmware":lambda x:x.update(firmware_raw=0x5000000),
 "wrong data base":lambda x:x.update(kdata_base=ktext+0xc50000),
 "bytes mismatch":lambda x:x["sites"][3].update(data_hex="00"*11),
 "stale buffer":lambda x:x["sites"][0].update(data_hex=x["sites"][0]["initial_hex"]),
 "missing receipt":lambda x:x["sites"].pop(),
 "missing contract":lambda x:x.pop("read_contract")
}
for name,change in cases.items():
    mutated=copy.deepcopy(capture);change(mutated)
    try:validate(manifest,mutated)
    except (CaptureError,KeyError,TypeError,ValueError):continue
    raise AssertionError("false acceptance: "+name)

log=["<118>[diag] E10A4 START fw=0x5500008 ktext=%#x kdata=%#x contract=checked_pipe_v1"%(ktext,ktext+0xc40000)]
for i,r in enumerate(capture["sites"]):
    log.append("<118>[diag] E10A4 READ_BEGIN index=%d name=%s stage=%s va=%#x requested=%d"%(i,r["name"],r["stage"],r["va"],r["requested"]))
    log.append("<118>[diag] E10A4 READ_DONE index=%d rc=0 stage=0 syscall_attempted=1 signed_returned=%d transferred=%d errno=0 requested=%d"%(i,r["returned"],r["transferred"],r["requested"]))
    log.append("<118>[diag] E10A4 READ_BYTES index=%d data=%s initial=%s"%(i,r["data_hex"],r["initial_hex"]))
log.append("<118>[diag] E10A4 PASS count=10 bytes=134 complete=1")
assert validate(manifest,from_klog("\n".join(log)))
for bad in [
    log[:-1],
    [x for x in log if "READ_DONE index=0 " not in x],
    log+["<118>[diag] E10A4 ABORT reason=FAILED index=9"],
    log+ [log[1]]
]:
    try:from_klog("\n".join(bad))
    except (CaptureError,KeyError,ValueError):continue
    raise AssertionError("invalid log accepted")
print("PASS: 14 malformed capture cases + four malformed log cases + valid ten-window log")
