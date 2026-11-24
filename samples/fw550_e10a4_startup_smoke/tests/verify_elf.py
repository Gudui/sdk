#!/usr/bin/env python3
"""Offline static smoke-source/ELF and log review, never runs a payload."""
import argparse, pathlib, re, subprocess, sys
p=argparse.ArgumentParser()
p.add_argument("elf",type=pathlib.Path)
a=p.parse_args()
out=subprocess.check_output(["readelf","-h",str(a.elf)],text=True)
assert "DYN (Position-Independent Executable file)" in out
assert "Advanced Micro Devices X86-64" in out
dyn=subprocess.check_output(["readelf","-r",str(a.elf)],text=True)
types=set(re.findall(r"R_X86_64_[A-Z0-9_]+",dyn))
print("Relocation types:",", ".join(sorted(types)))
assert types <= {"R_X86_64_RELATIVE"}, "Unsupported relocation types for examined upstream loader: "+str(types)
strings=subprocess.check_output(["strings",str(a.elf)],text=True)
for marker in ["E10A4S MAIN_ENTER","E10A4S FIRMWARE","E10A4S EXIT_OK","E10A4S EXIT_FAIL"]:
    assert marker in strings, "Missing marker "+marker
symbols=subprocess.check_output(["readelf","-Ws",str(a.elf)],text=True)
assert "kernel_copyout_exact" not in symbols
print("PASS: E10A4S symbols, markers, relocations, PS5 ELF format (offline only)")
