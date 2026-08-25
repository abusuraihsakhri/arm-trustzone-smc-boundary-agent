#!/usr/bin/env python3
"""
ARM SMCCC SMC Call Boundary Guard.

- Parses 32-bit SMC function identifiers per ARM DEN0028: owning entity number,
  fast/yielding call type, service call, caller id
- Allowlist policy enforcement at the TrustZone boundary
- Secure-memory overlap verification for address parameters
- Token-bucket rate limiting per caller core against SMC flooding
- Tamper-evident audit log via SHA-256 hash chaining
Stdlib only.
"""

import hashlib
import time
from dataclasses import dataclass, field


OEN_ARM_ARCHITECTURE = 0
OEN_STD = 1
OEN_SIP = 2
OEN_OEM = 3
OEN_TRUSTED_OS = 50

PSCI_FUNCTIONS = {
    (0x84000000, "aarch32"): "PSCI_VERSION",
    (0x84000001, "aarch32"): "CPU_SUSPEND",
    (0x84000002, "aarch32"): "CPU_OFF",
    (0x84000003, "aarch32"): "CPU_ON",
    (0xC4000003, "aarch64"): "CPU_ON_64",
    (0x84000008, "aarch32"): "SYSTEM_OFF",
}


@dataclass
class SmcCall:
    function_id: int
    args: tuple
    caller_core: int
    aarch64: bool = False


@dataclass
class SmcDecision:
    allowed: bool
    reason: str
    parsed: dict


def parse_function_id(fid: int) -> dict:
    """Field extraction for SMCCC function identifiers. Bit 30 selects the
    64-bit calling convention (0x84xxxxxx SMC32 vs 0xC4xxxxxx SMC64 pairs);
    the owning entity occupies the top byte."""
    top_byte = (fid >> 24) & 0xFF
    smc64_convention = bool((fid >> 30) & 1)
    state = (fid >> 16) & 0xFF
    service = (fid >> 8) & 0xFF
    caller_id = fid & 0xFF
    return {"owning_entity_byte": top_byte,
            "smc64_convention": smc64_convention,
            "service": service, "caller_id": caller_id,
            "state_nonzero": state != 0}


class SmcFirewall:
    def __init__(self, allowed_functions: set, secure_memory_ranges: list,
                 calls_per_second_per_core: float = 50.0):
        self.allowed = set(allowed_functions)
        self.secure_ranges = secure_memory_ranges
        self.rate = calls_per_second_per_core
        self.buckets = {}
        self.audit_head = "GENESIS"
        self.audit_log = []

    def _rate_limited(self, core: int) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.get(core, (self.rate, now))
        elapsed = now - last
        tokens = min(self.rate, tokens + elapsed * self.rate)
        if tokens < 1.0:
            self.buckets[core] = (tokens, now)
            return True
        self.buckets[core] = (tokens - 1.0, now)
        return False

    def _memory_violation(self, call: SmcCall) -> str:
        for arg in call.args:
            for lo, hi, label in self.secure_ranges:
                if isinstance(arg, int) and lo <= arg < hi:
                    return f"arg {arg:#x} inside secure range {label} [{lo:#x},{hi:#x})"
        return None

    def evaluate(self, call: SmcCall) -> SmcDecision:
        parsed = parse_function_id(call.function_id)
        key = (call.function_id, "aarch64" if call.aarch64 else "aarch32")
        name = PSCI_FUNCTIONS.get(key, f"svc_{call.function_id:#010x}")

        if parsed["state_nonzero"]:
            verdict, why = False, "reserved state bits set: malformed SMC identifier"
        elif call.function_id not in self.allowed:
            verdict, why = False, f"{name} not on allowlist"
        else:
            mem = self._memory_violation(call)
            if mem:
                verdict, why = False, mem
            elif self._rate_limited(call.caller_core):
                verdict, why = False, "token bucket exhausted (SMC flood)"
            else:
                verdict, why = True, f"{name} accepted"

        self._audit(call.function_id, call.caller_core, verdict, why)
        return SmcDecision(verdict, why, {**parsed, "name": name})

    def _audit(self, fid: int, core: int, ok: bool, why: str) -> None:
        entry = f"{time.time_ns()}|core{core}|{fid:#010x}|{'OK' if ok else 'DENY'}|{why}"
        digest = hashlib.sha256((self.audit_head + entry).encode()).hexdigest()
        self.audit_head = digest
        self.audit_log.append({"entry": entry, "chain": digest[:16]})

    def verify_audit_chain(self) -> bool:
        head = "GENESIS"
        for item in self.audit_log:
            calc = hashlib.sha256((head + item["entry"]).encode()).hexdigest()
            if calc[:16] != item["chain"]:
                return False
            head = calc
        return True


if __name__ == "__main__":
    allowlist = {0x84000000, 0x84000003, 0xC4000003, 0x82000010}
    fw = SmcFirewall(allowlist,
                     [(0xFE000000, 0xFE100000, "TEE_shm"),
                      (0x40000000, 0x40020000, "secure_DRAM")],
                     calls_per_second_per_core=5)

    good = SmcCall(0x84000003, (0x1,), caller_core=0)
    print("CPU_ON:", fw.evaluate(good))

    rogue = SmcCall(0xC4000007, (0xFE000800,), caller_core=1)
    print("rogue read:", fw.evaluate(rogue))

    malformed = SmcCall(0x84010003, (), caller_core=2)
    print("malformed:", fw.evaluate(malformed))

    unknown = SmcCall(0x83000048, (), caller_core=4)
    print("off-allowlist:", fw.evaluate(unknown))

    flood = [fw.evaluate(SmcCall(0x82000010, (), caller_core=3)).allowed
             for _ in range(12)]
    print("flood results:", flood)

    tampered = list(fw.audit_log)
    print("chain intact:", fw.verify_audit_chain())
    fw.audit_log[0]["entry"] = tampered[0]["entry"].replace("OK", "DENY")
    print("chain intact after tamper:", fw.verify_audit_chain())
