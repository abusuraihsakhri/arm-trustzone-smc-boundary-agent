# ARM TrustZone SMC Boundary Simulator & Security Guard

A pure Python hardware security and firmware boundary simulation engine implementing:
- **ARM Secure Monitor Call Calling Convention (SMCCC / DEN0028):**
  - Bitfield function identifier encoding and decoding:
    $$\text{Bit 31: FastCall (1) vs YieldingCall (0)}$$
    $$\text{Bit 30: Calling Convention SMC32 (0) vs SMC64 (1)}$$
    $$\text{Bits [29:24]: Owning Entity / Service Call Owner (Arch, CPU, SiP, OEM, Standard/Trusted OS, Hypervisor, Secure Monitor)}$$
    $$\text{Bits [23:16]: Function Number within service}$$
    $$\text{Bits [15:0]: Custom / Implementation sub-identifier}$$
- **World Switch Lifecycle Simulation:**
  - Accurately models context saving, EL3 Secure Monitor interception, and register transitions across Normal World (EL1/EL2) $\leftrightarrow$ Secure Monitor (EL3) $\leftrightarrow$ Secure World (OP-TEE / Trusted OS).
- **Secure Memory Region Firewall & Access Control:**
  - Enforces physical memory isolation across TEE RAM, TEE Stack, Secure Devices, and Shared Memory buffers.
  - Detects and logs illicit Normal World execution or DMA access into secure-only physical partitions.
- **SMC Allowlist Policy Enforcement & Rate Limiting:**
  - Enforces entity privileges (e.g. denying Normal World direct calls to Secure Monitor administrative functions).
  - Token-bucket rate limiting preventing SMC denial-of-service or side-channel timing attacks.
- **High-Throughput Batch SMC Validation:** Audits firmware SMC call traces and security policy files from CSV.

Requires Python standard library only (zero external runtime dependencies).

---

## SMCCC Function Identifier Architecture

| Bit Range | Field Name | Description |
|:----------|:-----------|:------------|
| `31` | Type | `1` = Fast Call (atomic, run-to-completion); `0` = Yielding Call (preemptible) |
| `30` | Call Conv | `1` = SMC64 (64-bit arguments/returns in X0-X7); `0` = SMC32 (32-bit in W0-W7) |
| `29:24` | Owner | Service owning entity: `0x00` Arch, `0x02` SiP/CPU, `0x03` OEM, `0x32-0x3F` Trusted OS, `0x3E` Monitor |
| `23:16` | Function Number | Dispatched function index within owner subsystem |
| `15:0` | Sub-function / Reserved | Implementation-defined parameters or standard UID/Revision query |

---

## Features

- **Standard Compliance:** Aligned with ARM SMCCC specification (DEN0028) and OP-TEE Trusted OS conventions.
- **Boundary Verification:** Detects illegal world crossings, memory permission violations, and malformed identifiers.
- **Batch CSV Processing:** High-throughput batch triage for firmware security audit logs and fuzzing traces.

---

## Installation & Requirements

- Python 3.10+ (tested on 3.10, 3.11, 3.12)
- Zero external runtime dependencies. `pytest` is optional for running tests.

```bash
git clone https://github.com/abusuraihsakhri/arm-trustzone-smc-boundary-agent.git
cd arm-trustzone-smc-boundary-agent
```

---

## CLI Usage

### 1. Execute an SMC Call
```bash
python cli.py smc 0x80000000
```

### 2. Inspect Secure Memory Map
```bash
python cli.py memory
```

### 3. Verify Memory Access Permissions
```bash
python cli.py check --address 0xBE000100 --access read
```

### 4. Decode / Encode SMC Function IDs
```bash
python cli.py decode 0xB200FF01
python cli.py encode --fast-call --owner 50 --func-num 1
```

### 5. Batch Process SMC Calls from CSV
```bash
python cli.py batch --input sample.csv --output results.csv
```

---

## Python API Quickstart

```python
from simulator import TrustZoneSimulator, World, SMCFunction, SMCReturnCode

sim = TrustZoneSimulator()

# Query SMCCC version (0x80000000)
resp = sim.smc_call(SMCFunction.SMC_VERSION, caller_world=World.NORMAL)
print(f"SMCCC Version Call Return: {resp.return_code_name}")
print(f"Version: 0x{resp.return_values[0]:08X}")

# Test unauthorized memory access
allowed, reason = sim.check_memory_access(0xBE000100, access_type="read", caller_world=World.NORMAL)
print(f"Access Allowed: {allowed} ({reason})")
```

---

## Running Tests

Run the test suite using standard `unittest` or `pytest`:

```bash
pytest -v
```
