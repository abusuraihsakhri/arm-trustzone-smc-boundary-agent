# ARM TrustZone SMC Boundary Simulator

A Python simulator for ARM TrustZone Secure Monitor Call (SMC) boundary operations. Implements world switching (Secure ↔ Normal), SMC function ID encoding/decoding per SMCCC, secure memory protection, and security boundary validation.

## What This Actually Does

This is a **simulation** of ARM TrustZone concepts. It models the SMC calling convention (SMCCC), world switching, memory protection regions, and call dispatch without requiring ARM hardware. The SMC function ID encoding follows the actual SMCCC specification.

## Features

### SMC Interface
- **SMC Function ID Encoding/Decoding**: Per SMCCC spec (FastCall, SMC32/64, Owner, Function)
- **Call Dispatch**: Routes SMC calls to appropriate handlers by owner ID
- **Parameter Passing**: SMCCC-compliant argument passing (x0-x7)

### World Management
- **Secure World**: Trusted OS (OP-TEE style) handler
- **Normal World**: Caller world for SMC requests
- **Monitor World**: Handles world switches and architecture calls

### Memory Protection
- **TEE RAM**: Secure-only, RWX
- **TEE Stack**: Secure-only, RW
- **Shared Memory**: Accessible from both worlds
- **Access Control**: Per-region permission checking with violation logging

### Security Boundary
- **Validation**: Normal world cannot call Secure Monitor functions directly
- **Audit Log**: All SMC calls and security violations logged
- **Violation Tracking**: Unauthorized access attempts recorded

## Quick Start

```bash
# Run full simulation
python cli.py simulate

# Execute an SMC call
python cli.py smc 0xB200FF01

# Decode an SMC function ID
python cli.py decode 0xC4000003

# Encode an SMC function ID
python cli.py encode --fast-call --smc64 --owner 50 --func-num 1

# Check memory access
python cli.py check --address 0xBE000100 --access read

# Show memory map
python cli.py memory

# Show status
python cli.py status
```

## SMC Function ID Format (SMCCC)

```
Bit 31:    FastCall (1) / YieldingCall (0)
Bit 30:    SMC64 (1) / SMC32 (0)
Bits 29-24: Service Call Owner
Bits 23-16: Function Number
Bits 15-0:  Reserved
```

## Python API

```python
from simulator import TrustZoneSimulator, World, SMCFunction

sim = TrustZoneSimulator()

# Execute SMC call
response = sim.smc_call(SMCFunction.SMC_VERSION)
print(response.return_code)

# Check memory access
allowed, reason = sim.check_memory_access(0xBE000100, 'read', World.NORMAL)

# Get status
status = sim.get_status()
```

## Requirements

Python 3.10+ stdlib only (no external dependencies).

## License

MIT
