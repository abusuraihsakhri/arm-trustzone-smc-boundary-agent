"""
CLI for ARM TrustZone SMC Boundary Simulator.

Commands:
- smc: Execute an SMC call
- memory: Show secure memory map
- check: Check memory access permission
- simulate: Run a simulation of Normal world operations
- status: Show simulator status
- decode: Decode an SMC function ID
- encode: Encode an SMC function ID
"""
import argparse
import json
import sys

from simulator import (
    TrustZoneSimulator, World, SMCReturnCode, SMCOwner,
    SMCFunction, SecureMemoryType, SecureMemoryRegion,
    encode_smc_function_id, decode_smc_function_id,
    simulate_normal_world_operations,
)


def cmd_smc(args):
    """Execute an SMC call."""
    sim = TrustZoneSimulator()
    func_id = int(args.function_id, 0) if isinstance(args.function_id, str) else args.function_id
    smc_args = [int(a, 0) for a in args.args] if args.args else []

    response = sim.smc_call(func_id, smc_args, World.NORMAL)

    decoded = decode_smc_function_id(func_id)
    print(f"SMC Call: 0x{func_id:08X}")
    print(f"  Decoded: owner=0x{decoded['owner']:02X}, func=0x{decoded['func_num']:02X}, "
          f"fast={'Y' if decoded['fast_call'] else 'N'}, smc64={'Y' if decoded['smc64'] else 'N'}")
    print(f"  Return code: {response.return_code} ({SMCReturnCode(response.return_code).name})")
    if response.return_values:
        print(f"  Return values: {[f'0x{v:016X}' for v in response.return_values]}")
    return 0


def cmd_memory(args):
    """Show secure memory map."""
    sim = TrustZoneSimulator()
    regions = sim.get_memory_map()
    print(f"Secure Memory Map ({len(regions)} regions):")
    for r in regions:
        print(f"  {r['name']:20s}  {r['base']}  size={r['size']}  "
              f"{r['permissions']}  secure_only={r['secure_only']}  type={r['type']}")
    return 0


def cmd_check(args):
    """Check memory access permission."""
    sim = TrustZoneSimulator()
    address = int(args.address, 0)
    world = World.SECURE if args.secure else World.NORMAL
    allowed, reason = sim.check_memory_access(address, args.access, world)
    print(f"Memory Access Check:")
    print(f"  Address: 0x{address:016X}")
    print(f"  Access:  {args.access}")
    print(f"  World:   {world.value}")
    print(f"  Result:  {'ALLOWED' if allowed else 'DENIED'}")
    print(f"  Reason:  {reason}")
    return 0 if allowed else 1


def cmd_simulate(args):
    """Run a simulation of Normal world operations."""
    sim = TrustZoneSimulator()
    results = simulate_normal_world_operations(sim)

    print("TrustZone Simulation Results:")
    for i, r in enumerate(results, 1):
        print(f"\n  [{i}] {r['operation']}:")
        if 'response' in r:
            resp = r['response']
            print(f"      Return: {resp.get('return_code_name', resp.get('return_code', 'N/A'))}")
            if 'return_values' in resp and resp['return_values']:
                print(f"      Values: {resp['return_values'][:2]}")
        if 'allowed' in r:
            print(f"      Access: {'ALLOWED' if r['allowed'] else 'DENIED'}")
            print(f"      Reason: {r['reason']}")

    # Show violations
    violations = sim.get_security_violations()
    if violations:
        print(f"\n  Security Violations ({len(violations)}):")
        for v in violations:
            print(f"    - {v['description']}")

    status = sim.get_status()
    print(f"\n  Summary: {status['total_smc_calls']} SMC calls, "
          f"{status['security_violations']} violations")
    return 0


def cmd_status(args):
    """Show simulator status."""
    sim = TrustZoneSimulator()
    status = sim.get_status()
    print("TrustZone Simulator Status:")
    for k, v in status.items():
        print(f"  {k}: {v}")
    return 0


def cmd_decode(args):
    """Decode an SMC function ID."""
    func_id = int(args.function_id, 0)
    decoded = decode_smc_function_id(func_id)
    print(f"SMC Function ID: 0x{func_id:08X}")
    print(f"  FastCall:  {'Yes' if decoded['fast_call'] else 'No'}")
    print(f"  SMC64:     {'Yes' if decoded['smc64'] else 'No'}")
    print(f"  Owner:     0x{decoded['owner']:02X}")
    print(f"  Function:  0x{decoded['func_num']:02X}")
    return 0


def cmd_encode(args):
    """Encode an SMC function ID."""
    func_id = encode_smc_function_id(
        fast_call=args.fast_call,
        smc64=args.smc64,
        owner=args.owner,
        func_num=args.func_num,
    )
    print(f"Encoded SMC Function ID: 0x{func_id:08X}")
    decoded = decode_smc_function_id(func_id)
    print(f"  FastCall:  {'Yes' if decoded['fast_call'] else 'No'}")
    print(f"  SMC64:     {'Yes' if decoded['smc64'] else 'No'}")
    print(f"  Owner:     0x{decoded['owner']:02X}")
    print(f"  Function:  0x{decoded['func_num']:02X}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='arm-trustzone-smc',
        description='ARM TrustZone SMC Boundary Simulator'
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # smc
    p = sub.add_parser('smc', help='Execute an SMC call')
    p.add_argument('function_id', type=str, help='Function ID (hex, e.g. 0xB200FF01)')
    p.add_argument('args', nargs='*', help='SMC arguments (hex)')
    p.set_defaults(func=cmd_smc)

    # memory
    p = sub.add_parser('memory', help='Show secure memory map')
    p.set_defaults(func=cmd_memory)

    # check
    p = sub.add_parser('check', help='Check memory access')
    p.add_argument('--address', type=str, required=True, help='Address (hex)')
    p.add_argument('--access', choices=['read', 'write', 'execute'], default='read')
    p.add_argument('--secure', action='store_true', help='Access from Secure world')
    p.set_defaults(func=cmd_check)

    # simulate
    p = sub.add_parser('simulate', help='Run Normal world simulation')
    p.set_defaults(func=cmd_simulate)

    # status
    p = sub.add_parser('status', help='Show simulator status')
    p.set_defaults(func=cmd_status)

    # decode
    p = sub.add_parser('decode', help='Decode SMC function ID')
    p.add_argument('function_id', type=str, help='Function ID (hex)')
    p.set_defaults(func=cmd_decode)

    # encode
    p = sub.add_parser('encode', help='Encode SMC function ID')
    p.add_argument('--fast-call', action='store_true', help='Fast call')
    p.add_argument('--smc64', action='store_true', help='SMC64')
    p.add_argument('--owner', type=int, required=True, help='Owner ID')
    p.add_argument('--func-num', type=int, required=True, help='Function number')
    p.set_defaults(func=cmd_encode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
