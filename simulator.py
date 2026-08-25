"""
ARM TrustZone SMC Boundary Simulator.

Implements realistic simulations of ARM TrustZone concepts:
- Secure Monitor Call (SMC) interface
- World switching: Secure ↔ Normal
- Secure memory protection regions
- SMC function ID encoding (SMCCC)
- Parameter passing conventions (SMCCC)
- Security boundary validation and access control

Uses only Python stdlib (hashlib, hmac, secrets, struct, enum, dataclasses).
"""
import hashlib
import hmac
import secrets
import struct
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum, IntEnum
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class World(Enum):
    """ARM TrustZone execution worlds."""
    SECURE = "secure"
    NORMAL = "normal"
    MONITOR = "monitor"


class SMCCallingConvention(IntEnum):
    """
    SMC Calling Convention (SMCCC) function identifier encoding.

    Bits [31]:    FastCall (1) or YieldingCall (0)
    Bits [30]:    SMC32 (0) or SMC64 (1)
    Bits [29:24]: Service Call Owner
    Bits [23:16]: Function Number within service
    Bits [15:0]:  Reserved / custom
    """
    pass


# SMCCC Owner IDs
class SMCOwner(IntEnum):
    ARM_ARCH = 0x00
    CPU_SERVICE = 0x02
    SIP_SERVICE = 0x02
    OEM_SERVICE = 0x03
    TRUSTED_OS = 0x32       # OP-TEE, Trusty, etc.
    TRUSTED_OS_END = 0x3F
    HYPERVISOR = 0x5A
    SECURE_MONITOR = 0x7E


# Common SMC function IDs
class SMCFunction(IntEnum):
    # Architecture calls
    SMC_VERSION = 0x80000000
    SMC_ARCH_WORKAROUND_1 = 0x80008000
    SMC_ARCH_WORKAROUND_2 = 0x80008001
    SMC_ARCH_WORKAROUND_3 = 0x80008002

    # CPU service calls
    SMC_CPU_ON = 0xC4000003
    SMC_CPU_OFF = 0x84000002
    SMC_CPU_SUSPEND = 0xC4000001

    # Trusted OS calls
    SMC_STD_CALL_COUNT = 0xB200FF00
    SMC_STD_UID = 0xB200FF01
    SMC_STD_REVISION = 0xB200FF03

    # Secure Monitor calls
    SMC_MON_SMC64 = 0xC2000000


# Memory region types
class SecureMemoryType(Enum):
    TEE_RAM = "tee_ram"
    TEE_STACK = "tee_stack"
    TEE_HEAP = "tee_heap"
    SECURE_DEVICE = "secure_device"
    SHARED_MEMORY = "shared_memory"


# SMC return codes
class SMCReturnCode(IntEnum):
    SUCCESS = 0
    NOT_SUPPORTED = -1
    INVALID_PARAM = -2
    DENIED = -3
    INVALID_ADDRESS = -4
    BUSY = -5
    ABORT = -6


# ---------------------------------------------------------------------------
# SMC Function ID helpers
# ---------------------------------------------------------------------------

def encode_smc_function_id(fast_call: bool, smc64: bool, owner: int,
                           func_num: int) -> int:
    """
    Encode an SMC function ID per SMCCC.

    Format:
        Bit 31:    FastCall (1) / YieldingCall (0)
        Bit 30:    SMC64 (1) / SMC32 (0)
        Bits 29-24: Owner
        Bits 23-16: Function number
        Bits 15-0:  Custom/reserved
    """
    fid = 0
    if fast_call:
        fid |= (1 << 31)
    if smc64:
        fid |= (1 << 30)
    fid |= (owner & 0x3F) << 24
    fid |= (func_num & 0xFF) << 16
    return fid & 0xFFFFFFFF


def decode_smc_function_id(func_id: int) -> Dict[str, int]:
    """
    Decode an SMC function ID.

    Returns dict with fast_call, smc64, owner, func_num fields.
    """
    return {
        'fast_call': bool(func_id & (1 << 31)),
        'smc64': bool(func_id & (1 << 30)),
        'owner': (func_id >> 24) & 0x3F,
        'func_num': (func_id >> 16) & 0xFF,
        'raw': func_id & 0xFFFFFFFF,
    }


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SMCRequest:
    """An SMC request from Normal world to Secure world."""
    function_id: int
    args: List[int] = field(default_factory=list)  # Up to 7 arguments (x1-x7)
    caller_world: World = World.NORMAL
    timestamp: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        decoded = decode_smc_function_id(self.function_id)
        return {
            'function_id': f"0x{self.function_id:08X}",
            'decoded': decoded,
            'args': [f"0x{x:016X}" for x in self.args],
            'caller_world': self.caller_world.value,
        }


@dataclass
class SMCResponse:
    """An SMC response from Secure world."""
    return_code: int
    return_values: List[int] = field(default_factory=list)  # x0-x3
    handler_world: World = World.SECURE
    handled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'return_code': self.return_code,
            'return_code_name': SMCReturnCode(self.return_code).name if self.return_code in SMCReturnCode.__members__.values() else str(self.return_code),
            'return_values': [f"0x{x:016X}" for x in self.return_values],
            'handler_world': self.handler_world.value,
        }


@dataclass
class SecureMemoryRegion:
    """A protected memory region in the Secure world."""
    name: str
    base_address: int
    size: int
    memory_type: SecureMemoryType
    read: bool = True
    write: bool = True
    execute: bool = False
    secure_only: bool = True

    def contains(self, address: int) -> bool:
        return self.base_address <= address < self.base_address + self.size

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'base': f"0x{self.base_address:016X}",
            'size': f"0x{self.size:X}",
            'type': self.memory_type.value,
            'permissions': f"{'R' if self.read else '-'}{'W' if self.write else '-'}{'X' if self.execute else '-'}",
            'secure_only': self.secure_only,
        }


# ---------------------------------------------------------------------------
# SMC Handler Registry
# ---------------------------------------------------------------------------

class SMCHandler:
    """Base class for SMC function handlers."""
    owner: int = 0
    service_name: str = "unknown"

    def can_handle(self, function_id: int) -> bool:
        decoded = decode_smc_function_id(function_id)
        return decoded['owner'] == self.owner

    def handle(self, request: SMCRequest) -> SMCResponse:
        raise NotImplementedError


class ArchHandler(SMCHandler):
    """Handles ARM Architecture SMC calls."""
    owner = SMCOwner.ARM_ARCH
    service_name = "ARM Architecture"

    def handle(self, request: SMCRequest) -> SMCResponse:
        fid = request.function_id
        if fid == SMCFunction.SMC_VERSION:
            return SMCResponse(
                return_code=SMCReturnCode.SUCCESS,
                return_values=[0x00010000],  # SMCCC v1.0
                handler_world=World.MONITOR,
                handled=True,
            )
        return SMCResponse(
            return_code=SMCReturnCode.NOT_SUPPORTED,
            handler_world=World.MONITOR,
            handled=True,
        )


class TrustedOSHandler(SMCHandler):
    """Handles Trusted OS (OP-TEE style) SMC calls."""
    owner = SMCOwner.TRUSTED_OS
    service_name = "Trusted OS"

    def __init__(self):
        self._session_counter = 0
        self._open_sessions: Dict[int, Dict] = {}

    def handle(self, request: SMCRequest) -> SMCResponse:
        func_num = decode_smc_function_id(request.function_id)['func_num']

        if func_num == 0x00:  # SMC_STD_CALL_COUNT
            return SMCResponse(
                return_code=SMCReturnCode.SUCCESS,
                return_values=[10],  # Number of supported calls
                handler_world=World.SECURE,
                handled=True,
            )
        elif func_num == 0x01:  # SMC_STD_UID
            return SMCResponse(
                return_code=SMCReturnCode.SUCCESS,
                return_values=[0x486178e0, 0x4de6b823, 0x80000000, 0x00000000],
                handler_world=World.SECURE,
                handled=True,
            )
        return SMCResponse(
            return_code=SMCReturnCode.NOT_SUPPORTED,
            handler_world=World.SECURE,
            handled=True,
        )


# ---------------------------------------------------------------------------
# TrustZone Simulator
# ---------------------------------------------------------------------------

class TrustZoneSimulator:
    """
    Full ARM TrustZone SMC Boundary Simulator.

    Manages:
    - World state (Secure/Normal/Monitor)
    - SMC call dispatch
    - Secure memory regions
    - Security boundary enforcement
    - Audit logging
    """

    def __init__(self):
        self._current_world = World.NORMAL
        self._memory_regions: Dict[str, SecureMemoryRegion] = {}
        self._handlers: List[SMCHandler] = [ArchHandler(), TrustedOSHandler()]
        self._smc_log: List[Dict[str, Any]] = []
        self._security_violations: List[Dict[str, Any]] = []
        self._call_counter = 0
        self._setup_default_memory()

    def _setup_default_memory(self):
        """Set up default secure memory regions."""
        self.add_memory_region(SecureMemoryRegion(
            name="TEE_RAM",
            base_address=0xBE000000,
            size=0x01000000,  # 16 MB
            memory_type=SecureMemoryType.TEE_RAM,
            read=True, write=True, execute=True,
            secure_only=True,
        ))
        self.add_memory_region(SecureMemoryRegion(
            name="TEE_STACK",
            base_address=0xBDF00000,
            size=0x00100000,  # 1 MB
            memory_type=SecureMemoryType.TEE_STACK,
            read=True, write=True, execute=False,
            secure_only=True,
        ))
        self.add_memory_region(SecureMemoryRegion(
            name="SharedMemory",
            base_address=0xFE000000,
            size=0x01000000,  # 16 MB
            memory_type=SecureMemoryType.SHARED_MEMORY,
            read=True, write=True, execute=False,
            secure_only=False,  # Accessible from both worlds
        ))

    # -- Memory management --

    def add_memory_region(self, region: SecureMemoryRegion) -> None:
        self._memory_regions[region.name] = region

    def check_memory_access(self, address: int, access_type: str,
                            caller_world: World) -> Tuple[bool, str]:
        """
        Check if a memory access is allowed.

        Args:
            address: Physical address
            access_type: 'read', 'write', or 'execute'
            caller_world: World requesting access

        Returns:
            (allowed: bool, reason: str)
        """
        for name, region in self._memory_regions.items():
            if region.contains(address):
                # Check if secure-only region is accessed from Normal world
                if region.secure_only and caller_world == World.NORMAL:
                    self._log_violation(
                        f"Normal world access to secure region {name}",
                        address, access_type, caller_world
                    )
                    return False, f"DENIED: {name} is secure-only, access from {caller_world.value} world"

                # Check permissions
                if access_type == 'read' and not region.read:
                    return False, f"DENIED: {name} is not readable"
                if access_type == 'write' and not region.write:
                    return False, f"DENIED: {name} is not writable"
                if access_type == 'execute' and not region.execute:
                    return False, f"DENIED: {name} is not executable"

                return True, f"ALLOWED: {name} ({region.memory_type.value})"

        # Address not in any region - allow for Normal world memory
        return True, "ALLOWED: unmanaged memory region"

    def _log_violation(self, description: str, address: int,
                       access_type: str, world: World):
        self._security_violations.append({
            'description': description,
            'address': f"0x{address:016X}",
            'access_type': access_type,
            'world': world.value,
            'call_number': self._call_counter,
        })

    # -- SMC handling --

    def smc_call(self, function_id: int, args: Optional[List[int]] = None,
                 caller_world: World = World.NORMAL) -> SMCResponse:
        """
        Execute an SMC call.

        This simulates the world switch from Normal → Monitor → Secure → Monitor → Normal.
        """
        self._call_counter += 1
        request = SMCRequest(
            function_id=function_id,
            args=args or [],
            caller_world=caller_world,
        )

        # Log the call
        decoded = decode_smc_function_id(function_id)
        self._smc_log.append({
            'call_number': self._call_counter,
            'request': request.to_dict(),
            'decoded': decoded,
        })

        # Validate the call
        valid, reason = self._validate_smc_call(request)
        if not valid:
            response = SMCResponse(
                return_code=SMCReturnCode.DENIED,
                handler_world=World.MONITOR,
                handled=False,
            )
            self._smc_log[-1]['response'] = response.to_dict()
            self._smc_log[-1]['validation'] = reason
            return response

        # Dispatch to handler
        for handler in self._handlers:
            if handler.can_handle(function_id):
                # World switch: Normal → Monitor → Secure
                old_world = self._current_world
                self._current_world = World.MONITOR
                response = handler.handle(request)
                self._current_world = old_world

                self._smc_log[-1]['response'] = response.to_dict()
                self._smc_log[-1]['handler'] = handler.service_name
                return response

        # No handler found
        response = SMCResponse(
            return_code=SMCReturnCode.NOT_SUPPORTED,
            handler_world=World.MONITOR,
            handled=False,
        )
        self._smc_log[-1]['response'] = response.to_dict()
        return response

    def _validate_smc_call(self, request: SMCRequest) -> Tuple[bool, str]:
        """
        Validate an SMC call before dispatching.

        Checks:
        - Caller world permissions
        - Function ID format
        - Parameter validation
        """
        decoded = decode_smc_function_id(request.function_id)

        # Check: Normal world cannot make certain Secure Monitor calls
        if decoded['owner'] == SMCOwner.SECURE_MONITOR and request.caller_world == World.NORMAL:
            return False, "Normal world cannot call Secure Monitor functions directly"

        # Check: FastCall vs YieldingCall validation
        # (In simulation, we allow both)

        # Check: Valid function ID range
        if request.function_id == 0:
            return False, "Invalid function ID: 0x00000000"

        return True, "Valid"

    # -- World switching --

    def switch_world(self, target: World) -> World:
        """
        Simulate a world switch.

        Returns the previous world.
        """
        old = self._current_world
        self._current_world = target
        return old

    @property
    def current_world(self) -> World:
        return self._current_world

    # -- Status and logging --

    def get_smc_log(self) -> List[Dict[str, Any]]:
        return list(self._smc_log)

    def get_security_violations(self) -> List[Dict[str, Any]]:
        return list(self._security_violations)

    def get_memory_map(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._memory_regions.values()]

    def get_status(self) -> Dict[str, Any]:
        return {
            'current_world': self._current_world.value,
            'memory_regions': len(self._memory_regions),
            'handlers': len(self._handlers),
            'total_smc_calls': self._call_counter,
            'security_violations': len(self._security_violations),
        }

    def reset(self):
        """Reset simulator state."""
        self._current_world = World.NORMAL
        self._smc_log.clear()
        self._security_violations.clear()
        self._call_counter = 0


# ---------------------------------------------------------------------------
# Simulation helpers
# ---------------------------------------------------------------------------

def simulate_normal_world_operations(sim: TrustZoneSimulator) -> List[Dict]:
    """Simulate typical Normal world operations that trigger SMC calls."""
    results = []

    # 1. Query SMCCC version
    r = sim.smc_call(SMCFunction.SMC_VERSION)
    results.append({'operation': 'Query SMCCC Version', 'response': r.to_dict()})

    # 2. Query Trusted OS UID
    r = sim.smc_call(SMCFunction.SMC_STD_UID)
    results.append({'operation': 'Query Trusted OS UID', 'response': r.to_dict()})

    # 3. Query call count
    r = sim.smc_call(SMCFunction.SMC_STD_CALL_COUNT)
    results.append({'operation': 'Query Call Count', 'response': r.to_dict()})

    # 4. Try to access secure memory from Normal world
    allowed, reason = sim.check_memory_access(0xBE000100, 'read', World.NORMAL)
    results.append({'operation': 'Read TEE_RAM from Normal', 'allowed': allowed, 'reason': reason})

    # 5. Access shared memory from Normal world
    allowed, reason = sim.check_memory_access(0xFE000100, 'read', World.NORMAL)
    results.append({'operation': 'Read SharedMemory from Normal', 'allowed': allowed, 'reason': reason})

    # 6. Try a denied call
    r = sim.smc_call(0xFE000000)  # Secure Monitor call from Normal world
    results.append({'operation': 'Secure Monitor call from Normal', 'response': r.to_dict()})

    return results
