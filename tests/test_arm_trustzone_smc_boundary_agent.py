"""
Tests for ARM TrustZone SMC Boundary Simulator.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from simulator import (
    TrustZoneSimulator, World, SMCReturnCode, SMCOwner,
    SMCFunction, SecureMemoryType, SecureMemoryRegion,
    encode_smc_function_id, decode_smc_function_id,
    SMCRequest, SMCResponse, SMCHandler, ArchHandler, TrustedOSHandler,
    simulate_normal_world_operations,
)


# ---------------------------------------------------------------------------
# SMC Function ID encoding/decoding tests
# ---------------------------------------------------------------------------

class TestSMCFunctionID:
    def test_encode_fast_smc64(self):
        fid = encode_smc_function_id(fast_call=True, smc64=True, owner=0x32, func_num=0x01)
        assert fid & (1 << 31)  # FastCall bit set
        assert fid & (1 << 30)  # SMC64 bit set
        assert ((fid >> 24) & 0x3F) == 0x32  # Owner
        assert ((fid >> 16) & 0xFF) == 0x01  # Function

    def test_encode_yielding_smc32(self):
        fid = encode_smc_function_id(fast_call=False, smc64=False, owner=0x02, func_num=0x05)
        assert not (fid & (1 << 31))  # FastCall bit clear
        assert not (fid & (1 << 30))  # SMC64 bit clear
        assert ((fid >> 24) & 0x3F) == 0x02

    def test_decode_roundtrip(self):
        fid = encode_smc_function_id(True, True, 0x32, 0x10)
        decoded = decode_smc_function_id(fid)
        assert decoded['fast_call'] is True
        assert decoded['smc64'] is True
        assert decoded['owner'] == 0x32
        assert decoded['func_num'] == 0x10

    def test_decode_known_ids(self):
        d = decode_smc_function_id(SMCFunction.SMC_VERSION)
        assert d['fast_call'] is True
        assert d['smc64'] is False

    def test_decode_cpu_on(self):
        d = decode_smc_function_id(SMCFunction.SMC_CPU_ON)
        assert d['fast_call'] is True
        assert d['smc64'] is True


# ---------------------------------------------------------------------------
# SecureMemoryRegion tests
# ---------------------------------------------------------------------------

class TestSecureMemoryRegion:
    def test_contains(self):
        region = SecureMemoryRegion(
            name="test", base_address=0x1000, size=0x1000,
            memory_type=SecureMemoryType.TEE_RAM,
        )
        assert region.contains(0x1000) is True
        assert region.contains(0x1FFF) is True
        assert region.contains(0x2000) is False
        assert region.contains(0x0FFF) is False

    def test_to_dict(self):
        region = SecureMemoryRegion(
            name="test", base_address=0x1000, size=0x1000,
            memory_type=SecureMemoryType.TEE_RAM,
        )
        d = region.to_dict()
        assert d['name'] == 'test'
        assert 'permissions' in d


# ---------------------------------------------------------------------------
# SMCRequest / SMCResponse tests
# ---------------------------------------------------------------------------

class TestSMCDataClasses:
    def test_request_to_dict(self):
        req = SMCRequest(function_id=0x80000000, args=[1, 2, 3])
        d = req.to_dict()
        assert 'function_id' in d
        assert 'decoded' in d

    def test_response_to_dict(self):
        resp = SMCResponse(return_code=SMCReturnCode.SUCCESS, return_values=[42])
        d = resp.to_dict()
        assert d['return_code'] == 0
        assert d['return_code_name'] == 'SUCCESS'


# ---------------------------------------------------------------------------
# Handler tests
# ---------------------------------------------------------------------------

class TestHandlers:
    def test_arch_handler_version(self):
        handler = ArchHandler()
        req = SMCRequest(function_id=SMCFunction.SMC_VERSION)
        resp = handler.handle(req)
        assert resp.return_code == SMCReturnCode.SUCCESS
        assert resp.handled is True

    def test_arch_handler_unsupported(self):
        handler = ArchHandler()
        req = SMCRequest(function_id=0x00000001)
        resp = handler.handle(req)
        assert resp.return_code == SMCReturnCode.NOT_SUPPORTED

    def test_trusted_os_handler_uid(self):
        handler = TrustedOSHandler()
        req = SMCRequest(function_id=SMCFunction.SMC_STD_UID)
        resp = handler.handle(req)
        assert resp.return_code == SMCReturnCode.SUCCESS
        assert len(resp.return_values) == 4

    def test_trusted_os_handler_call_count(self):
        handler = TrustedOSHandler()
        req = SMCRequest(function_id=SMCFunction.SMC_STD_CALL_COUNT)
        resp = handler.handle(req)
        assert resp.return_code == SMCReturnCode.SUCCESS

    def test_handler_can_handle(self):
        arch = ArchHandler()
        assert arch.can_handle(SMCFunction.SMC_VERSION) is True
        assert arch.can_handle(SMCFunction.SMC_STD_UID) is False


# ---------------------------------------------------------------------------
# TrustZoneSimulator tests
# ---------------------------------------------------------------------------

class TestTrustZoneSimulator:
    def test_initial_state(self):
        sim = TrustZoneSimulator()
        assert sim.current_world == World.NORMAL
        status = sim.get_status()
        assert status['memory_regions'] >= 3
        assert status['total_smc_calls'] == 0

    def test_smc_call_version(self):
        sim = TrustZoneSimulator()
        resp = sim.smc_call(SMCFunction.SMC_VERSION)
        assert resp.return_code == SMCReturnCode.SUCCESS
        assert resp.handled is True

    def test_smc_call_uid(self):
        sim = TrustZoneSimulator()
        resp = sim.smc_call(SMCFunction.SMC_STD_UID)
        assert resp.return_code == SMCReturnCode.SUCCESS

    def test_smc_call_denied_from_normal(self):
        sim = TrustZoneSimulator()
        # Secure Monitor call from Normal world should be denied
        resp = sim.smc_call(0xFE000000, caller_world=World.NORMAL)
        assert resp.return_code == SMCReturnCode.DENIED

    def test_smc_call_not_supported(self):
        sim = TrustZoneSimulator()
        resp = sim.smc_call(0x00000001)
        assert resp.return_code == SMCReturnCode.NOT_SUPPORTED

    def test_memory_access_secure_region_from_normal(self):
        sim = TrustZoneSimulator()
        allowed, reason = sim.check_memory_access(0xBE000100, 'read', World.NORMAL)
        assert allowed is False
        assert 'secure' in reason.lower() or 'denied' in reason.lower()

    def test_memory_access_secure_region_from_secure(self):
        sim = TrustZoneSimulator()
        allowed, reason = sim.check_memory_access(0xBE000100, 'read', World.SECURE)
        assert allowed is True

    def test_memory_access_shared_from_normal(self):
        sim = TrustZoneSimulator()
        allowed, reason = sim.check_memory_access(0xFE000100, 'read', World.NORMAL)
        assert allowed is True

    def test_world_switch(self):
        sim = TrustZoneSimulator()
        old = sim.switch_world(World.SECURE)
        assert old == World.NORMAL
        assert sim.current_world == World.SECURE

    def test_smc_log(self):
        sim = TrustZoneSimulator()
        sim.smc_call(SMCFunction.SMC_VERSION)
        sim.smc_call(SMCFunction.SMC_STD_UID)
        log = sim.get_smc_log()
        assert len(log) == 2

    def test_security_violations(self):
        sim = TrustZoneSimulator()
        sim.check_memory_access(0xBE000100, 'read', World.NORMAL)
        violations = sim.get_security_violations()
        assert len(violations) == 1

    def test_memory_map(self):
        sim = TrustZoneSimulator()
        mmap = sim.get_memory_map()
        assert len(mmap) >= 3
        names = [r['name'] for r in mmap]
        assert 'TEE_RAM' in names
        assert 'SharedMemory' in names

    def test_reset(self):
        sim = TrustZoneSimulator()
        sim.smc_call(SMCFunction.SMC_VERSION)
        sim.reset()
        assert sim.get_status()['total_smc_calls'] == 0
        assert sim.current_world == World.NORMAL

    def test_add_custom_memory_region(self):
        sim = TrustZoneSimulator()
        sim.add_memory_region(SecureMemoryRegion(
            name="CustomRegion",
            base_address=0xD0000000,
            size=0x1000,
            memory_type=SecureMemoryType.SECURE_DEVICE,
        ))
        assert len(sim.get_memory_map()) >= 4


# ---------------------------------------------------------------------------
# Simulation helper tests
# ---------------------------------------------------------------------------

class TestSimulation:
    def test_simulate_normal_world_operations(self):
        sim = TrustZoneSimulator()
        results = simulate_normal_world_operations(sim)
        assert len(results) >= 5
        # Should have at least one denied access
        denied = [r for r in results if 'allowed' in r and not r['allowed']]
        assert len(denied) >= 1


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_smc_command(self):
        from cli import main
        ret = main(['smc', '0x80000000'])
        assert ret == 0

    def test_memory_command(self):
        from cli import main
        ret = main(['memory'])
        assert ret == 0

    def test_check_denied(self):
        from cli import main
        ret = main(['check', '--address', '0xBE000100', '--access', 'read'])
        assert ret == 1  # Should be denied from Normal world

    def test_check_allowed(self):
        from cli import main
        ret = main(['check', '--address', '0xBE000100', '--access', 'read', '--secure'])
        assert ret == 0

    def test_simulate_command(self):
        from cli import main
        ret = main(['simulate'])
        assert ret == 0

    def test_status_command(self):
        from cli import main
        ret = main(['status'])
        assert ret == 0

    def test_decode_command(self):
        from cli import main
        ret = main(['decode', '0x80000000'])
        assert ret == 0

    def test_encode_command(self):
        from cli import main
        ret = main(['encode', '--fast-call', '--owner', '50', '--func-num', '1'])
        assert ret == 0
