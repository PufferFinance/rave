// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import "src/RSA.sol";

contract TestModExp is Test {
    RSA c;

    function setUp() public {
        c = new RSA();
    }

    // test vector from https://github.com/ethereum/EIPs/blob/master/EIPS/eip-198.md
    function testVector() public {
        bytes memory base = hex"03";
        bytes memory exp = hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
        bytes memory mod = hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

        bytes memory got = c.modExp(base, exp, mod);
        bytes memory expected = hex"0000000000000000000000000000000000000000000000000000000000000001";

        assertEq(keccak256(expected), keccak256(got), "ok");
    }

    function testFFI() public {
        string[] memory cmds = new string[](5);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runModExp.py";
        bytes memory base = new bytes(512);
        base[0] = hex"02";
        bytes memory exp = new bytes(512);
        exp[0] = hex"05";
        bytes memory mod = new bytes(512);
        mod[0] = hex"11";
        cmds[2] = vm.toString(base);
        cmds[3] = vm.toString(exp);
        cmds[4] = vm.toString(mod);

        bytes memory resp = vm.ffi(cmds);
        bytes memory got = c.modExp(base, exp, mod);

        console.logBytes(resp);
        console.logBytes(got);

        // 2**5 % 17 = 15
        assertEq(keccak256(abi.encode(resp)), keccak256(abi.encode(got)));
        assertEq(resp, got);
    }

    function testModExpFuzz(bytes memory _base, bytes memory _exp, bytes memory _mod) public {
        console.logBytes(_base);
        console.logBytes(_exp);
        console.logBytes(_mod);
        vm.assume(_base.length > 1);
        vm.assume(_exp.length > 1);
        vm.assume(_mod.length > 1);
        // vm.assume(vm.parseUint(vm.toString(_base)) > 0);
        // vm.assume(vm.parseUint(vm.toString(_exp)) > 0);
        // vm.assume(vm.parseUint(vm.toString(_mod)) > 0);
        vm.assume(_mod.length == _base.length);
        vm.assume(_mod.length == _exp.length);
        vm.assume(_base.length == _exp.length);

        string[] memory cmds = new string[](5);
        cmds[0] = "python3";
        cmds[1] = "test/scripts/runModExp.py";
        cmds[2] = vm.toString(_base);
        cmds[3] = vm.toString(_exp);
        cmds[4] = vm.toString(_mod);

        bytes memory got = c.modExp(_base, _exp, _mod);
        console.logBytes(got);
        console.log("got len: %s", got.length);

        bytes memory resp = vm.ffi(cmds);
        console.logBytes(resp);
        console.log("resp len: %s", resp.length);

        assertEq(keccak256(resp), keccak256((got)));
        assertEq(resp, got);
    }
}
