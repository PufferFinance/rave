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

    function testVerifyRSA256b() public {
        bytes memory _sig = hex"57306b21925c4f51f9ea5109e79892f8f599e55d15207aaa8504f2f5184d8c3c";
        bytes memory _pubKey = hex"95dcdfc3b42b1c55cff71501870540793855c054354ef4d2e55fb462d648f0af";
        bytes memory _msg =
            hex"9142b53464ea3543c71cf74de645f98197562edb9a064df5d6794876912fa2a9360589e3bd6163374d6108217dfd42f68725b367bb020d0ab4ade77262498ba3b80be1611d7fae308a2ec1c80b39e7487307fe6d9a2c695fb06e135a43ef65b42ec7a9e12e3343dca067fe57c1f0ab826d149c99909a7519014c17ca93492a09";
        bytes32 _msgHash = hex"54393031ccd25d810022d0a0a4c36aac7b0d19a9340b75358fbe09e6ab1b893c";

        assertEq(keccak256(_msg), _msgHash);

        bool got = c.verifyRSA(_sig, _pubKey, _msgHash);
        assert(got);
    }

    function testVerifyRSA4096b() public {
        bytes memory _sig =
            hex"37fff20a08cfac0bd4f3ba55d1a5c4b6b0289520dcd19b20a815b1417da020d741f58005653a23826d296d872fd198c226d0fd0adefa87ea4b0487eba21a516d9038a98efaca0195df8181bf95dfc2e726537183e60e64d2572f95a51c11b53b5a0bbc0503d0112b1c1289cc4340d73ec5ed8681c59014b4a4a160fa21e61b510e22cddcb0dccc1e2dc53b523fe203b9111d49ecf0f91ea94f16db1f8dcc95e14b899ff038f6eee675a7f1a9bf18531796f35859ecd96444015fe184d110a2e873cf99fb38ba59a6edd3d2b202d532e5e33e3df5334a5ba913f69eb809ea1454cd40c5c663e8e13640b57952bc40e9b4e488d4fa78b97c879a33feb4967f980663ccf0fb1d287b0736b8f3c6bd6709daeafae4778c1065cae4afe6d2ecccb288883f3af1cb576cac9ef21a3e8ee1f293ef660b35c0f781545af4246eccc940266ff4260a4470f7047e4a675fa21554c65dba2a3c4b3572b5cac1365491b384ada4659d3dfda9b534aed6de25e9f27778eed6dbdbba26b30b6fccafb152861bee173d82e8c9f9230c822284f9948dcab0761699f2f8e0ec8ec130524638922c4b22d85dc7ff9da6187ea2c0d66b7f9f5780d2b1e1c84966aeb900fbb9820040a382c19d76e2ba45f1920405be90db61170f09b03d0acbf9a8b41ec9b55585577054d8c43cb03623fab67fac3b950d7d2592ab18342d70caa9b981c76574df2f46";
        bytes memory _pubKey =
            hex"c3ae001afac8462d225941efa33561b5c5dc535be010ac4289b9489f0c7a22daba34a42b73c0691b8b3134baee3480241adb6bea9c9801b6b812cc11314596a1672e68185a63eba2846f2060db5e87289877350dbc18d01f5a262ffd40eaba25f466b4bdd0d4f6094fd4fb0c104722475fb9c4aa51d84b62315447e9ba6c83acc7aabde09ce583140d7ad32c53f02bc97e7c6b195bf53146dda29c301e5bef7b8d85d2c9fe864863e47cc63499d6c4f0ecd470924a3d19121adc5ae312ca9b2ad69b1fb05fdfc0024644325e9d63ccc248c23ff3754edf3953766ad56b1f037b8371b5df85315ef82bf686eeaf905564f5db8fbe4bc1aeba4fd5bea1843231b907883d7f2e02eff0b1b24c3fcce9938b6fb3fa3d23d1117ce1e65ad2bee7c4f4d347dcb9baee25de0b1bcebe8a9c19969b57da362dd0cda98372e36c53cebf58b80c5bff7b97a08101358e174e9c2252baff38e73bc2ba533e67ca93827315d33fd5dd2e8bf4c7b2f7d40201a1f1b934954c3ccee3792938e39c6a0e7f6d5ceef56bbe0b0d9e768a0bcdaa9821fa9715b17b01d2fcf1f0b50e7bc186ca4aa9200099d55a78d3dba29ba3ee8a88c1505f63a143e807f65857c4e88242d8819d5db8e1fbaee4954bb9c950c0218a9298272f39097e2e294e1cbfb7ad01b80cd3b98bd8871bfee55c9a32ec31467a41ca3d3f41f2b19901cd8de5102219da0513a1";
        bytes memory _msg =
            hex"8e7cf9e9b0a49a9b8995a0088b1a8b1d117aec67b86cb14b77c0d222e368fa1c0c54aeafa1cba35776ff490b2efcf00e14c99cef968b148e5b5ddc252d393afbb9b144cf18c9f377ee98a9568b2cf0ddbea21b0e7ded747d9877bdfa510e00b98b207eb3dec6fc1a700ade6f6c2180f3a56d59994bbb3a5d13e1496a46072f5364c7aaf771cbc94a34e6b9ce2954ffe81a1611ae4c5566834a3ebf9cdd4675f8525e3d3eeea6d7d9903c61404c86ee2c26dd295467f07ef7ae8fb0a10546378ac445f6634954644d7321219eca49ea643f1f279971c0b4359df68571bf9016b086e2c5d05deb96b829c117bd26419e7d64ecd7f4a8c165ce46bef2bb89ead46613a7bc7868d28d05faadd6ebeac670be9938bbf88367954cc2123a7f8783fed701a11f9917b0aedbf71c20f71a6baefa7168473b44a3194111624ba63aafd0f7700960e1c9b46770e6cedc1113cd9b8e190b023bb5ff999fabc1dc2fb8b4fe815b9224ca4fa88df3ff313298dea337785492030e1c8666431ae363056cd70f1d16d1b14e41699f0dfc819e24fa3c50fe8510a966be680bf44b1a562898aaaa44b8d288d828ec0b8f2d12d784d22eaf72bbca47f704b9fcb3d3eda6f0ab736f87dc505f4b68cf3f6f047822e38ac57e50ef1f7688cfe074fa5533bbb24e954b0ce4ee5b9405df99bcb37de5aa28194702b27dff10871645965c827b2dd6621e77662889bb21beac1f7c0cd73d305a339006127047e6f2d23550ced5cc04237b4b915ad8bd06e9f1569086c40cf90630607bd710a8c8c8afd241903ed86d92f1c68c4ff009bcf1d631ef1d6c30811594d8e20f034884e7346eb9c902fc15fcae25026c9440aaba2e8915e10d148c2ade73fec4c43734bc5849aae6ee5d24978e4ee69f8ac308992af82898562122699c4bafddc6aa8b417fdba806b03a511ac0ac19733afec9026c7ef80dbdb7ffd6d36ebb948081a6de8ee49d4633c78e1a821f68f56bd4b737219a87dfc041125d8c01894b153a36b1dd0e67cc1666b33d8d3a689c17bc05ffc27b4ff6e91239b9dc44bd892e5b43d54169824296ca790502d44ddb7510252c74d6f4d2a050aba05bfedab7d346c9cb37afb57ff81a700f0f6cf5503d460a4049b4605403faecabd467208f1909dd6ea61be1e5d8db14cb7d29b5db7e122401e8e3e4b88412ab6c3303583173d04ed2776e55ea1c66107c2898cb0cb781290e5755285ff9d888806b432470c48431717bc1eb2c91c017ff5cdf7228bffb333e2bf552df96af396a8014a3d3e45b7328a1f2913e910df85443c9da9f5f0aebf46dffe0231a5650ea2feeaf65a9884cf22911d1b9d855c75c93666d2c34cb38e944fbc950c937caa1a59d5fd9fcbd3188c9ae49bc95adcbd36f9699d2d85111b38802cc61438e121ad0a5674e6c5d6e284ea92dceaf01c2634e642ca95bd431c450f0475b0505258d91ea70c2be1605cb834e9384ae503ce54a222e4a82415c04a8f20f8688afea12d9df2deb364c815201085a091fd1d9a0d796bf563bde5ddc951a02c16d85f014e101bb070c5adf044bbabb2e3fe1eb09e5ee0fdb6a620884739a171dadfe2127408b8a5c3cccb4616c7f9c5721f855e977533e0e4d3c660787c80b9153ce3c4e011d25a9847c0eab6b83076dcf5b3e371b6064979c2b62e6db769db0a1a733799f09f99c0915b82fe3b495eca7a22b8ffb3fff61283afb3a5584e9d03e1331a9a93ad7b82ac4891f371ad15038fe6e12862fe65788346fc795b55ae4d0a2eb930317bda5a3f1b27bee8eb906bd8b1ad59ff93e59b1db83ad85d4f063692653db1b9ea804ab86b19a6bc27ecaeedda76325115c53c80b9ee4a40527ff07ae9e3b945d7c9e51500d4bafe384034d28ffe6c940a93611d85d5be72f3a5feed8ce14750fda33552c2b4a7e904e35f7da18e9461ae7c43bcd53a7b95bf56f9f1e2e9e7016e644ad35e011d0862f67034a667f6d92e820914edb1a967d48aae90aa03cab80a77b4920dce14205f50a4a3223b547219f0f272d800d7c4bc605a3e7992d9edd606e8a4fbd9ce8141558d2ef702504d6b9dd3c9c9fe048d3fac17367d9ceb2fd8c2fb6760496504e455b59d0ece931195360ace73df78c3210a02626bc34680833ad5bdb639c018b17a825fce0075c720b19918a95fc0c5475442a28f9756d8b458a5e0faa078674b58b3f6bf5a1a313e86f8897b0eb7bcc8944bf9b156e058d392d2ed6de4fca4d01924d56a76f9d8c1ce93a25204e31a6392ccb496864fc42f6541ee4373b725fa9fc69c864305be8e1242ed676af240ddffc6ac061bddb6a75956da670868078a6fa6b4aa4bf4fd53074e3f4f65ea012e32d1d70e60aa4b37840d9b72be076c646c461b79393b60925d09f5fdafee63b99b86ae20de020cd3f40bfe9b8d18a602bd850a89471d4128fb3617a99c9085c4bd68e93fcd811b61c03d5addadaab5f94e5831f917b437e9046c2e96c7f7312fe4307469fe0e30f01d7641f8dd2ed61342f395e8a2b4d59947569130aa609aab416ec4d7042dfecab31185319fe8f89ce6eb9d3ccbb02c1fb9ad7a4f9bfa824a63fcede124e4c9b7e14cf2e1dc3d89850f795b61f3fba7f5b32d5a810902176686e8352dc6a0f86366b1166ed88414f0d7efa1686b84d0b6b7af63565c5ed62f339f9bf89ba89a27f841097043ca66b268b3132744f588922b39147fb58280296354caa081e161779d32c90037fb5c43806c4a4c413b0990c0ed85fe6d4c5fb30afd7a6cad530304ae69703d59fc6acc20b88b4e192dbbb57a53d04f010f7e5c32622e724765378296eea1c0ddad67891955e9150a96d22d1282763e99e2899cc6532cc945439ea993a18a09f8640f8b7d0a48cc3523392";
        bytes32 _msgHash = hex"46e0a38174575660080b384ee27ce9fc29538ce6c5c162b455c4ddf9dea5c62b";

        assertEq(keccak256(_msg), _msgHash, "hash not matching");

        bool got = c.verifyRSA(_sig, _pubKey, _msgHash);
        assert(got);
    }
}
