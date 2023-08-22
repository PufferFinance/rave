// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0 <0.9.0;

import { Test, console } from "forge-std/Test.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Utils } from "rave/Utils.sol";
import { NodePtr, Asn1Decode } from "rave/ASN1Decode.sol";

contract TestASN1 is Test {

    using Asn1Decode for bytes;
    using BytesUtils for bytes;
    using Utils for bytes;
    using NodePtr for uint256;

    bytes cert = hex"308204a130820309a003020102020900d107765d32a3b096300d06092a864886f70d01010b0500307e310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341301e170d3136313132323039333635385a170d3236313132303039333635385a307b310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051864f687474703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f72745369676e696e6743412e63726c300d06092a864886f70d01010b050003820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";

    constructor() { }

    /*
    function testASN1RootOverflow() public {
        bytes memory bugCert = bytes(cert);
        
        // Max certificate length portion.
        bugCert[1] = hex"02";
        bugCert[2] = hex"99";
        bugCert[3] = hex"99";

        //  [1] len bytes length?

        // Attempt to load the 'root node' of the cert.
        uint256 rootPtr = bugCert.root();
        bugCert.firstChildOf(rootPtr);

        test read uint, u16, readn overflow.

        todo test: isChildOf, nextSiblingOf, firstChildOf
    }
    */

    function testANS1RootOctetStringAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"040402990133";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.rootOfOctetStringAt(ptr);
    }

    function testANS1RootOctetStringAtSuccess() public {
        bytes memory buf = hex"040402020133";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.rootOfOctetStringAt(ptr);
    }

    function testANS1RootOfBitStringAtOverflow() public {
        vm.expectRevert();

        // len -> 3 -> +1 = len ->     4
        bytes memory buf = hex"030400009933";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.rootOfBitStringAt(ptr);
    }

    function testANS1RootOfBitStringAtSuccess() public {
        bytes memory buf = hex"030402020133";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.rootOfBitStringAt(ptr);
    }

    function testANS1BytesAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.bytesAt(ptr);
    }

    function testANS1BytesAtSuccess() public {
        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.bytesAt(ptr);
    }

    function testANS1AllBytesAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.allBytesAt(ptr);
    }

    function testANS1AllBytesAtSuccess() public {
        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.allBytesAt(ptr);
    }

    function testANS1Bytes32AtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.bytes32At(ptr);
    }

    function testANS1Bytes32AtSuccess() public {
        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.bytes32At(ptr);
    }

    function testANS1UintAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.uintAt(ptr);
    }

    function testANS1UintAtSuccess() public {
        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.uintAt(ptr);
    }

    function testANS1UintBytesAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.uintBytesAt(ptr);
    }

    function testANS1UintBytesAtSuccess() public {
        bytes memory buf = hex"020400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.uintBytesAt(ptr);
    }

    function testANS1KeccakBytesAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.keccakOfBytesAt(ptr);
    }

    function testANS1KeccakBytesAtSuccess() public {
        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.keccakOfBytesAt(ptr);
    }

    function testANS1KeccakAllAtOverflow() public {
        vm.expectRevert();

        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.keccakOfAllBytesAt(ptr);
    }

    function testANS1KeccakAllAtSuccess() public {
        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.keccakOfAllBytesAt(ptr);
    }

    function testANS1BitStrAtOverflow() public {
        vm.expectRevert();

        // High order len bit is set
        // which triggers else in readNodeLen
        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 200, 200);
        buf.bitstringAt(ptr);
    }

    function testANS1BitStrAtSuccess() public {
        // High order len bit is set
        // which triggers else in readNodeLen
        bytes memory buf = hex"030400112233";
        uint256 ptr = NodePtr.getPtr(0, 2, 5);
        buf.bitstringAt(ptr);
    }

    function testASN1RootOverflowIf() public {
        vm.expectRevert();

        // High order len bit is set
        // which triggers else in readNodeLen
        bytes memory buf = hex"0281";
        buf.root();
    }

    function testASN1RootOverflowElseIf() public {
        vm.expectRevert();

        // High order len bit is not set
        // which triggers else, if in readNodeLen
        bytes memory buf = hex"0201";
        buf.root();
    }

    function testASN1RootOverflowElseElIf() public {
        vm.expectRevert();

        // High order len bit is not set
        // which triggers else, if in readNodeLen
        bytes memory buf = hex"0202";
        buf.root();
    }

    function testASN1RootOverflowElseElse() public {
        vm.expectRevert();

        // High order len bit is not set
        // which triggers else, if in readNodeLen
        bytes memory buf = hex"0203";
        buf.root();
    }

    function testASN1Uint8Overflow() public {
        vm.expectRevert();
        bytes memory buf = hex"029901";

        uint256 rootPtr = buf.root();
        buf.uintAt(rootPtr);
    }

    function testASN1IntegerOverflow() public {
        vm.expectRevert();

        // 02 (type = INTEGER)
        // 99 (len = OVERFLOW)
        // ... actual buffer to traverse
        bytes memory x = hex"0299010010";

        uint256 rootPtr = x.root();
        uint256 out = x.uintAt(rootPtr);
        console.log(out);
    }

    function testASN1RootSuccessChances() public {
        // if, len = 1, buf 1
        bytes memory a = hex"02010101";
        a.root();

        // if:if, len 1, buf 1
        bytes memory b = hex"02810101";
        b.root();

        // if:elseif, len 1 (2 bytes), buf 1
        bytes memory c = hex"0282000101";
        c.root();

        // if:..else var len 1 (3 bytes), buf 1
        bytes memory d = hex"028300000101";
        d.root();
    }
}

/*

TODO: check for x509 hdr byte sequence

https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

3082
30 SEQUENCE
82 extended byte for tag data?
len

The length of any DER field can be expressed as a series of up to 126 bytes. So the biggest INTEGER you can represent in DER is 256(2**1008)-1. For a truly unbounded INTEGER you’d have to encode in BER, which allows indefinitely-long fields.


*/
