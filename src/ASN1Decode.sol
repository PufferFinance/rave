// SPDX-License-Identifier: MIT
// Original source: https://github.com/JonahGroendal/asn1-decode
pragma solidity >=0.8.0 <0.9.0;

import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Math } from "openzeppelin-contracts/contracts/utils/math/Math.sol";

library NodePtr {
    uint80 constant MAX_UNIT80 = 1208925819614629174706175;

    // Unpack first byte index
    function type_index(uint256 self) internal pure returns (uint256) {
        return uint80(self);
    }

    // Unpack first content byte index
    function content_index(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 80);
    }

    // Unpack last content byte index
    function end_index(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 160);
    }

    function content_len(uint256 self) public pure returns (uint256) {
        return (end_index(self) - content_index(self)) + 1;
    }

    // Pack 3 uint80s into a uint256
    function getPtr(uint256 _type_index, uint256 _content_index, uint256 _end_index) internal pure returns (uint256) {
        // This prevents overflowing the individual bit fields.
        require(_type_index <= MAX_UNIT80);
        require(_content_index <= MAX_UNIT80);
        require(_end_index <= MAX_UNIT80);

        // Bit shift fields into correct segements.
        _type_index |= _content_index << 80;
        _type_index |= _end_index << 160;
        return _type_index;
    }

    function overflowCheck(uint256 self, uint256 len) internal pure {
        require(type_index(self) < uint256(len));
        require(content_index(self) < uint256(len));
        require(end_index(self) < uint256(len));
    }
}

library Asn1Decode {
    using NodePtr for uint256;
    using BytesUtils for bytes;

    /*
    * @dev Get the root node. First step in traversing an ASN1 structure
    * @param der The DER-encoded ASN1 structure
    * @return A pointer to the outermost node
    */
    function root(bytes memory der) internal pure returns (uint256) {
        // seq byte (30)
        // len pt 1 (x)
        // len pt 2 (optional)
        // ... contentbytes (1 or more) ...
        // minimum sanity check
        // Not the only length check.
        require(der.length >= 3);
        return readNodeLength(der, 0);
    }

    /*
    * @dev Get the root node of an ASN1 structure that's within a bit string value
    * @param der The DER-encoded ASN1 structure
    * @return A pointer to the outermost node
    */
    function rootOfBitStringAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        ptr.overflowCheck(der.length);
        require(der[ptr.type_index()] == 0x03, "Not type BIT STRING");

        // Not sure if the '+1' is right but overflow is checked for.
        uint256 len = ptr.content_index() + 1;
        require(len < der.length);

        return readNodeLength(der, len);
    }

    /*
    * @dev Get the root node of an ASN1 structure that's within an octet string value
    * @param der The DER-encoded ASN1 structure
    * @return A pointer to the outermost node
    */
    function rootOfOctetStringAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        ptr.overflowCheck(der.length);
        require(der[ptr.type_index()] == 0x04, "Not type OCTET STRING");
        return readNodeLength(der, ptr.content_index());
    }

    /*
    * @dev Get the next sibling node
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return A pointer to the next sibling node
    */
    function nextSiblingOf(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        ptr.overflowCheck(der.length);
        uint256 index = (ptr.end_index() + 1);
        require(index < der.length);
        return readNodeLength(der, index);
    }

    /*
    * @dev Get the first child node of the current node
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return A pointer to the first child node
    */
    function firstChildOf(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        ptr.overflowCheck(der.length);
        require(der[ptr.type_index()] & 0x20 == 0x20, "Not a constructed type");
        return readNodeLength(der, ptr.content_index());
    }

    /*
    * @dev Use for looping through children of a node (either i or j).
    * @param i Pointer to an ASN1 node
    * @param j Pointer to another ASN1 node of the same ASN1 structure
    * @return True iff j is child of i or i is child of j.
    */
    function isChildOf(uint256 i, uint256 j) internal pure returns (bool) {
        return (
            (
                (i.content_index() <= j.type_index()) && 
                (j.end_index() <= i.end_index())
            ) || 
            (
                (j.content_index() <= i.type_index()) &&
                (i.end_index() <= j.end_index())
            )
        );
    }

    /*
    * @dev Extract value of node from DER-encoded structure
    * @param der The der-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Value bytes of node
    */
    function bytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        ptr.overflowCheck(der.length);
        return der.substring(ptr.content_index(), ptr.content_len());
    }

    /*
    * @dev Extract entire node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return All bytes of node
    */
    function allBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        ptr.overflowCheck(der.length);
        return der.substring(ptr.type_index(), ptr.content_len());
    }

    /*
    * @dev Extract value of node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Value bytes of node as bytes32
    */
    function bytes32At(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        ptr.overflowCheck(der.length);
        require(ptr.content_len() <= 32);
        return der.readBytesN(ptr.content_index(), ptr.content_len());
    }

    /*
    * @dev Extract value of node from DER-encoded structure
    * @param der The der-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Uint value of node
    */
    function uintAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        ptr.overflowCheck(der.length);
        require(der[ptr.type_index()] == 0x02, "Not type INTEGER");
        require(der[ptr.content_index()] & 0x80 == 0, "Not positive");
        uint256 len = ptr.content_len();

        require(len <= 32);
        return uint256(
            der.readBytesN(ptr.content_index(), len) >> 
            ((32 - len) * 8)
        );
    }

    /*
    * @dev Extract value of a positive integer node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Value bytes of a positive integer node
    */
    function uintBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        ptr.overflowCheck(der.length);
        require(der[ptr.type_index()] == 0x02, "Not type INTEGER");
        require(der[ptr.content_index()] & 0x80 == 0, "Not positive");
        uint256 valueLength = ptr.content_len();
        return der.substring(ptr.content_index(), ptr.content_len());

        // This seems invalid.
        if (der[ptr.content_index()] == 0) {
            return der.substring(ptr.content_index() + 1, valueLength - 1);
        } else {
            return der.substring(ptr.content_index(), valueLength);
        }
    }

    function keccakOfBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        ptr.overflowCheck(der.length);
        return der.keccak(ptr.content_index(), ptr.content_len());
    }

    function keccakOfAllBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        ptr.overflowCheck(der.length);
        return der.keccak(ptr.type_index(), ptr.content_len());
    }

    /*
    * @dev Extract value of bitstring node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Value of bitstring converted to bytes
    */
    function bitstringAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        ptr.overflowCheck(der.length);

        // Check type is bitstring.
        require(der[ptr.type_index()] == 0x03, "Not type BIT STRING");
        // Only 00 padded bitstr can be converted to bytestr!
        require(der[ptr.content_index()] == 0x00);

        // Return the segment and avoid overflows.
        uint256 valueLength = ptr.end_index() + 1 - ptr.content_index();
        require(valueLength > 0);
        require(ptr.content_index() + 1 < der.length);
        require(valueLength - 1 < der.length);
        return der.substring(ptr.content_index() + 1, valueLength - 1);
    }

    function readNodeLength(bytes memory der, uint256 ix) private pure returns (uint256) {
        // Avoid overflow for first len byte.
        require((ix + 1) < der.length);

        // Reject multi-byte identifiers.
        require((der[ix] & 0x1F) != 0x1F);

        // Read length of a DER segment.
        uint256 length = 0;
        uint80 ixFirstContentByte = 0;
        uint80 ixLastContentByte = 0;
        if ((der[ix + 1] & 0x80) == 0) {
            length = Math.max(uint8(der[ix + 1]), 1);
            ixFirstContentByte = uint80(ix + 2);
            ixLastContentByte = uint80(ixFirstContentByte + (length - 1));
        } else {
            // How large is the length field?
            uint8 lengthbytesLength = uint8(der[ix + 1] & 0x7F);

            // Avoid overflow.
            require((ix + 2) < der.length);
            if (lengthbytesLength == 1) {
                length = der.readUint8(ix + 2);
            } else if (lengthbytesLength == 2) {
                require((der.length - (ix + 2)) >= 2);
                length = der.readUint16(ix + 2);
            } else {
                // Ensure enough bytes left for len no.
                require((der.length - (ix + 2)) >= lengthbytesLength);
                require(lengthbytesLength <= 32);

                // Read variable length len field.
                // Shift out the bit length of the length.
                // Max shift is limited to sizeof length.
                // But zero is still checked for bellow.
                length = uint256(der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8);
            }

            // Content length field must be positive.
            require(length > 0);
            ixFirstContentByte = uint80(ix + 2 + lengthbytesLength);
            ixLastContentByte = uint80(ixFirstContentByte + (length - 1));
        }

        // Sanity checks for ptrs.
        require(ixFirstContentByte >= 2);
        require(ixLastContentByte >= 2);

        // The expected content segment must not overflow.
        require(ixFirstContentByte < der.length);
        require(ixLastContentByte < der.length);

        // Return the nodeptr structure.
        return NodePtr.getPtr(ix, ixFirstContentByte, ixLastContentByte);
    }
}
