// SPDX-License-Identifier: MIT
// Original source: https://github.com/JonahGroendal/asn1-decode
pragma solidity >=0.8.0 <0.9.0;

import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Math } from "openzeppelin-contracts/contracts/utils/math/Math.sol";

library NodePtr {
    uint80 constant MAX_UNIT80 = 1208925819614629174706175;
    uint256 constant ZERO_LEN = 0;

    // Unpack first byte index
    function type_index(uint256 self) internal pure returns (uint256) {
        return uint80(self);
    }

    // Unpack first content byte index
    function content_index(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 80);
    }

    // Points to the end of the DER segement.
    // Not necessarily the end of the content segment as
    // empty content segements are valid in DER.
    function end_index(uint256 self) internal pure returns (uint256) {
        return uint80(self >> 160);
    }

    function content_len(uint256 self) public pure returns (uint256) {
        if(content_index(self) == 0) {
            return 0;
        }
        else {
            return (end_index(self) - content_index(self)) + 1;
        }
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
        return readNodeLength(der, ptr.content_index() + 1);
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
        if(ptr.content_len() == 0)
        {
            revert();
        }
        else
        {
            return readNodeLength(der, ptr.content_index());
        } 
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
        if(ptr.content_len() >= 1) {
            return der.substring(
                ptr.content_index(),
                ptr.content_len()
            );
        }
        revert();
    }

    /*
    * @dev Extract entire node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return All bytes of node
    */
    function allBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        ptr.overflowCheck(der.length);
        if(ptr.content_len() >= 1) {
            uint256 len = (ptr.end_index() - ptr.type_index()) + 1;
            require(ptr.type_index() + len <= der.length);
            return der.substring(ptr.type_index(), len);
        }
        revert();
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

        if(ptr.content_len() >= 1) {
            return der.readBytesN(ptr.content_index(), ptr.content_len());
        }
        revert();
    }

    /*
    * @dev Extract value of node from DER-encoded structure
    * @param der The der-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Uint value of node
    */
    function uintAt(bytes memory der, uint256 ptr) internal pure returns (uint256) {
        // Sanity checks for pointer fields.
        ptr.overflowCheck(der.length);

        // Check field types and value.
        require(der[ptr.type_index()] == 0x02, "Not type INTEGER");
        if(ptr.content_len() >= 1) {
            // Ensure unsigned int.
            require(der[ptr.content_index()] & 0x80 == 0, "Not positive");

            // Specify bytes to read.
            uint256 len = ptr.content_len();
            require(len <= 32);

            // Read N bytes into uint field.
            return uint256(
                der.readBytesN(ptr.content_index(), len) >> 
                ((32 - len) * 8)
            );
        }
        revert();
    }

    /*
    * @dev Extract value of a positive integer node from DER-encoded structure
    * @param der The DER-encoded ASN1 structure
    * @param ptr Points to the indices of the current node
    * @return Value bytes of a positive integer node
    */
    function uintBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes memory) {
        // Sanity check on pointer.
        ptr.overflowCheck(der.length);

        // Only if content segment present.
        if(ptr.content_len() >= 1) {
            // Number must be a positive number.
            require(der[ptr.type_index()] == 0x02, "Not type INTEGER");
            require(der[ptr.content_index()] & 0x80 == 0, "Not positive");

            // Read bytes at offset.
            return der.substring(ptr.content_index(), ptr.content_len());
        }
        revert();

        // This seems invalid.
        /*
        uint256 valueLength = ptr.content_len();
        if (der[ptr.content_index()] == 0) {
            return der.substring(ptr.content_index() + 1, valueLength - 1);
        } else {
            return der.substring(ptr.content_index(), valueLength);
        }
        */
    }

    function keccakOfBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        ptr.overflowCheck(der.length);
        if(ptr.content_len() >= 1) {
            return der.keccak(ptr.content_index(), ptr.content_len());
        }
        revert();
    }

    function keccakOfAllBytesAt(bytes memory der, uint256 ptr) internal pure returns (bytes32) {
        ptr.overflowCheck(der.length);
        if(ptr.content_len() >= 1) {
            uint256 len = (ptr.end_index() - ptr.type_index()) + 1;
            require(ptr.type_index() + len <= der.length);
            return der.keccak(ptr.type_index(), len);
        }
        revert();
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

        // Only attempt to read if content set.
        if(ptr.content_len() >= 1) {
            // Only 00 padded bitstr can be converted to bytestr!
            require(der[ptr.content_index()] == 0x00);

            // Return the segment and avoid overflows.
            uint256 start_index = ptr.content_index() + 1;
            uint256 valueLength = (ptr.end_index() - ptr.content_index());
            require(start_index < der.length);
            require(start_index + valueLength <= der.length);
            return der.substring(start_index, valueLength);
        }
        revert();
    }

    /*
        A DER field looks like:

type, (opt type) (len or len flag) (opt len ... N) (opt buf .. N)

- Possibility for: one or two-byte type field.
- Possible:
    - one byte len field.
    - two byte len field.
    - len info field followed by:
        - variable length len field.
- Possible:
    - variable length buffer
    - or nothing

        This function returns a NodePtr indexing these fields.
        If the buffer (or content) section is empty then
        ptr.content_len() == 0 and ptr.content_index() == 0.

        The ptr.end_index() always points to the last byte of
        the segment which may be a length field (if there's no
        content portion) or the last content byte (if there's
        a content / buffer portion set for it.)

    */
    function readNodeLength(bytes memory der, uint256 ix) private pure returns (uint256) {
        // Avoid overflow for first len byte.
        require((ix + 1) < der.length);

        // Reject multi-byte identifiers.
        require((der[ix] & 0x1F) != 0x1F);

        // Read length of a DER segment.
        uint256 length = 0;
        uint80 ixFirstContentByte = 0;
        uint80 ixLastContentByte = uint80(ix + 1);
        if ((der[ix + 1] & 0x80) == 0) {
            length = uint8(der[ix + 1]);
            if(length >= 1)
            {
                ixFirstContentByte = uint80(ix + 2);
                ixLastContentByte += uint80(length);
            }
        } else {
            // How large is the length field?
            uint8 lengthbytesLength = uint8(der[ix + 1] & 0x7F);

            // Avoid overflow.
            require((ix + 2 + lengthbytesLength) < der.length);
            if (lengthbytesLength == 1) {
                length = der.readUint8(ix + 2);
            } else if (lengthbytesLength == 2) {
                require(ix + 3 < der.length);
                length = der.readUint16(ix + 2);
            } else {
                // Ensure enough bytes left for len no.
                require(ix + 2 + lengthbytesLength <= der.length);
                require(lengthbytesLength <= 32);

                // Read variable length len field.
                // Shift out the bit length of the length.
                // Max shift is limited to sizeof length.
                // But zero is still checked for bellow.
                length = uint256(der.readBytesN(ix + 2, lengthbytesLength) >> (32 - lengthbytesLength) * 8);
            }

            // Content length field must be positive.
            ixLastContentByte += uint80(lengthbytesLength);
            if(length >= 1)
            {
                ixFirstContentByte = uint80(ix + 2 + lengthbytesLength);
                ixLastContentByte += uint80(length);
            }
        }

        // The expected content segment must not overflow.
        require(ixFirstContentByte < der.length);
        require(ixLastContentByte < der.length);
        require(ixLastContentByte > 0);

        // If the end pointer value is less than start then
        // it may lead to an underflow and this is
        // particullarly bad with solidity's wrap-around math.
        require(ixLastContentByte >= ixFirstContentByte);

        // Return the nodeptr structure.
        return NodePtr.getPtr(ix, ixFirstContentByte, ixLastContentByte);
    }
}
