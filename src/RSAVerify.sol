pragma solidity >=0.8.0 <0.9.0;

// Copied from https://github.com/ensdomains/ens-contracts/blob/80aa5108f11d11cd7956135ef21ac45da8eb934d/contracts/dnssec-oracle/algorithms/RSAVerify.sol

library ModexpPrecompile {
    /**
     * @dev Computes (base ^ exponent) % modulus over big numbers.
     */
    function modexp(bytes memory base, bytes memory exponent, bytes memory modulus)
        internal
        view
        returns (bool success, bytes memory output)
    {
        bytes memory input = abi.encodePacked(
            uint256(base.length), uint256(exponent.length), uint256(modulus.length), base, exponent, modulus
        );

        output = new bytes(modulus.length);

        assembly {
            success := staticcall(gas(), 5, add(input, 32), mload(input), add(output, 32), mload(modulus))
        }
    }
}

library RSAVerify {
    /**
     * @dev Recovers the input data from an RSA signature, returning the result in S.
     * @param N The RSA public modulus.
     * @param E The RSA public exponent.
     * @param S The signature to recover.
     * @return True if the recovery succeeded.
     */
    function rsarecover(bytes memory N, bytes memory E, bytes memory S) internal view returns (bool, bytes memory) {
        return ModexpPrecompile.modexp(S, E, N);
    }
}
