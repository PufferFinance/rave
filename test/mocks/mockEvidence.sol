// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.13;

abstract contract MockEvidence {
    function report() public pure virtual returns (string memory);
    function sig() public pure virtual returns (bytes memory);
    function signingMod() public pure virtual returns (bytes memory);
    function signingExp() public pure virtual returns (bytes memory);
    function mrenclave() public pure virtual returns (bytes32);
    function mrsigner() public pure virtual returns (bytes32);
    function payload() public pure virtual returns (bytes memory);
}

contract ValidBLSEvidence is MockEvidence {
    function report() public pure override returns (string memory) {
        return
        "{\"id\":\"142090828149453720542199954221331392599\",\"timestamp\":\"2023-02-15T01:24:57.989456\",\"version\":4,\"epidPseudonym\":\"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=\",\"advisoryURL\":\"https://security-center.intel.com\",\"advisoryIDs\":[\"INTEL-SA-00334\",\"INTEL-SA-00615\"],\"isvEnclaveQuoteStatus\":\"SW_HARDENING_NEEDED\",\"isvEnclaveQuoteBody\":\"AgABAIAMAAANAA0AAAAAAEJhbJjVPJcSY5RHybDnAD8AAAAAAAAAAAAAAAAAAAAAFBQLB/+ADgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAfAAAAAAAAANCud0d0wgZKYN2SVB/MfLizrN6g15PzsnonpE2/cedfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACk8eLeQq3kKFam57ApQyJ412rRw+hs7M1vL0ZTKGHCDAYVo7T4o+KD0jwJJV5RNg4AAAAAAAAAAAAAAAAAAAAA\"}";
    }

    function sig() public pure override returns (bytes memory) {
        // base64 decoded signature as hex
        return
        hex"4c15c80ec83f5ebbee20f1be0cf1f7c1850179988442cba027152e01b79474592f2cd526fc8b2b2808b9c6afeaed642061aafa9b92ffcedc7cfbc1418bb9865719ef86c9de9f01bc166cf5f2ce392a70d5cd2017336c8817eaad129ad9ff5dd88eb3ecc26b0d21e04aba01c0bf303ed5e343e85104ea7a6e45514938158358825bf339fbd5116581218575551478e49c0aecfb1eb40c863c4401c44da2aa5634e335512915b38d77c7dc693ee8b9fa41f3bf9d939c1c5e382c010c42da237650c16a3ff4ac504376b215b1fc08f69a3dc0c3d0404f643e42e3078a70db5d61305c87e90ad39968b28e333e24b0887b0f01ace55d647805575fd96648c006abe3";
    }

    function signingMod() public pure override returns (bytes memory) {
        return
        hex"a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b5";
    }

    function signingExp() public pure override returns (bytes memory) {
        return hex"010001";
    }

    function mrenclave() public pure override returns (bytes32) {
        return hex"d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f";
    }

    function mrsigner() public pure override returns (bytes32) {
        return hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";
    }

    function payload() public pure override returns (bytes memory) {
        // This is the hex-encoded 48 byte BLS public key
        return hex"a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e";
    }
}
