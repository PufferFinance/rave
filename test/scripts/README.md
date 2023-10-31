# scripts
This directory contains the bash and Python scripts used during testing, invoked via `vm.ffi()`.

### runRSAKeygen.sh
> Generates a new PEM-encoded RSA private key `/tmp/private.pem` and public key `/tmp/public.pem`. 

### runPubKeyExtraction.sh
> Returns the RSA modulus extracted from PEM-encoded `/tmp/public.pem`.

### runRSASigGen.sh
> Returns the signature over the input string using PEM-encoded RSA private key `/tmp/private.pem`.

### runX509Gen.sh
> Generates a new self-signed x509 certificate.

### runX509GetDer.sh
> Returns the self-signed DER-encoded x509 certificate as hex-encoded bytes.

### runX509BodyExtraction.sh
> Returns the self-signed DER-encoded x509 certificate's body (excluding header and signature) as hex-encoded bytes.

### runX509ModulusExtraction.sh
> Returns the RSA modulus from the self-signed DER-encoded x509 certificate.

### runX509SigExtraction.sh
> Returns the RSA signature from the self-signed DER-encoded x509 certificate.

### runSignRandomEvidence.py
> Generates a remote attestation report using supplied inputs (mrenclave, mrsigner, 64B commitment), then signs the report with the supplied self-signed x509 certificate. 

Example usage: 

`python3 ./test/scripts/runSignRandomEvidence.py 0x123... 0x456... 0x789... /tmp/4906Bitx509SigningKey.pem`
    > This will sign a report using the supplied key file. The report *values* will be returned as abi-encoded bytes (by JSON-decoding off-chain we can do cheap string concatanation on-chain). The enclave quotebody will be base64 decoded, which can be more cheaply re-encoded on-chain.