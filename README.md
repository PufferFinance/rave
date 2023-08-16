# <h1 align="center"> On-Chain Remote Attestation Verification </h1>
![Github Actions](https://github.com/PufferFinance/rave/workflows/CI/badge.svg)

RAVe is a set of smart contracts for verifying Intel SGX remote attestation reports signed by [Intel's Attestation Service, adhering to the EPID specs](https://api.trustedservices.intel.com/documents/sgx-attestation-api-spec.pdf). SGX devices can use these contracts to prove on-chain that they are running the expected enclave and have committed to some data, enabling new use cases like [ZK-2FA](https://ethresear.ch/t/2fa-zk-rollups-using-sgx/14462).

At a high level RAVe verifies that the leaf x509 certificate used to sign the attestation report originates from Intel. The report is parsed, its enclave measurements are verified, and finally the 64 byte enclave committed data (e.g., a public key) is extracted. 




## Usage
[Download Foundry](https://book.getfoundry.sh/getting-started/installation): 

```sh
curl -L https://foundry.paradigm.xyz | bash
```  

Install Foundry: 

```sh
foundryup
```  

Install RAVe dependencies:
```sh
forge install
forge build
```

Install RAVe dependencies:
```sh
forge install
forge build
```

Setup Python virtual environment to install script dependencies.
```sh
python3 -m venv ./env
source .env/bin/activate
pip install -r requirements.txt
```

Run RAVe tests (Note some tests rely on scripts run via FFI that can fail if not run sequentially):
```sh
forge install
forge build
forge test --ffi 
```
