#!/bin/bash

# Conf -- set paths to secure signer #############################################
signer_root=/home/matthew/projects/secure-signer

##################################################################################

# Key variables used by the script.
ss_out_path=$signer_root/ss_out
signer_path=$signer_root/target/x86_64-unknown-linux-musl/release/secure-signer
client_path=$signer_root/target/debug/client
enclave_path=$signer_root/Secure-Signer

# Set environmental vars.
SECURE_SIGNER_PORT=9001
pushd ${enclave_path} > /dev/null
mrenclave=$(occlum print mrenclave)
popd > /dev/null


# Make BLS keypair.
$client_path --bls-keygen --mrenclave "$mrenclave"
keygen_response=$(cat $ss_out_path/keygen_response)

# sdfsdf
pub=$(echo $keygen_response | jq -r '.pk_hex')
sig=$(echo $keygen_response | jq -r '.evidence.signed_report')
report=$(echo $keygen_response | jq -r '.evidence.raw_report')
x509=$(echo $keygen_response | jq -r '.evidence.signing_cert')

RAVE_INPUTS=$(python3 preprocess_rave_inputs.py $REPORT $SIGNATURE $X509)

echo $x509

exit
#####################
# occlum print mrsigner > MRSIGNER
