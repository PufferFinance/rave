#!/bin/bash

# Conf -- set paths to secure signer #############################################
signer_root=/home/matthew/projects/secure-signer

##################################################################################

# Utilities.
hexlify="python3 -c \"import binascii as b; import sys; "
hexlify+="print(b.hexlify(sys.stdin.read().encode('ascii')).decode('utf-8'))\""

# Key variables used by the script.
ss_out_path=$signer_root/ss_out
signer_path=$signer_root/target/x86_64-unknown-linux-musl/release/secure-signer
client_path=$signer_root/target/debug/client
enclave_path=$signer_root/Secure-Signer

# Set environmental vars.
SECURE_SIGNER_PORT=9001
pushd ${enclave_path} > /dev/null
mrenclave=$(occlum print mrenclave)
mrsigner=$(occlum print mrsigner)
popd > /dev/null

# Make BLS keypair.
$client_path --bls-keygen --mrenclave "$mrenclave" > /dev/null
keygen_response=$(cat $ss_out_path/keygen_response)

# sdfsdf
pub=$(echo $keygen_response | jq -r '.pk_hex')
sig=$(echo $keygen_response | jq -r '.evidence.signed_report')
report=$(echo $keygen_response | jq -r '.evidence.raw_report')
x509=$(echo $keygen_response | jq -r '.evidence.signing_cert')
x509_hex=$(eval "echo '$x509' | $hexlify")


intel_root_cert=$(python3 preprocess_rave_inputs.py --certs $x509_hex -get_root 1)
leaf_cert=$(python3 preprocess_rave_inputs.py --certs $x509_hex -get_leaf 1)
sig_mod=$(eval "echo -e $leaf_cert > /tmp/evsm"; ./runX509ModulusExtraction.sh '/tmp/evsm')
sig_exp="010001"

report_hex=$(eval "echo '$report' | $hexlify")
sig_hex=$(eval "echo '$sig' | $hexlify")
abi_out=$(
    python3 preprocess_rave_inputs.py \
    --abi_encode 1 \
    --certs $x509_hex \
    --report $report_hex \
    --sig $sig_hex \
    --sig_mod $sig_mod \
    --sig_exp $sig_exp \
    --mrenclave $mrenclave \
    --mrsigner $mrsigner 
)

echo $abi_out

# Sig mod has 0x preceeding

#RAVE_INPUTS=$(python3 preprocess_rave_inputs.py --certs $x509_hex)
#echo $RAVE_INPUTS

# | base64 | tr -d "\r\n  "
# --report $REPORT --sig $SIGNATURE

# report = json
# sig = b64 rsa sig of report above
# x409 = two --begin cert-- ... --end cert--
# need signing mod and signing exp.
# which is the leaf x509 cert intel root ca, leaf cert

exit
#####################
# occlum print mrsigner > MRSIGNER
