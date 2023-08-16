#!/bin/bash

# Conf -- set paths to secure signer #############################################
signer_root=/home/matthew/projects/secure-signer

##################################################################################

# Utilities.
hexlify="python3 -c \"import binascii as b; import sys; "
hexlify+="print(b.hexlify(sys.stdin.read().encode('ascii')).decode('utf-8'),)\""

# Key variables used by the script.
ss_out_path=$signer_root/ss_out
signer_path=$signer_root/target/x86_64-unknown-linux-musl/release/secure-signer
client_path=$signer_root/target/debug/client
enclave_path=$signer_root/Secure-Signer

# Set environmental vars.
SECURE_SIGNER_PORT=9001
pushd ${enclave_path} > /dev/null
mrenclave=$(occlum print mrenclave) # hex
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





#openssl x509 -in /tmp/rleaf.pem -text -noout -certopt ca_default -certopt no_validity -certopt no_serial -certopt no_subject -certopt no_extensions -certopt no_signame 


#exit


#openssl dgst -sha256 -verify /tmp/rleaf.pem -signature /tmp/rsig.sign /tmp/rreport.txt



pushd "./bin" > /dev/null

leaf_cert_pem=$(echo "$x509" | ./get_report_cert)
leaf_cert_hex=$(echo "$leaf_cert_pem" | ./pem_to_der | ./to_hex)
#sig_mod=$(eval "echo -e '$leaf_cert_pem' > /tmp/evsm"; "../runX509ModulusExtraction.sh" '/tmp/evsm')


sig_mod="9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B"
sig_exp="010001"

      


#echo "$leaf_cert_hex" | ./from_hex | ./der_to_pem | ./is_valid_signer_cert

#echo $sig_mod

#echo

#echo $sig


report_hex=$(echo -n "$report" | ./to_hex)
report_calldata_hex=$(echo -n "$report" | ./report_to_calldata)
sig_hex=$(echo "$sig" | base64 --decode | ./to_hex)

#echo $sig_hex

#echo

popd > /dev/null

# Inputs should all be hex.
abi_out=$(
    python3 preprocess_rave_inputs.py \
    --abi_encode 1 \
    --cert $leaf_cert_hex \
    --report $report_calldata_hex \
    --sig $sig_hex \
    --sig_mod $sig_mod \
    --sig_exp $sig_exp \
    --mrenclave $mrenclave \
    --mrsigner $mrsigner 
)

echo -n $abi_out

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
