#!/bin/sh
# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
mkdir -p /ca /verifier /trust /node /state
if [ ! -s /ca/key.pem ]; then
  openssl req -x509 -newkey rsa:3072 -nodes -days 3650 \
    -keyout /ca/key.pem -out /ca/cert.pem -subj '/CN=Directory demo internal CA'
fi
issue_cert() {
  destination="$1"
  hostname="$2"
  if [ -s "$destination/tls.crt" ] && openssl x509 -checkend 2592000 -noout -in "$destination/tls.crt"; then
    return
  fi
  openssl req -new -newkey rsa:2048 -nodes -keyout "$destination/tls.key" \
    -out "$destination/request.pem" -subj "/CN=$hostname"
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$hostname" > "$destination/extensions.cnf"
  openssl x509 -req -in "$destination/request.pem" -CA /ca/cert.pem -CAkey /ca/key.pem \
    -CAcreateserial -days 365 -out "$destination/tls.crt" -extfile "$destination/extensions.cnf"
}
issue_cert /verifier directory-identity-verifier
issue_cert /node identity-node-tls
if [ ! -s /verifier/result.key ]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out /verifier/result.key
fi
openssl pkey -in /verifier/result.key -pubout -out /trust/result.pub
if [ ! -s /verifier/bearer.token ]; then
  openssl rand -hex 32 > /verifier/bearer.token
fi
cp /verifier/bearer.token /trust/bearer.token
cp /ca/cert.pem /verifier/ca.crt
cp /ca/cert.pem /trust/ca.crt
chown -R 65532:65532 /verifier /trust /state
# Public trust material is readable; private keys and tokens remain mode 0600.
chmod 644 /trust/result.pub /trust/ca.crt /verifier/ca.crt /node/tls.crt /verifier/tls.crt
