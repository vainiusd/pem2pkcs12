#!/usr/bin/env python3

#
# This script is used to convert Let's Encrypt created files into a PKCS12 file
#

import sys
import argparse
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.x509.oid import NameOID

import pdb

if __name__ == '__main__':
    # Arguments
    parser = argparse.ArgumentParser(description='LE PEM converter to PKCS12')
    parser.add_argument("-d", "--file_dir", required=True, type=Path,
        help='Path to Let\'s Encrypt generated files ($RENEWED_LINEAGE)')
    parser.add_argument("-s", "--secret", required=True, type=str, help='PKSC12 password')
    parser.add_argument("-o", "--output", required=False, type=Path, help='PKSC12 output file')
    p = parser.parse_args()

    # Check if directory exists
    FILEDIR = str(p.file_dir.resolve())+ "/" 
    if not p.file_dir.exists():
        print('Directory does not exist: {path}'.format(path=FILEDIR))
        sys.exit(2)

    # If output filename is omitted, name will be set based on CN
    if p.output is not None:
        PKSC12_FILE = p.output
    else:
        PKSC12_FILE = None

    KEYFILE = FILEDIR + 'privkey.pem'
    CERTFILE = FILEDIR + 'cert.pem'
    FULLCHAINFILE = FILEDIR + 'fullchain.pem'
    CHAINFILE = FILEDIR + 'chain.pem'

    ## Read certificate file into crypto object
    with open(CERTFILE, 'rb') as certfile:
        try:
            pem_cert = certfile.read()
            cert = load_pem_x509_certificate(pem_cert)
        except Exception as e:
            print(e)

    ## Read CA certificate chain file into crypto objects
    with open(CHAINFILE, 'rb') as chainfile:
        try:
            pem_chain = chainfile.read()
            pem_chain = pem_chain.decode('ascii')
            pem_chains = pem_chain.split('-----END CERTIFICATE-----')
            pem_chains.pop()
            pem_b_chains = []
            for i in range(len(pem_chains)):
                pem_chains[i] += '-----END CERTIFICATE-----\r\n'
                pem_b_chains.append(pem_chains[i].encode('ascii'))
            chains = []
            for i in range(len(pem_b_chains)):
                chains.append(load_pem_x509_certificate(pem_b_chains[i],None))
            # import pdb
            # pdb.set_trace()  
        except Exception as e:
            print(e)


    ## Read private key file into crypto object
    with open(KEYFILE, 'rb') as keyfile:
        try:
            pem_key = keyfile.read()
            key = load_pem_private_key(pem_key,None)
        except Exception as e:
            print(e)



    ## Serialize crypto objects (key, cert, chain certs) into a pkcs12 file

    PASSWORD = p.secret
    HOSTNAME = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    if not PKSC12_FILE:
        PKSC12_FILE = HOSTNAME + '.p12'

    pkcs12_bytes = serialize_key_and_certificates(
        HOSTNAME.encode('ascii'),
        key, 
        cert,
    #    None,
        chains,
    #    NoEncryption()
        BestAvailableEncryption(PASSWORD.encode('ascii'))
    )

    ###
    ### For ASA CLI
    ## https://www.cisco.com/c/en/us/support/docs/security-vpn/public-key-infrastructure-pki/200339-Configure-ASA-SSL-Digital-Certificate-I.html#anc15

    # import base64
    # pkcs12_b64 = b"-----BEGIN PKCS12-----\n"
    # pkcs12_b64 += base64.b64encode(pkcs12_bytes, altchars=None)
    # pkcs12_b64 += b"\n-----END PKCS12-----"

    # with open("./bundle.p12", 'wb') as pkcs12:
    #     pkcs12.write(pkcs12_b64)


    # For standard pkcs12 bundles
    with open(PKSC12_FILE, 'wb') as pkcs12:
        pkcs12.write(pkcs12_bytes)

