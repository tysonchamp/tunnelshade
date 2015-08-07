#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  gencert.py
#  
#  Copyright 2013 tunnelshade <blog.tunnelshade.in>
#
#  * openssl genrsa -des3 -out ca.key 1024
#
#  * openssl req -new -x509 -days 3650 -key ca.key -out ca.crt
#  
#  This script creates signed certificates in a folder called domains  

from OpenSSL import crypto
import os, hashlib

def gen_cert(domain,
            ca_crt = os.path.join(os.path.dirname(__file__),"ca.crt"),
            ca_key = os.path.join(os.path.dirname(__file__),"ca.key")
            ):
    """This function takes a domain name as a parameter and then creates a certificate and key with the
    domain name(replacing dots by underscores), finally signing the certificate using specified CA and 
    returns the path of key and cert files. If you are yet to generate a CA then check the top comments"""
    
    key_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".key")
    cert_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".crt")

    # Check happens if the certificate and key pair already exists for a domain
    if os.path.exists(key_path) and os.path.exists(cert_path):
        pass
    else:
        #Serial Generation - Serial number must be unique for each certificate,
        # so serial is generated based on domain name
        md5_hash = hashlib.md5()
        md5_hash.update(domain)
        serial = int(md5_hash.hexdigest(), 36)

        # The CA stuff is loaded from the same folder as this script
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(ca_crt).read())
        # The last parameter is the password for your CA key file
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(ca_key).read(), "owtf-dev")


        key = crypto.PKey()
        key.generate_key( crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().C = "IN"
        cert.get_subject().ST = "AP"
        cert.get_subject().L = "127.0.0.1"
        cert.get_subject().O = "OWTF"
        cert.get_subject().OU = "Inbound-Proxy"
        cert.get_subject().CN = domain # This is where the domain fits
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)
        cert.set_serial_number(serial)
        cert.set_issuer(ca_cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(ca_key, "sha1")

        # The key and cert files are dumped and their paths are returned
        key_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".key")
        domain_key = open(key_path,"w")
        domain_key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        
        cert_path = os.path.join(os.path.dirname(__file__),"domains/"+domain.replace('.','_')+".crt")
        domain_cert = open(cert_path,"w")
        domain_cert.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    return key_path, cert_path
