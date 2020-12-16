'''
    Some prototype
'''

from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from getpass import getpass
import sys, json, copy, binascii,uuid
import ctypes
import logging

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric

from colorama import Fore, Back, Style 

import res.const as const

str_format_base = Fore.LIGHTWHITE_EX + '%(asctime)s %(levelname)s ' + Fore.RESET + '%(message)s'
logging.basicConfig(format=str_format_base, level=const.LOG_LEVEL)

cert = x509.load_pem_x509_certificate(bytes_certificate)
const.display_cert(logging, "Device", "Device cert.", device_cert)
cert_algo = device_cert.signature_algorithm_oid._name.upper()

root_ca = x509.load_pem_x509_certificate(bytes_root_ca)
ca_cert_algo = root_ca.signature_algorithm_oid._name.upper()
logging.info(const.str_format_green.format("Device", "Lookup", "Found matching root certificate."))
const.display_cert(logging, "Device", "CA Root Cert.", root_ca)

ca_public_key = root_ca.public_key()

try:

    if isinstance(ca_public_key, openssl.rsa._RSAPublicKey):

        # By default: SHA256
        cert_sign_algo = hashes.SHA256()
        padding_provider = asymmetric.padding.PKCS1v15()
        #
        if ('SHA1' in cert_algo):
            cert_sign_algo = hashes.SHA1()

        ca_public_key.verify(device_cert.signature, device_cert.tbs_certificate_bytes, 
                            padding_provider,
                            cert_sign_algo)
        logging.info(const.str_format_green.format("Device", "Cert. signature validation", "OK (Good signature)"))

    if isinstance(ca_public_key, openssl.ec._EllipticCurvePublicKey):

        # By default: SHA256
        cert_sign_algo = asymmetric.ec.ECDSA(hashes.SHA256())
        #
        if ('SHA1' in cert_algo):
            cert_sign_algo = asymmetric.ec.ECDSA(hashes.SHA1())

        ca_public_key.verify(device_cert.signature, device_cert.tbs_certificate_bytes, cert_sign_algo)
        logging.info(const.str_format_green.format("Device", "Cert. signature validation", "Good signature for this EDCSA certificate"))

except exceptions.InvalidSignature as eis:

    logging.error(const.str_format_red.format(data_type, "Cert. signature validation", "FAILED (Invalid Signature)"))
