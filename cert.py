import logging
import binascii

from colorama import Fore, Back, Style 

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import openssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric
cert_algo = this_cert.signature_algorithm_oid._name.upper()


toc_public_key = toc_certificate.public_key()

try:

    if isinstance(toc_public_key, openssl.rsa._RSAPublicKey):

        # By default: SHA256
        cert_sign_algo = hashes.SHA256()
        #
        if ('SHA1' in cert_algo):
            cert_sign_algo = hashes.SHA1()

        toc_public_key.verify(this_cert.signature, this_cert.tbs_certificate_bytes, cert_sign_algo)
        logging.info(str_format_green.format(data_type, "Cert. signature validation", "OK (Good signature)"))

    if isinstance(toc_public_key, openssl.ec._EllipticCurvePublicKey):

        # By default: SHA256
        cert_sign_algo = asymmetric.ec.ECDSA(hashes.SHA256())
        #
        if ('SHA1' in cert_algo):
            cert_sign_algo = asymmetric.ec.ECDSA(hashes.SHA1())

        toc_public_key.verify(this_cert.signature, this_cert.tbs_certificate_bytes, cert_sign_algo)
        logging.info(str_format_green.format(data_type, "Cert. signature validation", "Good signature for this EDCSA certificate"))

except exceptions.InvalidSignature as eis:

    f = open("" + str(this_cert.serial_number) + ".cer","wb")
    f.write(raw_cert)
    f.close()
    logging.warning(str_format_red.format(data_type, "Cert. signature validation", "FAILED (Invalid Signature)"))
