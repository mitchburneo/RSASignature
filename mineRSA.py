from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto import Random
from base64 import b64encode, b64decode


class RSASignature(object):
    # THIS METHOD GENERATES AND RETURNS RSA PRIVATE & PUBLIC KEYS
    @staticmethod
    def generate_rsa_keys(length=2048):
        private_key = RSA.generate(length, Random.new().read)
        public_key = private_key.publickey()
        return private_key.exportKey('PEM'), public_key.exportKey('PEM')

    # CREATES RSA SIGNATURE, RETURNS A BYTES OBJECT
    @staticmethod
    def rsa_sign(data):
        private_key = RSA.importKey(open("private.key", 'r').read())
        digest = SHA512.new()
        digest.update(data.encode())
        signer = PKCS1_v1_5.new(private_key)
        return b64encode(signer.sign(digest))

    # VERIFIES RSA SIGNATURE, RETURNS TRUE OR FALSE
    @staticmethod
    def rsa_verify(public_key, data, sign):
        sign = b64decode(sign)
        digest = SHA512.new()
        digest.update(data.encode())
        verifier = PKCS1_v1_5.new(public_key)
        return verifier.verify(digest, sign)
