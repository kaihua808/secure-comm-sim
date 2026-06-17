import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_ecc_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def key_to_hex(key, is_private=False):
    if is_private:
        raw = key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        raw = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    return raw.hex()


def sha256_digest(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def ecdsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def aes_gcm_encrypt(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def ecdh_encrypt_session_key(bob_public_key, session_key: bytes):
    ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
    ephemeral_pub  = ephemeral_priv.public_key()
    shared_secret  = ephemeral_priv.exchange(ec.ECDH(), bob_public_key)

    wrap_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"session-key-wrap"
    ).derive(shared_secret)

    wrap_nonce = os.urandom(12)
    wrapped    = AESGCM(wrap_key).encrypt(wrap_nonce, session_key, None)

    ephemeral_pub_bytes = ephemeral_pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return ephemeral_pub_bytes, wrap_nonce, wrapped


def ecdh_decrypt_session_key(bob_private_key, ephemeral_pub_bytes: bytes,
                              wrap_nonce: bytes, wrapped_key: bytes) -> bytes:
    ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_pub_bytes
    )
    shared_secret = bob_private_key.exchange(ec.ECDH(), ephemeral_pub)

    wrap_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"session-key-wrap"
    ).derive(shared_secret)

    return AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_key, None)


class TransmissionPacket:
    def __init__(self):
        self.reset()

    def reset(self):
        self.nonce         = None
        self.ciphertext    = None
        self.ephemeral_pub = None
        self.wrap_nonce    = None
        self.wrapped_key   = None
        self.signature     = None
        self.digest        = None
        self.original_msg  = None
        self.session_key   = None
