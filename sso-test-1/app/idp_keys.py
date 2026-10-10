import os
from functools import lru_cache

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

KEY_DIR = os.environ.get("IDP_KEY_DIR", "/data/keys")
KID = "sso-test-1"


def _ensure_keys():
    os.makedirs(KEY_DIR, exist_ok=True)
    private_path = os.path.join(KEY_DIR, "private.pem")
    public_path = os.path.join(KEY_DIR, "public.pem")
    if not os.path.exists(private_path):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path_tmp = private_path + ".tmp"
        with open(private_path_tmp, "wb") as handle:
            handle.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        os.replace(private_path_tmp, private_path)
        with open(public_path, "wb") as handle:
            handle.write(
                key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    return private_path, public_path


@lru_cache(maxsize=1)
def private_key_pem() -> bytes:
    private_path, _ = _ensure_keys()
    with open(private_path, "rb") as handle:
        return handle.read()


@lru_cache(maxsize=1)
def jwks() -> dict:
    _, public_path = _ensure_keys()
    with open(public_path, "rb") as handle:
        public_pem = handle.read()
    key = serialization.load_pem_public_key(public_pem)
    jwk = json.loads(RSAAlgorithm.to_jwk(key))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}
