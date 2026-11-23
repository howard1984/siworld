"""Emit synthetic KATs using libsodium and the reference Argon2 C binding.

Run with PyNaCl==1.6.2 and argon2-cffi==25.1.0. No Rust code is invoked.
"""

import hashlib
import hmac
import json
import unicodedata

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt


def hkdf(ikm, salt, info):
    prk = hmac.digest(salt, ikm, "sha256")
    return hmac.digest(prk, info + b"\x01", "sha256")


def generate():
    safe = bytes(range(16))
    salt = bytes(range(16, 32))
    normalized = unicodedata.normalize("NFC", "cafe\u0301").encode()
    stretched = hash_secret_raw(normalized, salt, 3, 65536, 1, 32, Type.ID, 19)
    wrap_key = hkdf(stretched, safe, b"SVST0001/wrap")
    key = bytes(range(32))
    nonce = bytes(range(24))
    wrap_ad = b"SVST0001/wrap" + safe
    wrapped = crypto_aead_xchacha20poly1305_ietf_encrypt(key, wrap_ad, nonce, wrap_key)
    prefix = bytes(range(19))
    ad = b"synthetic immutable piece context"
    chunks = []
    for index, last, size in ((0, False, 65536), (1, True, 17), (0, True, 65536)):
        plain = bytes(i % 251 for i in range(size))
        stream_nonce = prefix + index.to_bytes(4, "big") + bytes([last])
        cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(plain, ad, stream_nonce, key)
        chunks.append({"index": index, "last": last, "size": size,
                       "sha256": hashlib.sha256(cipher).hexdigest(),
                       "tag": cipher[-16:].hex()})
    index_id = bytes(range(32, 48))
    index_nonce = bytes(range(24, 48))
    index_key = hkdf(key, safe, b"SVST0001/index")
    index_ad = b"SVST0001/index" + safe + index_id + (1).to_bytes(8, "little")
    index = index_nonce + crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(8), index_ad, index_nonce, index_key)
    header = bytearray(b"SVST0001" + bytes([1, 0, 224, 0]) + bytes(4))
    header += safe + (1).to_bytes(8, "little") + index_id
    header += len(index).to_bytes(8, "little") + hashlib.sha256(index).digest()
    header += salt + nonce + wrapped + bytes(8)
    assert len(header) == 192
    header += hmac.digest(hkdf(key, safe, b"SVST0001/commit"), header, "sha256")
    return {"source": "PyNaCl 1.6.2 / libsodium; argon2-cffi 25.1.0 / reference Argon2 C",
            "safe": safe.hex(), "salt": salt.hex(), "normalized": normalized.hex(),
            "argon2id": stretched.hex(), "wrap_key": wrap_key.hex(),
            "wrap_nonce": nonce.hex(), "content_key": key.hex(), "wrapped": wrapped.hex(),
            "stream_prefix": prefix.hex(), "stream_ad": ad.hex(), "chunks": chunks,
            "empty_safe": {"g-0000000000000001": header.hex(),
                           "i-" + index_id.hex(): index.hex()}}


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2, sort_keys=True))
