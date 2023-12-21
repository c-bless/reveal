import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt(plain_text: str, key: str) -> bytes:
    hashed_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()

    nonce = get_random_bytes(16)
    cipher = AES.new(hashed_key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode('utf-8'))

    output = cipher.nonce + tag + ciphertext
    return base64.b64encode(output).decode("utf-8")


def decrypt(cipher_text_b64: str, key: str):
    hashed_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()
    decoded = base64.b64decode(cipher_text_b64.encode('utf-8'))
    nonce = decoded[:16]
    tag = decoded[16:32]
    ciphertext = decoded[32:]
    cipher = AES.new(hashed_key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data
