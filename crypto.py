import base64, hashlib, json, os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

ARGON_TIME=3; ARGON_MEMORY=65536; ARGON_PARALLELISM=2; ARGON_HASH_LEN=32

def b64e(x): return base64.urlsafe_b64encode(x).decode()
def b64d(x): return base64.urlsafe_b64decode(x.encode())
def derive_kek(password,salt):
    return hash_secret_raw(password.encode(),salt,ARGON_TIME,ARGON_MEMORY,ARGON_PARALLELISM,ARGON_HASH_LEN,Type.ID)
def canonical_bytes(payload): return json.dumps(payload,sort_keys=True,separators=(",",":")).encode()
def load_or_create_signing_key(path="signing_key.pem"):
    if os.path.exists(path):
        with open(path,"rb") as f: return serialization.load_pem_private_key(f.read(),password=None)
    key=ec.generate_private_key(ec.SECP256R1())
    with open(path,"wb") as f: f.write(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    return key
def public_key_bytes(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
def encrypt_payload(message,password,signing_key,expires_at=None,one_time=False):
    salt=os.urandom(16); nonce=os.urandom(12); session_key=AESGCM.generate_key(bit_length=256); kek=derive_kek(password,salt)
    ciphertext=AESGCM(session_key).encrypt(nonce,message.encode(),None); wrapped=aes_key_wrap(kek,session_key); fingerprint=hashlib.sha3_256(message.encode()).hexdigest()
    payload={"version":3,"cipher":"AES-256-GCM","kdf":"Argon2id","kdf_params":{"time":ARGON_TIME,"memory_kib":ARGON_MEMORY,"parallelism":ARGON_PARALLELISM},"hash":"SHA3-256","signature":"ECDSA-P256-SHA256","salt":b64e(salt),"nonce":b64e(nonce),"wrapped_key":b64e(wrapped),"ciphertext":b64e(ciphertext),"fingerprint":fingerprint,"expires_at":expires_at,"one_time":bool(one_time)}
    payload["signature_value"]=b64e(signing_key.sign(canonical_bytes(payload),ec.ECDSA(hashes.SHA256())))
    payload["public_key"]=b64e(public_key_bytes(signing_key)); return payload
def decrypt_payload(payload,password):
    signature=b64d(payload["signature_value"]); pub=serialization.load_der_public_key(b64d(payload["public_key"]))
    unsigned=dict(payload); unsigned.pop("signature_value",None); unsigned.pop("public_key",None)
    pub.verify(signature,canonical_bytes(unsigned),ec.ECDSA(hashes.SHA256()))
    kek=derive_kek(password,b64d(payload["salt"])); key=aes_key_unwrap(kek,b64d(payload["wrapped_key"]))
    plaintext=AESGCM(key).decrypt(b64d(payload["nonce"]),b64d(payload["ciphertext"]),None).decode()
    if hashlib.sha3_256(plaintext.encode()).hexdigest()!=payload["fingerprint"]: raise ValueError("SHA3-256 fingerprint mismatch")
    return plaintext
