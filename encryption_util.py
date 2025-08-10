from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib

def generate_asymmetric_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_private = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    with open('private_key.pem', 'wb') as f: f.write(pem_private)
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('public_key.pem', 'wb') as f: f.write(pem_public)
    print("RSA public/private key pair generated and saved.")

def load_public_key():
    with open("public_key.pem", "rb") as key_file: return serialization.load_pem_public_key(key_file.read())
def load_private_key():
    with open("private_key.pem", "rb") as key_file: return serialization.load_pem_private_key(key_file.read(), password=None)

def hybrid_encrypt(data_to_encrypt: str, public_key):
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_data = f.encrypt(data_to_encrypt.encode())
    encrypted_symmetric_key = public_key.encrypt(symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    data_hash = hashlib.sha256(data_to_encrypt.encode()).hexdigest()
    return encrypted_data, encrypted_symmetric_key, data_hash

def hybrid_decrypt(encrypted_data: bytes, encrypted_symmetric_key: bytes, private_key):
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    f = Fernet(symmetric_key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    return decrypted_data

def verify_data_integrity(decrypted_data: str, original_hash: str) -> bool:
    new_hash = hashlib.sha256(decrypted_data.encode()).hexdigest()
    return new_hash == original_hash

if __name__ == '__main__': generate_asymmetric_keys()