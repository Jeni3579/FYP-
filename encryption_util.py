# encryption_util.py

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import hashlib

# --- ASYMMETRIC KEY (RSA) MANAGEMENT ---
# In a real system, these keys would be securely stored and managed.
# For this project, we will generate them and save them to files.

def generate_asymmetric_keys():
    """Generates a public/private RSA key pair and saves them to PEM files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Serialize and save the private key
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('private_key.pem', 'wb') as f:
        f.write(pem_private)

    # Serialize and save the public key
    public_key = private_key.public_key()
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public)
    print("RSA public/private key pair generated and saved.")

def load_public_key():
    """Loads the RSA public key from a file."""
    with open("public_key.pem", "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def load_private_key():
    """Loads the RSA private key from a file."""
    with open("private_key.pem", "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

# --- HYBRID ENCRYPTION / DECRYPTION ---

def hybrid_encrypt(data_to_encrypt: str, public_key):
    """
    Encrypts data using a hybrid approach:
    1. Generates a new one-time symmetric key (Fernet).
    2. Encrypts the data with the symmetric key.
    3. Encrypts the symmetric key with the public RSA key.
    Returns the encrypted data, the encrypted symmetric key, and a data hash.
    """
    # 1. Generate one-time symmetric key and encrypt data
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_data = f.encrypt(data_to_encrypt.encode())
    
    # 2. Encrypt the symmetric key with the public RSA key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 3. Create a hash of the original data for integrity check
    data_hash = hashlib.sha256(data_to_encrypt.encode()).hexdigest()
    
    return encrypted_data, encrypted_symmetric_key, data_hash

def hybrid_decrypt(encrypted_data: bytes, encrypted_symmetric_key: bytes, private_key):
    """
    Decrypts data using the hybrid approach:
    1. Decrypts the symmetric key with the private RSA key.
    2. Decrypts the data with the symmetric key.
    Returns the decrypted data.
    """
    # 1. Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # 2. Decrypt the actual data
    f = Fernet(symmetric_key)
    decrypted_data = f.decrypt(encrypted_data).decode()
    
    return decrypted_data

def verify_data_integrity(decrypted_data: str, original_hash: str) -> bool:
    """Verifies the integrity of the decrypted data by re-hashing it."""
    new_hash = hashlib.sha256(decrypted_data.encode()).hexdigest()
    return new_hash == original_hash

# This part allows you to generate the keys by running the file directly
if __name__ == '__main__':
    generate_asymmetric_keys()