from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import binascii

def generate_ecdsa_signature(data):
    """
    Generate an ECDSA signature for the provided data using the private key.
    
    :param data: The data to be signed
    :return: The ECDSA signature in hexadecimal format
    """
    # Load the private key from the PEM file
    with open("private_key.pem", "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)
    
    # Hash the data (we are using SHA-256 here)
    data_hash = hashes.Hash(hashes.SHA256())
    data_hash.update(data)
    signed_hash = data_hash.finalize()
    
    # Sign the hash using the private key
    signature = private_key.sign(signed_hash, ec.ECDSA(hashes.SHA256()))
    
    # Convert the signature to hexadecimal format
    signature_hex = binascii.hexlify(signature).decode('utf-8')
    return signature_hex

if __name__ == "__main__":
    # The data to sign
    data_to_sign = b"Hello, this is a test message."
    
    # Generate the signature in hexadecimal format
    signature_hex = generate_ecdsa_signature(data_to_sign)
    
    # Print the signature in hexadecimal format
    print("Generated ECDSA Signature in Hexadecimal:", signature_hex)
