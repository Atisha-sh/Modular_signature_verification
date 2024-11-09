import binascii
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def verify_ecdsa_signature(signature_hex, data):
    """
    Verify the ECDSA signature using the public key.
    
    :param signature_hex: The ECDSA signature in hexadecimal format
    :param data: The original data that was signed
    :return: True if the signature is valid, False otherwise
    """
    try:
        # Load the public key from the PEM file
        with open("public_key.pem", "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())
        
        # Convert the hexadecimal signature to bytes
        signature_bytes = binascii.unhexlify(signature_hex)
        
        # Hash the data
        data_hash = hashes.Hash(hashes.SHA256())
        data_hash.update(data)
        signed_hash = data_hash.finalize()
        
        # Verify the signature using the public key and the signed hash
        public_key.verify(
            signature_bytes,
            signed_hash,
            ec.ECDSA(hashes.SHA256())
        )
        print("Signature is valid!")
        return True
    
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

if __name__ == "__main__":
    # Example signature in hexadecimal format (replace with your actual signature in hex)
    signature_hex = "304402201cd5d0f96e6060fb27e199c2f840f38579b3cf7b607e2bb60b41363a5566790102204c68aa9b06a4cd9bf93768003c2cc953ce94a9ea540cea4393af22f5a7bed606"  # Replace with your actual signature in hex
    
    # The message/data that was signed (use the original message here)
    data = b"Hello, this is a test message."
    
    # Call the verification function
    verify_ecdsa_signature(signature_hex, data)
