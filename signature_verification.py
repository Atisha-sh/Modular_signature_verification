import binascii
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# Function to verify ECDSA signature using cryptography library
def verify_ecdsa_signature(signature, public_key, signed_hash):
    try:
        # ECDSA Verification using cryptography
        public_key.verify(
            signature,
            signed_hash,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"ECDSA verification failed: {e}")
        return False


# Function to verify RSA signature using cryptography library
def verify_rsa_signature(signature, public_key, signed_hash):
    try:
        # RSA Verification using cryptography
        public_key.verify(
            signature,
            signed_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"RSA verification failed: {e}")
        return False


# Function to verify Schnorr signature (Placeholder for now)
def verify_schnorr_signature(signature, public_key, signed_hash):
    # Implement Schnorr verification logic here
    # Return True as a placeholder (this would need real Schnorr logic)
    return True


# Main signature verification function
def signature_verifier(address, signature_data, signed_hash, scheme_type):
    """
    Verify the signature based on the given scheme type (ecdsa, rsa, schnorr).
    
    :param address: Address of the signer (public key in PEM format)
    :param signature_data: Signature data (in hex or byte format)
    :param signed_hash: The signed hash (message hash)
    :param scheme_type: Type of signature scheme (ecdsa, rsa, schnorr)
    :return: Boolean indicating if signature is valid or not
    """
    # Convert the signature from hex to bytes (if signature is in hex format)
    signature_bytes = binascii.unhexlify(signature_data) if isinstance(signature_data, str) else signature_data

    # Deserialize the public key from the address
    try:
        public_key = serialization.load_pem_public_key(address)
    except Exception as e:
        print(f"Error loading public key: {e}")
        return False

    # Check the scheme type and call the corresponding verification function
    if scheme_type == "ecdsa":
        # Use the cryptography library for ECDSA signature verification
        return verify_ecdsa_signature(signature_bytes, public_key, signed_hash)
    
    elif scheme_type == "rsa":
        # For RSA, use the signature as-is and verify using cryptography
        return verify_rsa_signature(signature_bytes, public_key, signed_hash)
    
    elif scheme_type == "schnorr":
        # Schnorr verification placeholder logic (you will need to implement Schnorr signature verification here)
        return verify_schnorr_signature(signature_bytes, public_key, signed_hash)
    
    else:
        print("Unsupported signature scheme")
        return False
