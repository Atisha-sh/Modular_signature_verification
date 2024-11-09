from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate_private_and_public_keys():
    # Generate the private key using ECDSA with curve SECP256R1 (also known as prime256v1)
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Save private key to PEM file
    with open("private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key to PEM file
    with open("public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Private and Public keys have been generated and saved as PEM files.")

if __name__ == "__main__":
    generate_private_and_public_keys()
