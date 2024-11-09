# charter-21BCE10714
# CharterLabs Stage 1: Modular Signature Scheme Verification Algorithm

## Overview

This project implements a **Modular Signature Scheme Verification Algorithm** designed to support multiple signature schemes (e.g., ECDSA, RSA) and verify signatures across different formats. The algorithm dynamically recognizes the type of signature provided and verifies it with the given address.

### Key Objectives
- **Universal Signature Scheme Compatibility**: Supports multiple signature schemes by recognizing the specified scheme and using the correct verification logic.
- **Optimization for Performance**: Designed for efficiency, with early exits for failure cases to reduce time complexity.
- **Security**: Utilizes robust cryptographic libraries to ensure secure verification.

## Requirements

- Python 3.8 or later
- `cryptography` package (for cryptographic operations)

To install the required packages, run:

```bash
pip install cryptography
```
### Project Structure
```graphql
|-- generate_keys.py                 # Script to generate ECDSA and RSA keys
|-- generate_signature.py             # Script to generate a signature for ECDSA or RSA
|-- signature_verification.py         # Main signature verification algorithm supporting ECDSA and RSA
|-- test_signature_verification.py    # Test cases to validate signature verification for each scheme
|-- README.md                         # This README file
```
### Setup
Clone this repository:

```bash
git clone <repository_url>
cd <repository_name>
```
Install dependencies:

```bash
pip install cryptography
```
Run the key generation script to create ECDSA and RSA keys:

```bash
python generate_keys.py
```
Generate a signature for testing purposes:

```bash
python generate_signature.py
```
Run the verification tests:

```bash
python test_signature_verification.py
```
### Usage
- Key Generation: `generate_keys.py` creates `ecdsa_public_key.pem` and `rsa_public_key.pem` in the project directory.
- Signature Generation: `generate_signature.py` signs a sample message using the specified scheme.
- Signature Verification: Run `test_signature_verification.py` to verify that generated signatures match their public keys.
### Example
The following commands demonstrate generating and verifying a signature:
```bash
python generate_keys.py                     # Generate public/private keys
python generate_signature.py                 # Generate a signature for a test message
python test_signature_verification.py        # Verify the generated signature
```
## Task Details
### Task Objective
To build an algorithm capable of dynamically verifying ECDSA, RSA, or other schemes by identifying the provided signature scheme and verifying it against a signed address.

### Code Explanation
- generate_keys.py: Generates public/private key pairs for ECDSA and RSA schemes.
- generate_signature.py: Generates a signature based on the specified scheme.
- signature_verification.py: Core algorithm for verifying signatures based on a given scheme.
- test_signature_verification.py: Tests the signature verification logic across multiple schemes.

