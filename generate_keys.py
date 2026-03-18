"""
generate_keys.py
================
Generate RSA-2048 key pairs for Alice and Bob.
Run this ONCE before running the nodes.

Output files:
  - alice_private.pem / alice_public.pem
  - bob_private.pem   / bob_public.pem
"""

import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_keypair(name: str, output_dir: str = "."):
    """Generate an RSA-2048 key pair and save to PEM files."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_path = os.path.join(output_dir, f"{name}_private.pem")
    public_path = os.path.join(output_dir, f"{name}_public.pem")

    # Save private key
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Save public key
    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    print(f"[+] {name}_private.pem  created")
    print(f"[+] {name}_public.pem   created")


def main():
    output_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 50)
    print("  RSA-2048 Key Pair Generator")
    print("=" * 50)

    generate_keypair("alice", output_dir)
    generate_keypair("bob", output_dir)

    print()
    print("[✓] All keys generated successfully.")
    print()
    print("Distribution:")
    print("  Alice gets: alice_private.pem, alice_public.pem, bob_public.pem")
    print("  Bob   gets: bob_private.pem,   bob_public.pem,  alice_public.pem")


if __name__ == "__main__":
    main()
