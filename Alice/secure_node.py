"""
secure_node.py
==============
A bidirectional secure messaging node.
Each node can act as both SENDER and LISTENER.

Usage:
  python secure_node.py --name alice \
      --listen-port 5000 \
      --my-private-key alice_private.pem \
      --my-public-key alice_public.pem \
      --peer-public-key bob_public.pem

  python secure_node.py --name bob \
      --listen-port 5001 \
      --my-private-key bob_private.pem \
      --my-public-key bob_public.pem \
      --peer-public-key alice_public.pem

Once running, type a message and press Enter to send.
The node simultaneously listens for incoming messages.

Algorithms used:
  - Symmetric encryption : AES-256-CBC (with PKCS7 padding)
  - Asymmetric encryption: RSA-2048 (OAEP + SHA-256)
  - Hash function         : SHA-256
  - Digital signature      : RSA-PSS (SHA-256, max salt length)
"""

import argparse
import base64
import hashlib
import json
import os
import socket
import sys
import threading
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# ──────────────────────────────────────────────
#  Crypto helpers
# ──────────────────────────────────────────────

def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def aes_encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-CBC. Returns (iv, ciphertext)."""
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Encrypt data with RSA-OAEP (SHA-256)."""
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, data: bytes) -> bytes:
    """Decrypt data with RSA-OAEP (SHA-256)."""
    return private_key.decrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sha256_hash(data: bytes) -> str:
    """Compute SHA-256 hex digest."""
    return hashlib.sha256(data).hexdigest()


def rsa_sign(private_key, data: bytes) -> bytes:
    """Sign data hash with RSA-PSS."""
    return private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_verify(public_key, signature: bytes, data: bytes) -> bool:
    """Verify RSA-PSS signature. Returns True if valid."""
    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


# ──────────────────────────────────────────────
#  Sender logic (Alice-side process)
# ──────────────────────────────────────────────

def build_payload(
    plaintext: str,
    my_private_key,
    peer_public_key,
    source_ip: str,
    dest_ip: str,
) -> dict:
    """
    Build the secure payload:
      1. Generate AES-256 key
      2. Encrypt plaintext with AES-256-CBC
      3. Encrypt AES key with peer's RSA public key
      4. Hash the plaintext (SHA-256)
      5. Sign the hash with own RSA private key
      6. Package everything into a JSON-serializable dict
    """
    plaintext_bytes = plaintext.encode("utf-8")

    # --- Step 1: Generate symmetric key ---
    aes_key = os.urandom(32)  # 256-bit key
    print(f"\n  [SEND] Plaintext          : {plaintext}")
    print(f"  [SEND] AES-256 Key (hex)  : {aes_key.hex()}")

    # --- Step 2: Encrypt plaintext ---
    iv, ciphertext = aes_encrypt(plaintext_bytes, aes_key)
    print(f"  [SEND] IV (hex)           : {iv.hex()}")
    print(f"  [SEND] Ciphertext (b64)   : {base64.b64encode(ciphertext).decode()[:60]}...")

    # --- Step 3: Encrypt symmetric key with peer's public key ---
    encrypted_key = rsa_encrypt(peer_public_key, aes_key)
    print(f"  [SEND] Encrypted Key (b64): {base64.b64encode(encrypted_key).decode()[:60]}...")

    # --- Step 4: Hash the plaintext ---
    msg_hash = sha256_hash(plaintext_bytes)
    print(f"  [SEND] SHA-256 Hash       : {msg_hash}")

    # --- Step 5: Digital signature ---
    signature = rsa_sign(my_private_key, plaintext_bytes)
    print(f"  [SEND] Signature (b64)    : {base64.b64encode(signature).decode()[:60]}...")

    # --- Step 6: Build payload ---
    payload = {
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "hash": msg_hash,
        "signature": base64.b64encode(signature).decode(),
        "hash_algorithm": "SHA-256",
        "symmetric_algorithm": "AES-256-CBC",
        "asymmetric_algorithm": "RSA-2048-OAEP",
        "signature_algorithm": "RSA-PSS-SHA256",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return payload


def send_message(payload: dict, dest_host: str, dest_port: int):
    """Send the JSON payload to the peer via TCP socket."""
    data = json.dumps(payload).encode("utf-8")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dest_host, dest_port))
            # Send length prefix (8 bytes) + data
            s.sendall(len(data).to_bytes(8, "big"))
            s.sendall(data)
        print(f"  [SEND] Payload sent to {dest_host}:{dest_port} ({len(data)} bytes)")
        print(f"  [SEND] ✓ Message delivered successfully.\n")
    except ConnectionRefusedError:
        print(f"  [SEND] ✗ Could not connect to {dest_host}:{dest_port}. Is the peer listening?\n")
    except Exception as e:
        print(f"  [SEND] ✗ Error: {e}\n")


# ──────────────────────────────────────────────
#  Receiver logic (Bob-side process)
# ──────────────────────────────────────────────

def process_payload(
    payload: dict,
    my_private_key,
    peer_public_key,
):
    """
    Process a received payload:
      1. Decrypt symmetric key with own private key
      2. Decrypt ciphertext with symmetric key
      3. Verify hash integrity
      4. Verify digital signature
    """
    print(f"\n  {'='*50}")
    print(f"  INCOMING MESSAGE")
    print(f"  {'='*50}")
    print(f"  From           : {payload.get('source_ip', 'unknown')}")
    print(f"  To             : {payload.get('destination_ip', 'unknown')}")
    print(f"  Timestamp      : {payload.get('timestamp', 'unknown')}")
    print(f"  Algorithms     : {payload.get('symmetric_algorithm')}, "
          f"{payload.get('asymmetric_algorithm')}, "
          f"{payload.get('hash_algorithm')}, "
          f"{payload.get('signature_algorithm')}")
    print()

    # Decode base64 fields
    ciphertext = base64.b64decode(payload["ciphertext"])
    iv = base64.b64decode(payload["iv"])
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    received_hash = payload["hash"]
    signature = base64.b64decode(payload["signature"])

    # --- Step 1: Decrypt symmetric key ---
    print("  [RECV] Step 1: Decrypting symmetric key with private key...")
    try:
        aes_key = rsa_decrypt(my_private_key, encrypted_key)
        print(f"  [RECV]   AES Key (hex)    : {aes_key.hex()}")
        print(f"  [RECV]   ✓ Symmetric key decrypted.")
    except Exception as e:
        print(f"  [RECV]   ✗ Failed to decrypt symmetric key: {e}")
        return

    # --- Step 2: Decrypt ciphertext ---
    print("  [RECV] Step 2: Decrypting ciphertext with AES key...")
    try:
        plaintext_bytes = aes_decrypt(ciphertext, aes_key, iv)
        plaintext = plaintext_bytes.decode("utf-8")
        print(f"  [RECV]   Plaintext        : {plaintext}")
        print(f"  [RECV]   ✓ Message decrypted.")
    except Exception as e:
        print(f"  [RECV]   ✗ Failed to decrypt message: {e}")
        return

    # --- Step 3: Verify hash ---
    print("  [RECV] Step 3: Verifying SHA-256 hash...")
    computed_hash = sha256_hash(plaintext_bytes)
    print(f"  [RECV]   Received hash    : {received_hash}")
    print(f"  [RECV]   Computed hash    : {computed_hash}")
    if computed_hash == received_hash:
        print(f"  [RECV]   ✓ Hash MATCH — integrity verified.")
    else:
        print(f"  [RECV]   ✗ Hash MISMATCH — message may be tampered!")

    # --- Step 4: Verify digital signature ---
    print("  [RECV] Step 4: Verifying digital signature...")
    sig_valid = rsa_verify(peer_public_key, signature, plaintext_bytes)
    if sig_valid:
        print(f"  [RECV]   ✓ Signature VALID — sender authenticated.")
    else:
        print(f"  [RECV]   ✗ Signature INVALID — sender NOT verified!")

    # --- Conclusion ---
    print()
    print(f"  {'─'*50}")
    print(f"  CONCLUSION:")
    print(f"    Decryption     : ✓ Success")
    print(f"    Integrity      : {'✓ Verified' if computed_hash == received_hash else '✗ FAILED'}")
    print(f"    Authentication : {'✓ Verified' if sig_valid else '✗ FAILED'}")
    print(f"  {'─'*50}\n")


def listener_thread(
    listen_port: int,
    listen_host: str,
    my_private_key,
    peer_public_key,
):
    """Background thread that listens for incoming messages."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_host, listen_port))
    server.listen(5)
    print(f"  [LISTEN] Listening on {listen_host}:{listen_port}...")

    while True:
        try:
            conn, addr = server.accept()
            with conn:
                # Read length prefix
                length_data = conn.recv(8)
                if not length_data:
                    continue
                msg_length = int.from_bytes(length_data, "big")

                # Read full message
                chunks = []
                received = 0
                while received < msg_length:
                    chunk = conn.recv(min(4096, msg_length - received))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    received += len(chunk)

                raw = b"".join(chunks)
                payload = json.loads(raw.decode("utf-8"))
                process_payload(payload, my_private_key, peer_public_key)

        except json.JSONDecodeError:
            print("  [LISTEN] Received invalid JSON. Ignoring.")
        except Exception as e:
            print(f"  [LISTEN] Error: {e}")


# ──────────────────────────────────────────────
#  Interactive input loop
# ──────────────────────────────────────────────

def input_loop(
    node_name: str,
    my_private_key,
    peer_public_key,
    source_ip: str,
    dest_ip: str,
    dest_host: str,
    dest_port: int,
):
    """Main loop: read user input and send encrypted messages."""
    print()
    print(f"  Type a message and press Enter to send to peer.")
    print(f"  Type 'quit' to exit.\n")

    while True:
        try:
            msg = input(f"  [{node_name.upper()}] > ")
        except (EOFError, KeyboardInterrupt):
            print("\n  Exiting...")
            break

        if not msg.strip():
            continue
        if msg.strip().lower() == "quit":
            print("  Exiting...")
            break

        payload = build_payload(msg, my_private_key, peer_public_key, source_ip, dest_ip)

        # Pretty-print the payload for demonstration
        print(f"\n  [SEND] Full Payload JSON:")
        print("  " + json.dumps(payload, indent=2).replace("\n", "\n  "))
        print()

        send_message(payload, dest_host, dest_port)


# ──────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Secure Messaging Node — bidirectional sender/receiver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Terminal 1 (Alice)
  python secure_node.py --name alice \\
      --listen-port 5000 \\
      --my-private-key keys/alice_private.pem \\
      --my-public-key keys/alice_public.pem \\
      --peer-public-key keys/bob_public.pem \\
      --peer-host 192.168.1.20 --peer-port 5001

  # Terminal 2 (Bob)
  python secure_node.py --name bob \\
      --listen-port 5001 \\
      --my-private-key keys/bob_private.pem \\
      --my-public-key keys/bob_public.pem \\
      --peer-public-key keys/alice_public.pem \\
      --peer-host 192.168.1.10 --peer-port 5000
        """,
    )

    parser.add_argument("--name", required=True, help="Node name (e.g., alice or bob)")
    parser.add_argument("--listen-host", default="0.0.0.0", help="Host to listen on (default: 0.0.0.0)")
    parser.add_argument("--listen-port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--my-private-key", required=True, help="Path to own private key PEM")
    parser.add_argument("--my-public-key", required=True, help="Path to own public key PEM")
    parser.add_argument("--peer-public-key", required=True, help="Path to peer's public key PEM")
    parser.add_argument("--peer-host", required=True, help="Peer's IP address or hostname")
    parser.add_argument("--peer-port", type=int, required=True, help="Peer's listening port")
    parser.add_argument("--my-ip", default=None, help="Source IP shown in payload (default: auto-detect)")

    args = parser.parse_args()

    # Load keys
    my_private_key = load_private_key(args.my_private_key)
    peer_public_key = load_public_key(args.peer_public_key)

    # Determine source IP for payload
    if args.my_ip:
        source_ip = args.my_ip
    else:
        # Try to detect own IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((args.peer_host, 80))
                source_ip = s.getsockname()[0]
        except Exception:
            source_ip = "127.0.0.1"

    dest_ip = args.peer_host

    # Banner
    print()
    print("  " + "=" * 50)
    print(f"  Secure Node: {args.name.upper()}")
    print("  " + "=" * 50)
    print(f"  My IP (payload)    : {source_ip}")
    print(f"  Listening on       : {args.listen_host}:{args.listen_port}")
    print(f"  Peer               : {dest_ip}:{args.peer_port}")
    print(f"  Private key        : {args.my_private_key}")
    print(f"  Peer public key    : {args.peer_public_key}")
    print(f"  Symmetric algo     : AES-256-CBC")
    print(f"  Asymmetric algo    : RSA-2048-OAEP")
    print(f"  Hash algo          : SHA-256")
    print(f"  Signature algo     : RSA-PSS-SHA256")
    print("  " + "=" * 50)

    # Start listener in background thread
    t = threading.Thread(
        target=listener_thread,
        args=(args.listen_port, args.listen_host, my_private_key, peer_public_key),
        daemon=True,
    )
    t.start()

    # Give the listener a moment to bind
    time.sleep(0.3)

    # Start input loop (sender)
    input_loop(
        node_name=args.name,
        my_private_key=my_private_key,
        peer_public_key=peer_public_key,
        source_ip=source_ip,
        dest_ip=dest_ip,
        dest_host=args.peer_host,
        dest_port=args.peer_port,
    )


if __name__ == "__main__":
    main()
