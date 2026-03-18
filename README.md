# End-to-End Secure Message Delivery
## II3230 Keamanan Informasi

### Arsitektur

```
┌─────────────────────┐         TCP Socket        ┌─────────────────────┐
│       ALICE          │ ◄──────────────────────► │        BOB           │
│  192.168.1.10:5000   │     JSON Payload          │  192.168.1.20:5001   │
│                      │                           │                      │
│  - alice_private.pem │  Payload berisi:           │  - bob_private.pem   │
│  - alice_public.pem  │  • ciphertext (AES-256)   │  - bob_public.pem    │
│  - bob_public.pem    │  • encrypted_key (RSA)    │  - alice_public.pem  │
│                      │  • hash (SHA-256)          │                      │
│  Bisa KIRIM & TERIMA │  • signature (RSA-PSS)    │  Bisa KIRIM & TERIMA │
└─────────────────────┘  • metadata                └─────────────────────┘
```

### Algoritma yang Digunakan

| Komponen              | Algoritma        | Keterangan                          |
|----------------------|------------------|-------------------------------------|
| Symmetric Encryption | AES-256-CBC      | Enkripsi isi pesan                  |
| Asymmetric Encryption| RSA-2048-OAEP    | Enkripsi kunci AES                  |
| Hash Function        | SHA-256          | Verifikasi integritas               |
| Digital Signature    | RSA-PSS-SHA256   | Autentikasi & non-repudiation       |
| Transport            | TCP Socket       | Komunikasi antar-IP                 |
| Payload Format       | JSON             | Struktur data yang dikirim          |

### Prasyarat

```bash
pip install cryptography
```

### Cara Menjalankan

#### Langkah 1: Generate Kunci

```bash
mkdir keys
python generate_keys.py keys
```

Ini menghasilkan 4 file:
- `keys/alice_private.pem` & `keys/alice_public.pem`
- `keys/bob_private.pem` & `keys/bob_public.pem`

#### Langkah 2: Jalankan Bob (Terminal 1)

```bash
python secure_node.py --name bob \
    --listen-port 5001 \
    --my-private-key keys/bob_private.pem \
    --my-public-key keys/bob_public.pem \
    --peer-public-key keys/alice_public.pem \
    --peer-host 127.0.0.1 --peer-port 5000
```

#### Langkah 3: Jalankan Alice (Terminal 2)

```bash
python secure_node.py --name alice \
    --listen-port 5000 \
    --my-private-key keys/alice_private.pem \
    --my-public-key keys/alice_public.pem \
    --peer-public-key keys/bob_public.pem \
    --peer-host 127.0.0.1 --peer-port 5001
```

#### Langkah 4: Kirim Pesan

Di terminal Alice, ketik pesan dan tekan Enter:
```
[ALICE] > Bob, transfer dana penelitian sebesar 10 juta.
```

Bob akan otomatis menerima, mendekripsi, dan memverifikasi pesan.

Bob juga bisa mengirim pesan balik ke Alice — cukup ketik di terminal Bob!

### Menjalankan dengan Docker (Dua IP Berbeda)

```bash
# Buat network
docker network create --subnet=192.168.1.0/24 secure-net

# Jalankan container
docker run -dit --name alice --network secure-net --ip 192.168.1.10 python:3.11-slim
docker run -dit --name bob --network secure-net --ip 192.168.1.20 python:3.11-slim

# Install dependencies
docker exec alice pip install cryptography
docker exec bob pip install cryptography

# Copy file ke container
docker cp generate_keys.py alice:/app/generate_keys.py
docker cp secure_node.py alice:/app/secure_node.py
docker cp generate_keys.py bob:/app/generate_keys.py
docker cp secure_node.py bob:/app/secure_node.py

# Generate keys di alice, lalu copy ke bob
docker exec alice bash -c "cd /app && mkdir -p keys && python generate_keys.py keys"
docker exec alice bash -c "tar -C /app/keys -cf - ." | docker exec -i bob bash -c "mkdir -p /app/keys && tar -C /app/keys -xf -"

# Jalankan Bob (terminal 1)
docker exec -it bob bash -c "cd /app && python secure_node.py --name bob \
    --listen-port 5001 \
    --my-private-key keys/bob_private.pem \
    --my-public-key keys/bob_public.pem \
    --peer-public-key keys/alice_public.pem \
    --peer-host 192.168.1.10 --peer-port 5000 \
    --my-ip 192.168.1.20"

# Jalankan Alice (terminal 2)
docker exec -it alice bash -c "cd /app && python secure_node.py --name alice \
    --listen-port 5000 \
    --my-private-key keys/alice_private.pem \
    --my-public-key keys/alice_public.pem \
    --peer-public-key keys/bob_public.pem \
    --peer-host 192.168.1.20 --peer-port 5001 \
    --my-ip 192.168.1.10"
```

### Alur End-to-End

```
ALICE (Sender)                              BOB (Receiver)
─────────────────                           ─────────────────
1. Plaintext                                
2. Generate AES-256 Key                     
3. Encrypt plaintext → ciphertext           
4. Encrypt AES key + RSA(Bob pub) → enc_key 
5. SHA-256(plaintext) → hash                
6. RSA-PSS sign(Alice priv, plaintext)      
7. Send JSON payload via TCP ──────────────► 8.  Receive payload
                                             9.  RSA decrypt enc_key → AES key
                                             10. AES decrypt ciphertext → plaintext
                                             11. SHA-256(plaintext) == hash? ✓
                                             12. RSA-PSS verify(Alice pub) ✓
                                             13. Conclusion: valid & authentic
```

### Contoh Payload JSON

```json
{
  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",
  "ciphertext": "base64-encoded AES ciphertext",
  "iv": "base64-encoded initialization vector",
  "encrypted_key": "base64-encoded RSA-encrypted AES key",
  "hash": "sha256 hex digest of plaintext",
  "signature": "base64-encoded RSA-PSS signature",
  "hash_algorithm": "SHA-256",
  "symmetric_algorithm": "AES-256-CBC",
  "asymmetric_algorithm": "RSA-2048-OAEP",
  "signature_algorithm": "RSA-PSS-SHA256",
  "timestamp": "2026-03-17 14:30:00"
}
```
