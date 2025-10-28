import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
import base64

PBKDF2_ITERATIONS = 150000
SALT_LENGTH = 16
KEY_LENGTH = 32
IV_LENGTH = 12

def generate_salt():
    """Generate a random salt for key derivation"""
    return get_random_bytes(SALT_LENGTH)

def derive_master_key(passphrase, salt):
    """
    Derive master key from passphrase using PBKDF2
    
    Args:
        passphrase: User passphrase (string or bytes)
        salt: Salt bytes for key derivation
    
    Returns:
        32-byte master key
    """
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    
    from Crypto.Hash import SHA256
    master_key = PBKDF2(
        passphrase,
        salt,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        hmac_hash_module=SHA256
    )
    return master_key

def derive_content_key(master_key, info=b"content-key"):
    """
    Derive content encryption key from master key using HKDF
    
    Args:
        master_key: Master key from PBKDF2
        info: Context info for key derivation
    
    Returns:
        32-byte content key
    """
    from Crypto.Hash import SHA256
    content_key = HKDF(
        master_key,
        KEY_LENGTH,
        salt=b"",
        hashmod=SHA256,
        context=info
    )
    return content_key

def derive_deterministic_iv(content_key, video_id, segment_index=None, context="segment"):
    """
    Derive deterministic IV for a specific segment/content
    This ensures identical ciphertext across viewers for CDN caching
    
    Args:
        content_key: Content encryption key
        video_id: Video/content identifier
        segment_index: Segment index (for video segments)
        context: Context string (e.g., "segment", "manifest", "thumbnail")
    
    Returns:
        12-byte IV
    """
    if isinstance(video_id, str):
        video_id = video_id.encode('utf-8')
    
    if segment_index is not None:
        data = video_id + b":" + str(segment_index).encode('utf-8')
    else:
        data = video_id + b":" + context.encode('utf-8')
    
    h = hmac.new(content_key, data, hashlib.sha256)
    iv = h.digest()[:IV_LENGTH]
    return iv

def encrypt_aes_gcm(plaintext, key, iv=None, associated_data=None):
    """
    Encrypt data using AES-GCM
    
    Args:
        plaintext: Data to encrypt (bytes)
        key: 32-byte encryption key
        iv: 12-byte IV (generates random if None)
        associated_data: Additional authenticated data (optional)
    
    Returns:
        (iv, ciphertext, tag) tuple
    """
    if iv is None:
        iv = get_random_bytes(IV_LENGTH)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    if associated_data:
        cipher.update(associated_data)
    
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    
    return (iv, ciphertext, tag)

def decrypt_aes_gcm(ciphertext, key, iv, tag, associated_data=None):
    """
    Decrypt data using AES-GCM
    
    Args:
        ciphertext: Encrypted data
        key: 32-byte encryption key
        iv: 12-byte IV used for encryption
        tag: 16-byte authentication tag
        associated_data: Additional authenticated data (must match encryption)
    
    Returns:
        Decrypted plaintext bytes
    
    Raises:
        ValueError: If authentication fails (tampered data)
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    if associated_data:
        cipher.update(associated_data)
    
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    
    return plaintext

def encrypt_file_chunked(input_path, output_path, key, iv=None, chunk_size=4*1024*1024):
    """
    Encrypt a file in chunks (for large files)
    
    Args:
        input_path: Path to input file
        output_path: Path to output encrypted file
        key: 32-byte encryption key
        iv: 12-byte IV (generates random if None)
        chunk_size: Size of chunks to process (default 4MB)
    
    Returns:
        (iv, tag) tuple
    """
    if iv is None:
        iv = get_random_bytes(IV_LENGTH)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                encrypted_chunk = cipher.encrypt(chunk)
                f_out.write(encrypted_chunk)
    
    tag = cipher.digest()
    
    return (iv, tag)

def decrypt_file_chunked(input_path, output_path, key, iv, tag, chunk_size=4*1024*1024):
    """
    Decrypt a file in chunks (for large files)
    
    Args:
        input_path: Path to encrypted file
        output_path: Path to output decrypted file
        key: 32-byte encryption key
        iv: 12-byte IV used for encryption
        tag: 16-byte authentication tag
        chunk_size: Size of chunks to process (default 4MB)
    
    Raises:
        ValueError: If authentication fails
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    
    with open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                decrypted_chunk = cipher.decrypt(chunk)
                f_out.write(decrypted_chunk)
    
    cipher.verify(tag)

def pack_encrypted_blob(iv, ciphertext, tag):
    """
    Pack IV, ciphertext, and tag into a single blob
    Format: base64(iv || tag || ciphertext)
    
    Args:
        iv: 12-byte IV
        ciphertext: Encrypted data
        tag: 16-byte authentication tag
    
    Returns:
        Base64-encoded blob
    """
    blob = iv + tag + ciphertext
    return base64.b64encode(blob).decode('utf-8')

def unpack_encrypted_blob(blob_b64):
    """
    Unpack IV, ciphertext, and tag from blob
    
    Args:
        blob_b64: Base64-encoded blob
    
    Returns:
        (iv, ciphertext, tag) tuple
    """
    blob = base64.b64decode(blob_b64)
    
    iv = blob[:IV_LENGTH]
    tag = blob[IV_LENGTH:IV_LENGTH+16]
    ciphertext = blob[IV_LENGTH+16:]
    
    return (iv, ciphertext, tag)

def encrypt_json(data, key, video_id, context="manifest"):
    """
    Encrypt JSON data with deterministic IV for caching
    
    Args:
        data: Dict/list to encrypt
        key: Encryption key
        video_id: Video ID for IV derivation
        context: Context string for IV derivation
    
    Returns:
        Base64-encoded encrypted blob
    """
    import json
    plaintext = json.dumps(data).encode('utf-8')
    
    iv = derive_deterministic_iv(key, video_id, context=context)
    
    iv, ciphertext, tag = encrypt_aes_gcm(plaintext, key, iv)
    
    return pack_encrypted_blob(iv, ciphertext, tag)

def decrypt_json(blob_b64, key):
    """
    Decrypt JSON data
    
    Args:
        blob_b64: Base64-encoded encrypted blob
        key: Encryption key
    
    Returns:
        Decrypted dict/list
    """
    import json
    iv, ciphertext, tag = unpack_encrypted_blob(blob_b64)
    
    plaintext = decrypt_aes_gcm(ciphertext, key, iv, tag)
    
    return json.loads(plaintext.decode('utf-8'))

if __name__ == '__main__':
    print("Testing crypto utilities...")
    
    passphrase = "test_passphrase_12345"
    salt = generate_salt()
    
    master_key = derive_master_key(passphrase, salt)
    print(f"Master key: {master_key.hex()}")
    
    content_key = derive_content_key(master_key)
    print(f"Content key: {content_key.hex()}")
    
    video_id = "test_video_123"
    iv = derive_deterministic_iv(content_key, video_id, segment_index=0)
    print(f"Deterministic IV: {iv.hex()}")
    
    plaintext = b"Hello, this is a test message!"
    iv, ciphertext, tag = encrypt_aes_gcm(plaintext, content_key)
    print(f"Encrypted: {ciphertext.hex()}")
    
    decrypted = decrypt_aes_gcm(ciphertext, content_key, iv, tag)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    
    test_data = {"message": "test", "number": 42}
    encrypted_json = encrypt_json(test_data, content_key, video_id)
    print(f"Encrypted JSON: {encrypted_json[:50]}...")
    
    decrypted_json = decrypt_json(encrypted_json, content_key)
    print(f"Decrypted JSON: {decrypted_json}")
    
    print("\nAll tests passed!")
