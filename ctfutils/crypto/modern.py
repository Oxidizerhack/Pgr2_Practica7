"""Modern cryptography utilities."""

import base64
from ..exceptions import CryptoError

def base64_encode(data: str) -> str:
    """
    Encode string to base64.
    
    Args:
        data: String to encode
        
    Returns:
        Base64 encoded string
        
    Example:
        >>> base64_encode("Hello World")
        'SGVsbG8gV29ybGQ='
    """
    if not isinstance(data, str):
        raise CryptoError("Data must be a string")
    
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def base64_decode(data: str) -> str:
    """
    Decode base64 string.
    
    Args:
        data: Base64 encoded string
        
    Returns:
        Decoded string
    """
    try:
        return base64.b64decode(data).decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Invalid base64 data: {e}")

def xor_encrypt(data: str, key: str) -> str:
    """
    XOR encrypt/decrypt data with key.
    
    Args:
        data: Data to encrypt/decrypt
        key: XOR key
        
    Returns:
        XOR result as hex string
        
    Example:
        >>> xor_encrypt("Hello", "key")
        '03010d0c1b'
    """
    if not data or not key:
        raise CryptoError("Data and key cannot be empty")
    
    result = []
    for i, char in enumerate(data):
        key_char = key[i % len(key)]
        result.append(format(ord(char) ^ ord(key_char), '02x'))
    
    return ''.join(result)

def xor_decrypt_hex(hex_data: str, key: str) -> str:
    """
    Decrypt hex XOR data.
    
    Args:
        hex_data: Hex encoded XOR data
        key: XOR key
        
    Returns:
        Decrypted string
    """
    try:
        # Convert hex to bytes
        data_bytes = bytes.fromhex(hex_data)
        result = []
        
        for i, byte in enumerate(data_bytes):
            key_char = key[i % len(key)]
            result.append(chr(byte ^ ord(key_char)))
        
        return ''.join(result)
    except Exception as e:
        raise CryptoError(f"Invalid hex data: {e}")