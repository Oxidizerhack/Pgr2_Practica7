"""Classical cryptography algorithms."""

from ..exceptions import CryptoError

def caesar_encrypt(text: str, shift: int) -> str:
    """
    Encrypt text using Caesar cipher.
    
    Args:
        text: Text to encrypt
        shift: Number of positions to shift
        
    Returns:
        Encrypted text
        
    Example:
        >>> caesar_encrypt("HELLO", 3)
        'KHOOR'
    """
    if not isinstance(text, str):
        raise CryptoError("Text must be a string")
    
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt Caesar cipher."""
    return caesar_encrypt(text, -shift)

def vigenere_encrypt(text: str, key: str) -> str:
    """
    Encrypt text using Vigenère cipher.
    
    Args:
        text: Text to encrypt
        key: Encryption key
        
    Returns:
        Encrypted text
    """
    if not text or not key:
        raise CryptoError("Text and key cannot be empty")
    
    result = ""
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base + shift) % 26 + base)
            key_index += 1
        else:
            result += char
    
    return result

def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt Vigenère cipher."""
    if not text or not key:
        raise CryptoError("Text and key cannot be empty")
    
    result = ""
    key = key.upper()
    key_index = 0
    
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
            key_index += 1
        else:
            result += char
    
    return result