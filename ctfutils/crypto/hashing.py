"""Hashing and hash analysis utilities."""

import hashlib
from ..exceptions import CryptoError

def md5_hash(data: str) -> str:
    """
    Generate MD5 hash of data.
    
    Args:
        data: Data to hash
        
    Returns:
        MD5 hash as hex string
        
    Example:
        >>> md5_hash("Hello World")
        'b10a8db164e0754105b7a99be72e3fe5'
    """
    if not isinstance(data, str):
        raise CryptoError("Data must be a string")
    
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def sha256_hash(data: str) -> str:
    """
    Generate SHA256 hash of data.
    
    Args:
        data: Data to hash
        
    Returns:
        SHA256 hash as hex string
    """
    if not isinstance(data, str):
        raise CryptoError("Data must be a string")
    
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def sha1_hash(data: str) -> str:
    """Generate SHA1 hash of data."""
    if not isinstance(data, str):
        raise CryptoError("Data must be a string")
    
    return hashlib.sha1(data.encode('utf-8')).hexdigest()

def identify_hash(hash_string: str) -> str:
    """
    Try to identify hash type based on length.
    
    Args:
        hash_string: Hash to identify
        
    Returns:
        Possible hash type
    """
    hash_length = len(hash_string)
    
    if hash_length == 32:
        return "MD5"
    elif hash_length == 40:
        return "SHA1"
    elif hash_length == 64:
        return "SHA256"
    elif hash_length == 128:
        return "SHA512"
    else:
        return "Unknown"

def verify_hash(data: str, hash_value: str, hash_type: str = "md5") -> bool:
    """
    Verify if data matches the given hash.
    
    Args:
        data: Original data
        hash_value: Hash to verify against
        hash_type: Type of hash (md5, sha1, sha256)
        
    Returns:
        True if hash matches
    """
    hash_functions = {
        'md5': md5_hash,
        'sha1': sha1_hash,
        'sha256': sha256_hash
    }
    
    if hash_type.lower() not in hash_functions:
        raise CryptoError(f"Unsupported hash type: {hash_type}")
    
    computed_hash = hash_functions[hash_type.lower()](data)
    return computed_hash.lower() == hash_value.lower()