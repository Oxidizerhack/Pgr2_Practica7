"""Text steganography utilities."""

from ..exceptions import SteganographyError

def hide_text_whitespace(cover_text: str, secret_text: str) -> str:
    """
    Hide secret text using whitespace steganography.
    Uses spaces (0) and tabs (1) to represent binary data.
    
    Args:
        cover_text: Text to hide message in
        secret_text: Secret message to hide
        
    Returns:
        Text with hidden message
    """
    if not cover_text or not secret_text:
        raise SteganographyError("Cover text and secret text cannot be empty")
    
    # Convert secret to binary
    binary_secret = ''.join(format(ord(char), '08b') for char in secret_text)
    binary_secret += '1111111111111110'  # End marker
    
    lines = cover_text.split('\n')
    result_lines = []
    binary_index = 0
    
    for line in lines:
        if binary_index < len(binary_secret):
            # Add steganographic whitespace
            stego_chars = ""
            for bit in binary_secret[binary_index:binary_index + min(8, len(binary_secret) - binary_index)]:
                stego_chars += ' ' if bit == '0' else '\t'
            result_lines.append(line + stego_chars)
            binary_index += 8
        else:
            result_lines.append(line)
    
    return '\n'.join(result_lines)

def extract_text_whitespace(stego_text: str) -> str:
    """
    Extract hidden text from whitespace steganography.
    
    Args:
        stego_text: Text with hidden message
        
    Returns:
        Extracted secret message
    """
    lines = stego_text.split('\n')
    binary_data = ""
    
    for line in lines:
        # Extract trailing whitespace
        trailing_ws = ""
        for char in reversed(line):
            if char in [' ', '\t']:
                trailing_ws = char + trailing_ws
            else:
                break
        
        # Convert whitespace to binary
        for char in trailing_ws:
            binary_data += '0' if char == ' ' else '1'
    
    # Find end marker
    end_marker = '1111111111111110'
    end_pos = binary_data.find(end_marker)
    
    if end_pos == -1:
        raise SteganographyError("No hidden message found")
    
    # Extract message
    message_binary = binary_data[:end_pos]
    
    # Convert binary to text
    result = ""
    for i in range(0, len(message_binary), 8):
        byte = message_binary[i:i+8]
        if len(byte) == 8:
            result += chr(int(byte, 2))
    
    return result

def zero_width_encode(text: str) -> str:
    """
    Encode text using zero-width characters.
    
    Args:
        text: Text to encode
        
    Returns:
        Encoded text using zero-width characters
    """
    # Zero-width characters
    zw_chars = {
        '00': '\u200b',  # Zero Width Space
        '01': '\u200c',  # Zero Width Non-Joiner  
        '10': '\u200d',  # Zero Width Joiner
        '11': '\ufeff'   # Zero Width No-Break Space
    }
    
    binary = ''.join(format(ord(char), '08b') for char in text)
    result = ""
    
    for i in range(0, len(binary), 2):
        bits = binary[i:i+2].ljust(2, '0')
        result += zw_chars[bits]
    
    return result

def zero_width_decode(encoded_text: str) -> str:
    """
    Decode text from zero-width characters.
    
    Args:
        encoded_text: Text encoded with zero-width characters
        
    Returns:
        Decoded text
    """
    char_to_bits = {
        '\u200b': '00',
        '\u200c': '01', 
        '\u200d': '10',
        '\ufeff': '11'
    }
    
    binary = ""
    for char in encoded_text:
        if char in char_to_bits:
            binary += char_to_bits[char]
    
    result = ""
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            result += chr(int(byte, 2))
    
    return result