"""
Canonical JSON serialization for deterministic signing.
"""
import canonicaljson


def canonicalize(data: dict) -> bytes:
    """
    Convert dict to canonical JSON bytes.
    
    Ensures:
    - Sorted keys
    - UTF-8 encoding
    - No whitespace
    - Deterministic encoding
    
    Args:
        data: Dictionary to canonicalize
    
    Returns:
        Canonical JSON bytes
    """
    return canonicaljson.encode_canonical_json(data)

