"""
Transaction data models.
"""
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime


@dataclass
class Transaction:
    """Represents a blockchain transaction."""
    from_address: str
    to: str
    value: str  # String to avoid float precision issues
    nonce: int
    gas_limit: int = 21000
    data_hex: str = ""
    timestamp: str = ""
    
    def __post_init__(self):
        """Set timestamp if not provided."""
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for signing."""
        return {
            "from": self.from_address,
            "to": self.to,
            "value": self.value,
            "nonce": self.nonce,
            "gas_limit": self.gas_limit,
            "data_hex": self.data_hex,
            "timestamp": self.timestamp
        }


@dataclass
class SignedTransaction:
    """Transaction with signature."""
    tx: Transaction
    sig_scheme: str
    signature_b64: str
    pubkey_b64: str
    
    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "tx": self.tx.to_dict(),
            "sig_scheme": self.sig_scheme,
            "signature_b64": self.signature_b64,
            "pubkey_b64": self.pubkey_b64
        }
    
    @classmethod
    def from_dict(cls, data: dict):
        """Create SignedTransaction from dict."""
        tx_data = data['tx']
        tx = Transaction(
            from_address=tx_data['from'],
            to=tx_data['to'],
            value=tx_data['value'],
            nonce=tx_data['nonce'],
            gas_limit=tx_data.get('gas_limit', 21000),
            data_hex=tx_data.get('data_hex', ''),
            timestamp=tx_data['timestamp']
        )
        return cls(
            tx=tx,
            sig_scheme=data['sig_scheme'],
            signature_b64=data['signature_b64'],
            pubkey_b64=data['pubkey_b64']
        )
