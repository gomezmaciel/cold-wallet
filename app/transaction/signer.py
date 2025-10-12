"""
Transaction signing functionality.
"""
from nacl.signing import SigningKey
from nacl.encoding import Base64Encoder
from app.transaction.models import Transaction, SignedTransaction
from app.transaction.canonicalizer import canonicalize


class Signer:
    """Signs transactions with private key."""
    
    @staticmethod
    def sign(signing_key: SigningKey, tx: Transaction) -> SignedTransaction:
        """
        Sign a transaction.
        
        Args:
            signing_key: Private signing key
            tx: Transaction to sign
        
        Returns:
            SignedTransaction with signature
        """
        # Get canonical form
        tx_dict = tx.to_dict()
        canonical_bytes = canonicalize(tx_dict)
        
        # Sign the canonical bytes
        signed = signing_key.sign(canonical_bytes)
        
        # Extract signature (first 64 bytes)
        signature = signed.signature
        
        # Get public key
        verify_key = signing_key.verify_key
        pubkey_b64 = Base64Encoder.encode(verify_key.encode()).decode('utf-8')
        signature_b64 = Base64Encoder.encode(signature).decode('utf-8')
        
        return SignedTransaction(
            tx=tx,
            sig_scheme="Ed25519",
            signature_b64=signature_b64,
            pubkey_b64=pubkey_b64
        )
