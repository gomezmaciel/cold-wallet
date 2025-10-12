"""
Transaction verification functionality.
"""
from nacl.signing import VerifyKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from app.transaction.models import SignedTransaction
from app.transaction.canonicalizer import canonicalize
from app.crypto.keystore import KeyStore


class Verifier:
    """Verifies transaction signatures."""
    
    @staticmethod
    def verify(signed_tx: SignedTransaction) -> dict:
        """
        Verify a signed transaction.
        
        Args:
            signed_tx: SignedTransaction to verify
        
        Returns:
            dict with 'valid' (bool) and 'reason' (str) if invalid
        """
        try:
            # 1. Recompute canonical form
            tx_dict = signed_tx.tx.to_dict()
            canonical_bytes = canonicalize(tx_dict)
            
            # 2. Decode public key and signature
            pubkey_bytes = Base64Encoder.decode(signed_tx.pubkey_b64)
            signature_bytes = Base64Encoder.decode(signed_tx.signature_b64)
            
            # 3. Verify signature
            verify_key = VerifyKey(pubkey_bytes)
            try:
                verify_key.verify(canonical_bytes, signature_bytes)
            except BadSignatureError:
                return {"valid": False, "reason": "Invalid signature"}
            
            # 4. Verify address matches public key
            derived_address = KeyStore._derive_address(pubkey_bytes)
            if derived_address != signed_tx.tx.from_address:
                return {"valid": False, "reason": f"Address mismatch. Expected{derived_address}, got {signed_tx.tx.from_address}"}
            
            # All checks passed
            return {"valid": True}
            
        except Exception as e:
            return {"valid": False, "reason": f"Verification error: {str(e)}"}
