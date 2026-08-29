from typing import List, Dict, Any, Optional
from .reader import VyrArtifact

class VqlEngine:
    """Helper client for running VQL queries."""

    def __init__(self, artifact: VyrArtifact, passphrase: Optional[str] = None):
        self.artifact = artifact
        self.passphrase = passphrase

    def find_processes(self) -> List[Dict[str, Any]]:
        return self.artifact.query("FIND process", passphrase=self.passphrase)

    def find_network_connections(self) -> List[Dict[str, Any]]:
        return self.artifact.query("FIND event WHERE type = 'NetworkConnect'", passphrase=self.passphrase)

    def find_crypto_operations(self) -> List[Dict[str, Any]]:
        return self.artifact.query("FIND event WHERE type = 'CryptoOperation'", passphrase=self.passphrase)
