import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

VYR_MAGIC = b"VYR1"
TRAILER_MAGIC = b"VYRT"

class VyrArtifact:
    """Represents an authenticated Veyronis (.vyr) container."""

    def __init__(self, path: str, cli_path: Optional[str] = None):
        self.path = Path(path)
        self.cli_path = cli_path or self._find_cli_binary()
        self._validate_header()

    def _find_cli_binary(self) -> str:
        # Check standard release targets
        possible_paths = [
            Path("target/release/veyronis.exe"),
            Path("target/release/veyronis"),
            Path(__file__).parent.parent.parent.parent / "target" / "release" / "veyronis.exe",
            Path(__file__).parent.parent.parent.parent / "target" / "release" / "veyronis",
        ]
        for p in possible_paths:
            if p.exists():
                return str(p.resolve())
        return shutil.which("veyronis") or "veyronis"

    def _validate_header(self) -> None:
        with open(self.path, "rb") as f:
            magic = f.read(4)
            if magic != VYR_MAGIC:
                raise ValueError(f"Invalid VYR magic header: {magic!r}, expected {VYR_MAGIC!r}")
            self.major_version, self.minor_version = struct.unpack(">HH", f.read(4))
            self.uuid_bytes = f.read(16)
            self.created_ms, self.flags, _ = struct.unpack(">qII", f.read(16))
            self.header_checksum = f.read(8)

    def verify(self) -> bool:
        """Verifies container structure, Merkle tree root, and Ed25519 signature."""
        try:
            res = subprocess.run(
                [self.cli_path, "verify", str(self.path)],
                capture_output=True,
                text=True,
                check=False
            )
            return res.returncode == 0
        except Exception:
            return False

    def query(self, vql: str, passphrase: Optional[str] = None) -> List[Dict[str, Any]]:
        """Executes a VQL query and returns matching records."""
        cmd = [self.cli_path, "query", str(self.path), "--query", vql, "--output", "json"]
        if passphrase:
            cmd.extend(["--passphrase", passphrase])

        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(res.stdout)

    def export_events(self, passphrase: Optional[str] = None) -> List[Dict[str, Any]]:
        """Exports all decrypted VIR events."""
        return self.query("FIND event", passphrase=passphrase)


def open_artifact(path: str, cli_path: Optional[str] = None) -> VyrArtifact:
    """Opens a .vyr artifact file."""
    return VyrArtifact(path, cli_path=cli_path)
