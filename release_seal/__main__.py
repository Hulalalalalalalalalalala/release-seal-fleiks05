"""Command-line entry point."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from .inventory import inventory
from .signing import SignVerifyError, sign_directory, verify_directory


def _example_package() -> Path:
    return Path(__file__).resolve().parent.parent / "examples" / "package"


def _demo() -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    package = _example_package()
    print(f"inventory of {package}:")
    print(json.dumps(inventory(package), ensure_ascii=False, indent=2))

    with tempfile.TemporaryDirectory(prefix="release_seal_demo_") as work:
        scratch = Path(work)
        private = Ed25519PrivateKey.generate()
        private_path = scratch / "private.pem"
        public_path = scratch / "public.pem"
        private_path.write_bytes(private.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        ))
        public_path.write_bytes(private.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ))
        manifest_path = scratch / "manifest.json"
        try:
            document = sign_directory(package, private_path, manifest_path)
            print(f"\nsigned {len(document['files'])} file(s) -> {manifest_path}")

            print("\nverify (untouched delivery):")
            result = verify_directory(package, manifest_path, public_path)
            print(json.dumps(result, ensure_ascii=False, indent=2))

            tampered = scratch / "tampered"
            shutil.copytree(package, tampered)
            (tampered / "notes.txt").write_bytes(b"tampered during transit")
            print("\nverify (tampered copy):")
            result = verify_directory(tampered, manifest_path, public_path)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            private_path.unlink(missing_ok=True)
    print("\ntemporary private key removed; nothing secret remains")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="release_seal", description="Create an inventory of a local directory."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("inventory", help="list ordinary files and SHA-256 hashes")
    listing.add_argument("directory", help="directory to read")
    signing = commands.add_parser("sign", help="sign the inventory into a new manifest")
    signing.add_argument("directory", help="directory to read")
    signing.add_argument("private", help="PEM Ed25519 private key (read only)")
    signing.add_argument("manifest", help="manifest to create; must not exist")
    checking = commands.add_parser("verify", help="verify a manifest against a directory")
    checking.add_argument("directory", help="directory to check")
    checking.add_argument("manifest", help="signed manifest to trust")
    checking.add_argument("public", help="PEM Ed25519 public key to trust")
    commands.add_parser("demo", help="show the inventory of the bundled example package")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            return _demo()
        if args.command == "sign":
            document = sign_directory(args.directory, args.private, args.manifest)
            print(f"signed {len(document['files'])} file(s) -> {args.manifest}")
            return 0
        if args.command == "verify":
            result = verify_directory(args.directory, args.manifest, args.public)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["valid"] else 1
        result = inventory(args.directory)
    except (OSError, ValueError, SignVerifyError) as error:
        print(f"release_seal: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
