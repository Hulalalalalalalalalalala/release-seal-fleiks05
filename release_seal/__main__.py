"""Command-line entry point."""

import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from .inventory import inventory


def demo() -> int:
    """Sign and verify a copy of the example package with a throwaway key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    from .seal import sign_directory, verify_directory

    package = Path(__file__).resolve().parent.parent / "examples" / "package"
    with tempfile.TemporaryDirectory(prefix="release-seal-demo-") as workspace:
        work = Path(workspace)
        delivery = work / "package"
        shutil.copytree(package, delivery)
        key = Ed25519PrivateKey.generate()
        private_key = work / "demo-private.pem"
        public_key = work / "demo-public.pem"
        private_key.write_bytes(
            key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        public_key.write_bytes(
            key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )
        manifest = work / "manifest.json"
        print("== inventory ==")
        print(json.dumps(inventory(delivery), ensure_ascii=False, indent=2))
        print("== sign ==")
        print(json.dumps(
            sign_directory(delivery, private_key, manifest),
            ensure_ascii=False, indent=2,
        ))
        print("== verify: untouched delivery ==")
        print(json.dumps(
            verify_directory(delivery, manifest, public_key),
            ensure_ascii=False, indent=2,
        ))
        print("== verify: tampered delivery ==")
        target = delivery / "notes.txt"
        target.write_bytes(target.read_bytes() + b"tampered")
        print(json.dumps(
            verify_directory(delivery, manifest, public_key),
            ensure_ascii=False, indent=2,
        ))
        private_key.unlink()
    print("demo finished; the temporary private key has been removed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="release_seal",
        description="Inventory, sign and verify a local delivery directory.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser(
        "inventory", help="list ordinary files and SHA-256 hashes"
    )
    listing.add_argument("directory", help="directory to read")
    signing = commands.add_parser(
        "sign", help="sign the inventory with an Ed25519 private key"
    )
    signing.add_argument("directory", help="directory to read")
    signing.add_argument("private", help="PEM Ed25519 private key (read only)")
    signing.add_argument("manifest", help="manifest to create; must not exist yet")
    multi = commands.add_parser(
        "sign-multi",
        help="sign the inventory with several Ed25519 keys (version 3 manifest)",
    )
    multi.add_argument("directory", help="directory to read")
    multi.add_argument("manifest", help="manifest to create; must not exist yet")
    multi.add_argument(
        "private", nargs="+", help="PEM Ed25519 private keys (read only)"
    )
    checking = commands.add_parser(
        "verify", help="verify a signed manifest against a directory"
    )
    checking.add_argument("directory", help="directory to check")
    checking.add_argument("manifest", help="signed manifest to trust")
    checking.add_argument("public", help="PEM Ed25519 public key to trust")
    trusted = commands.add_parser(
        "verify-trusted",
        help="verify a manifest using keys in an offline trust store",
    )
    trusted.add_argument("directory", help="directory to check")
    trusted.add_argument("manifest", help="signed manifest to verify")
    trusted.add_argument("store", help="versioned trust store JSON file")
    policy_check = commands.add_parser(
        "verify-policy",
        help="verify a version 3 manifest under a threshold signature policy",
    )
    policy_check.add_argument("directory", help="directory to check")
    policy_check.add_argument("manifest", help="version 3 manifest to verify")
    policy_check.add_argument("store", help="versioned trust store JSON file")
    policy_check.add_argument("policy", help="threshold policy JSON file")
    batching = commands.add_parser(
        "verify-batch",
        help="run several verification commands from one JSON batch file",
    )
    batching.add_argument("batch", help="UTF-8 JSON batch file")
    trust = commands.add_parser(
        "trust", help="manage the offline public-key trust store"
    )
    trust_commands = trust.add_subparsers(dest="trust_command", required=True)
    importing = trust_commands.add_parser(
        "import", help="import a PEM Ed25519 public key"
    )
    importing.add_argument("public", help="PEM Ed25519 public key to trust")
    importing.add_argument("store", help="trust store JSON file (created if absent)")
    revoking = trust_commands.add_parser(
        "revoke", help="revoke an imported key by key id"
    )
    revoking.add_argument("store", help="trust store JSON file")
    revoking.add_argument("key_id", help="SHA-256 hex id of the key to revoke")
    revoking.add_argument("reason", nargs="?", help="optional revocation reason")
    commands.add_parser(
        "demo", help="demonstrate inventory, signing and verification"
    )
    args = parser.parse_args()
    try:
        if args.command == "demo":
            return demo()
        if args.command == "inventory":
            result = inventory(args.directory)
            code = 0
        elif args.command == "sign":
            from .seal import sign_directory

            result = sign_directory(args.directory, args.private, args.manifest)
            code = 0
        elif args.command == "sign-multi":
            from .seal import sign_multi_directory

            result = sign_multi_directory(
                args.directory, args.manifest, args.private
            )
            code = 0
        elif args.command == "verify":
            from .seal import verify_directory

            result = verify_directory(args.directory, args.manifest, args.public)
            code = 0 if result["valid"] else 1
        elif args.command == "verify-trusted":
            from .trust import verify_trusted

            result = verify_trusted(args.directory, args.manifest, args.store)
            code = 0 if result["valid"] else 1
        elif args.command == "verify-policy":
            from .policy import verify_policy

            result = verify_policy(
                args.directory, args.manifest, args.store, args.policy
            )
            code = 0 if result["valid"] else 1
        elif args.command == "verify-batch":
            from .batch import verify_batch

            result, code = verify_batch(args.batch)
        elif args.command == "trust":
            from .trust import import_key, revoke_key

            if args.trust_command == "import":
                result = import_key(args.public, args.store)
            else:
                result = revoke_key(args.store, args.key_id, args.reason)
            code = 0
        else:  # pragma: no cover - argparse rejects unknown commands
            parser.error(f"unknown command: {args.command}")
            return 2
    except (OSError, ValueError) as error:
        print(f"release_seal: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
