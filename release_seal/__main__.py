"""Command-line entry point."""

import argparse
import json
import sys

from .inventory import inventory


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="release_seal", description="Create an inventory of a local directory."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("inventory", help="list ordinary files and SHA-256 hashes")
    listing.add_argument("directory", help="directory to read")
    args = parser.parse_args()
    try:
        result = inventory(args.directory)
    except (OSError, ValueError) as error:
        print(f"release_seal: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
