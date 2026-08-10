"""Agent Guard command line client."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .client import AgentGuardClient


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentguard")
    parser.add_argument("--url", default="http://127.0.0.1:8787")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify", help="verify a signed AgentIdentity token")
    verify.add_argument("token", help="token text or path to a token file")
    authorize = commands.add_parser("authorize", help="authorize an AgentRequest JSON file")
    authorize.add_argument("request")
    revoke = commands.add_parser("revoke", help="revoke an AGP subject")
    revoke.add_argument("subject_type")
    revoke.add_argument("subject_id")
    revoke.add_argument("--reason", required=True)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    client = AgentGuardClient(args.url)
    if args.command == "verify":
        path = Path(args.token)
        token = path.read_text(encoding="utf-8").strip() if path.is_file() else args.token
        result = client.verify_identity(token)
    elif args.command == "authorize":
        result = client.authorize(json.loads(Path(args.request).read_text(encoding="utf-8")))
    else:
        result = client.revoke(
            subject_type=args.subject_type,
            subject_id=args.subject_id,
            reason=args.reason,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

