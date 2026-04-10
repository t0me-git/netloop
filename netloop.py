#!/usr/bin/env python3
"""netloop: Wrapper automation for network penetration testing tools."""

from __future__ import annotations

import argparse
import sys

import getinit_1
import netloop_utils


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="netloop automation utility")
    sub = parser.add_subparsers(dest="command", required=True)

    getinit_1.configure_parser(sub)
    netloop_utils.configure_parser(sub)

    return parser


COMMAND_HANDLERS = {
    "ntlmv2": getinit_1.run,
    "reset": netloop_utils.run_reset,
    "install": netloop_utils.run_install,
}


def main() -> int:
    parser = build_parser()
    parsed_args = parser.parse_args()

    handler = COMMAND_HANDLERS.get(parsed_args.command)
    if handler is None:
        print(f"Unsupported command: {parsed_args.command}", file=sys.stderr)
        return 2

    return handler(parsed_args)


if __name__ == "__main__":
    sys.exit(main())
