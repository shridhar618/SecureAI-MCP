"""python -m app.mcp_server [--http] | --mint-token USER | --revoke-token ID

stdout is the MCP protocol channel in stdio mode, so everything the Flask
app prints during startup is redirected to stderr.
"""

import argparse
import contextlib
import os
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.mcp_server", description=__doc__)
    ap.add_argument("--http", action="store_true", help="serve streamable HTTP (bearer token) instead of stdio")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--mint-token", metavar="USERNAME", help="create a token for a user and print it once")
    ap.add_argument("--days", type=int, default=30, help="token lifetime in days (with --mint-token)")
    ap.add_argument("--label", default="", help="label for the token (with --mint-token)")
    ap.add_argument("--revoke-token", metavar="ID", type=int)
    args = ap.parse_args(argv)

    with contextlib.redirect_stdout(sys.stderr):
        from app import create_app

        app = create_app()

    if args.mint_token or args.revoke_token:
        from datetime import UTC, datetime

        from app import db
        from app.models.mcp_token import McpToken
        from app.models.user import User

        with app.app_context():
            if args.mint_token:
                user = User.query.filter_by(username=args.mint_token).first()
                if not user or user.is_active is False:
                    print("No such active user.", file=sys.stderr)
                    return 1
                row, raw = McpToken.mint(user, days=max(1, min(args.days, 365)), label=args.label)
                print(f"token id {row.id} for {user.username}, expires {row.expires_at:%Y-%m-%d}", file=sys.stderr)
                print(raw)
            else:
                row = db.session.get(McpToken, args.revoke_token)
                if not row:
                    print("No such token.", file=sys.stderr)
                    return 1
                row.revoked_at = datetime.now(UTC)
                db.session.commit()
                print(f"revoked token {row.id}", file=sys.stderr)
        return 0

    from app.mcp_server.auth import AuthError, authenticate
    from app.mcp_server.server import build_server

    if not args.http:
        with app.app_context():
            try:
                authenticate(os.environ.get("SECUREAI_MCP_TOKEN"))
            except AuthError as exc:
                print(f"Refusing to start: {exc} Set SECUREAI_MCP_TOKEN.", file=sys.stderr)
                return 2

    server = build_server(app, http=args.http)
    if args.http:
        server.run("streamable-http", host=args.host, port=args.port)
    else:
        server.run("stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
