#!/usr/bin/env python3
"""Create a Google Drive OAuth token JSON for personal Gmail capture."""

from __future__ import annotations

import argparse
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow


SCOPES = ["https://www.googleapis.com/auth/drive"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a local OAuth browser flow and write a Drive token JSON."
    )
    parser.add_argument(
        "--client-secrets",
        default=".secrets/google-oauth-client.json",
        help="OAuth Desktop client JSON downloaded from Google Cloud.",
    )
    parser.add_argument(
        "--token-out",
        default=".secrets/google-oauth-token.json",
        help="Path for the generated authorized-user token JSON.",
    )
    args = parser.parse_args()

    client_secrets = Path(args.client_secrets)
    token_out = Path(args.token_out)
    token_out.parent.mkdir(parents=True, exist_ok=True)

    flow = InstalledAppFlow.from_client_secrets_file(str(client_secrets), scopes=SCOPES)
    credentials = flow.run_local_server(
        host="localhost",
        port=0,
        prompt="consent",
        authorization_prompt_message="Open this URL to authorize ROPE Google Drive capture: {url}",
    )
    token_out.write_text(credentials.to_json() + "\n", encoding="utf-8")
    token_out.chmod(0o600)
    print(f"Wrote OAuth token to {token_out}")


if __name__ == "__main__":
    main()
