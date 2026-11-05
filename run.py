"""Local-only launcher. No debugger, remote bind or default credentials."""
import argparse
import os
from pathlib import Path

from waitress import serve

from authsense import create_app


def main():
    parser = argparse.ArgumentParser(description="AuthSense local research prototype")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--instance",type=Path,default=Path(__file__).resolve().parent/"instance")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Choose a port between 1024 and 65535.")
    os.umask(0o077)
    app = create_app({"INSTANCE_PATH":args.instance.resolve(),"WEBAUTHN_ORIGIN":f"http://localhost:{args.port}"})
    print(f"AuthSense: http://localhost:{args.port}", flush=True)
    print("Local prototype. Press Ctrl+C to stop. No training data is included.", flush=True)
    serve(app, host="127.0.0.1", port=args.port, threads=4,
          max_request_body_size=32768, clear_untrusted_proxy_headers=True)


if __name__ == "__main__":
    main()
