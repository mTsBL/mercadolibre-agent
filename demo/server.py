"""Local disposable challenge-like target: python3 -m demo.server [--safe] [--spa]."""
import argparse
from http.server import ThreadingHTTPServer
from tests.fixtures import application, USERNAME, PASSWORD


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--safe", action="store_true")
    parser.add_argument("--spa", action="store_true")
    args = parser.parse_args()
    handler, prefix, _ = application("spa" if args.spa else "cookie", args.safe)
    server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    print(f"Disposable synthetic app: http://127.0.0.1:{args.port}", flush=True)
    print(f"CHALLENGE_USERNAME={USERNAME} CHALLENGE_PASSWORD={PASSWORD}", flush=True)
    print("Routes are randomized on each start. Ctrl+C stops the app.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
