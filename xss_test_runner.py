
import argparse
import csv
import ipaddress
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

SIGNATURE_FILE = Path("xss-signatures.txt")
RESULT_FILE = Path("results/xss-results.csv")


def validate_local_target(url):
    parsed = urlsplit(url)

    if parsed.scheme != "http":
        raise ValueError("Demo runner accepts local HTTP targets only.")

    host = parsed.hostname or ""

    if host == "localhost":
        return

    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass

    raise ValueError("Use localhost or 127.0.0.1 for this demo.")


def load_signatures():
    tests = []

    with SIGNATURE_FILE.open(encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split("|", 2)

            if len(parts) != 3:
                continue

            test_id, description, payload = parts

            tests.append({
                "id": test_id,
                "description": description,
                "payload": payload
            })

    return tests


def build_test_url(base_url, parameter, payload):
    parsed = urlsplit(base_url)

    query = dict(parse_qsl(parsed.query))
    query[parameter] = payload

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(query),
        parsed.fragment
    ))


def execute_test(base_url, parameter, test):
    test_url = build_test_url(
        base_url,
        parameter,
        test["payload"]
    )

    request = Request(
        test_url,
        headers={"User-Agent": "WAFscan-Demo-Runner/1.0"}
    )

    status = None
    reflected = False
    error = ""

    try:
        with urlopen(request, timeout=10) as response:
            status = response.status
            body = response.read(1024 * 1024).decode(
                "utf-8", errors="replace"
            )
            reflected = test["payload"] in body

    except HTTPError as exc:
        status = exc.code
        error = f"HTTP {exc.code}"

    except (URLError, TimeoutError, OSError) as exc:
        error = str(exc)

    return {
        "test_id": test["id"],
        "description": test["description"],
        "http_status": status,
        "raw_marker_reflected": reflected,
        "error": error
    }


def main():
    parser = argparse.ArgumentParser(
        description="WAFscan XSS sample test runner"
    )

    parser.add_argument(
        "--url",
        required=True,
        help="Local authorized test endpoint"
    )

    parser.add_argument(
        "--parameter",
        default="q",
        help="HTTP parameter to test"
    )

    args = parser.parse_args()

    validate_local_target(args.url)

    tests = load_signatures()

    if not tests:
        print("No signatures found.")
        return

    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)

    results = []

    print(f"Loaded {len(tests)} tests")

    for test in tests:
        print(f"Running {test['id']}: {test['description']}")

        result = execute_test(
            args.url,
            args.parameter,
            test
        )

        results.append(result)
        time.sleep(0.2)

    with RESULT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys()
        )

        writer.writeheader()
        writer.writerows(results)

    print(f"\nCompleted: {len(results)} tests")
    print(f"Results saved to: {RESULT_FILE}")


if __name__ == "__main__":
    main()
