#!/usr/bin/env python3
import argparse
import concurrent.futures
import json
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://10.10.10.1:8080/api/inspect")
parser.add_argument("--requests", type=int, default=20)
parser.add_argument("--workers", type=int, default=5)
args = parser.parse_args()

payload = json.dumps({"text": "Concurrent test test@example.com 0912345678"}).encode()

def one(i):
    req = urllib.request.Request(
        args.url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return i, response.status

with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
    results = list(pool.map(one, range(args.requests)))

ok = sum(1 for _, status in results if status == 200)
print(f"completed={len(results)} ok={ok} failed={len(results)-ok}")
