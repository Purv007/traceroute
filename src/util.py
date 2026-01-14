import os, base64, time, datetime, pathlib

def ensure_out():
    pathlib.Path("out").mkdir(parents=True, exist_ok=True)

def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def now_ns():
    return time.perf_counter_ns()

def ns_to_ms(ns: int) -> float:
    return ns / 1_000_000.0

def write(path: str, text: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
