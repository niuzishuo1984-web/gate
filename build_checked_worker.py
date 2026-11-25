#!/usr/bin/env python3
"""Rebuild the audited SSTP-only worker; every input/output is verified."""
import base64
import hashlib
import json
import subprocess
import tempfile
import urllib.request
import zlib
from pathlib import Path

URL = "https://raw.githubusercontent.com/lsh8848/cm-Workers-CheckSocks5/2f31cf9a242444eb22905d888d4d8871b0625b3a/_worker.js"
SOURCE_SHA = "6cab20b8474fe823740fa020c5e1ad832ace42546fc3fed5c5d5b9f1d8273824"
READABLE_SHA = "2ddc06615c51d0d44a12f768b8017026f60f5ca16c450cfc8573a322945ede87"
MIN_SHA = "38a7c2711e5c9a2625a04f71004e20e35cd3ad5a77f5996a1778d4bc8958f5c2"
FINAL_SHA = "0f76fb587e72a7e2f387cae982a7ee682b1a2b1272a61fcb81511cb2aa35a07a"
PATCH = "eNq1V21v2zYQ/ivXYKiklZbjl7zDMLI0WbM2cRDbyIc4LQiZtrXIoktSTbPU/31HUpKp2CnaoYuB2BR5z708x7vT7e1WEqstshXPF1woeIKIpymLFCxhIvgcvCjh2XiSUMEOJY/umZLe0SjduiO3W1JEW6RBdvRvi4LCUsHb07Pj4YfBp6ve9aAPHQSVUi0Ood1uwbIqvEtaK+lJlkYq5inQTM24iP+henVG4yQTzGfpFwKCfc6YVAE8jdKRsurw/ySe4pHxgN+zFBWqxwXjE0CJbnjy7vTk/adB7/3pJXQ6HfCkEnE69aCr9yvbh+Bp30YqnoD/6hlsrnKkBFOZSCFlD3DN5AJNYP5f/d5laIHjyaP/BEwILhDv2PUEYgkpdw32YBmQAnikpKIqk4ews90ixbMZo2Mm8OETeCc8VSxVtQH65yE6XSySODLY9b8lT48gmlEhmeoMB2e1fY+gCI1mrKYFBU+0TMprUnHBULVVsQyMz0uXl2abNFa8FIGu0IJhzskIcxPDKVN+1WMvgG/fiqhakDlV0QyFK2CheerXP/7BMNHELYxG6u6Nf/txNJJ3b4Lf6nGwIsYiIK75cdu4g1fI6y+ha5gWZr3ITXu7sYGb4slI/TxJruyLbLmnbm5uajrMqEUDGy02cJ5LYmvPkmgW7VaVUUN+EZssSTC8lQxo75Lm6jwAlY9pBBOmacp5J/oCmTgD/q1SJL+wzzneeI+PrLDm1RENILfMeXbkqkHQafxiCvbMrpN7hYri9JyhXWNbDnpXg/PeZd8rdVYyRYeG6AKWs9/cbhMoaY+4kO/swrcmBbAMKpZmIkEzNebw+kNpAD51XX+F63BB1SylcxYq/oE/MHFCUX+AaUqFkjexmvleHbMjuveCMuhQGK0TqzQazc2iiEm0cEITyUiZ35dYfSY8S3Vyu261tVt5UEsHlvYrYVixtN4rKuhcam9svhTWa+Mlpl80syfCGZW+p0u+trQq+mRqM1pitgl8oUmGyzUIw6OFsCyaxlHGywV9/Ro2W7AQ/OtjJViWkoW+fcg+SLyY6kqf6iPgnPmbzchxrB1FcKwhFqobaqfy7mJt/iGvrXQoMCNK95abvVxzQuGtQOQxi/iYDa/PTzg28BQrgl/JJYmlh5WJEyYsnapZgCoXCcWNOhbY+ps60Y6tPKsWaq2prM/agY4fliV5FQpz4gcdLwv3sgLxgsMlb5qHi01WmZ11s9YIdxAwa9boX22jbS7M/0N1SfaLnP/c5b6IpcSOZr3UGjEBFBMhDCUDmwFdw9+MS3Voxj0uig0bQjOn1evlgbUysb1eJpR4/H45og80LkqI1uI7PpadIIwm3TDiCYdu1xQY3XvXSxJEhj3f+Pxfy6D56mIXkJJOmb7XfTML5KgEVIx7is5xZtWV+y32WKzEip/3e/nJoBqYnU2BMbRWmmpj/8Cdd0uzcbQ7NpYWrb92nCT8oZY3ssMCWleg3/VUt/H0helqUk8Df54OCFz1+vi/6G8vSeX9S0u5kwuB6iC3Ln5Bv9aOp2b42N/FzPCez/YH++7IUQ73mqNq08Rrg/UHo1CGIwzDDb2V/LIJONLPCBTTFYF5JlVNMLyt8VhPVOiLpq5idJlYeIKu2Efrmw79HdOsdCVYOi59b/y0cHbSaAYrYGfQWI+ZGTSq2dVstHFwd4c8/cnbRYZvdQlev3ks9WSmL/qJfdOzZQ+Tngpsd++4Huzs7yusAHbu1h8Loac6c58fcCIZ4D3hmfIr6ATyd6rzi9PecPDpoo8kmItfvFvqgOorNgYUNh3VcWIHXz1a++X6YKdJ9rZ3nTfGvW2y2m7stXHKXa33WjsNsrvfurv7F4wY8rc="

def verify(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("SHA-256 mismatch; refusing to deploy")

with urllib.request.urlopen(URL, timeout=60) as response:
    original = response.read(400_000)
verify(original, SOURCE_SHA)
lines = original.decode("utf-8").replace("\r\n", "\n").splitlines(keepends=True)
patch = json.loads(zlib.decompress(base64.b64decode(PATCH)))
readable = "".join("".join(lines[o[1]:o[1]+o[2]]) if o[0] == "src" else o[1] for o in patch).encode("utf-8")
verify(readable, READABLE_SHA)
with tempfile.TemporaryDirectory() as tmp:
    inp, out = Path(tmp)/"readable.js", Path(tmp)/"min.js"
    inp.write_bytes(readable)
    subprocess.run(["npx", "--yes", "--package=terser@5.51.4", "terser", str(inp), "-c", "-m", "-o", str(out)], check=True)
    mini = out.read_bytes()
verify(mini, MIN_SHA)
text = mini.decode("utf-8")
parts = [["s",0,9383],["s",9389,2],["l","!"],["s",9392,63],["l",";"],["s",9455,1],["l",";"],["s",9462,4592],["l","return"],["s",14054,891],["l",","],["s",14952,30163]]
result = "".join(text[o[1]:o[1]+o[2]] if o[0] == "s" else o[1] for o in parts).encode("utf-8")
verify(result, FINAL_SHA)
Path("_worker.js").write_bytes(result)
subprocess.run(["node", "--check", "_worker.js"], check=True)
print("Audited worker reconstructed and verified.")
