#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared HTTP helper for scanners — urllib only, bounded and safe.

- No request is ever destructive by default (GET/HEAD/OPTIONS only).
- POST is used only by the auth/registration auditors, only with explicit
  user confirmation and only against an authorized scope.
- Every call is time-bounded and never raises: errors are returned.
"""
import time
import urllib.error
import urllib.parse
import urllib.request

USER_AGENT = "Conan-Framework/3.0 (authorized security audit)"


class _ChainHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append((code, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, method="GET", data=None, headers=None, timeout=15, max_bytes=200000):
    """Return dict: status, final_url, headers, body, chain, error, elapsed_ms.

    Never raises. `headers` is the raw HTTPMessage (supports get_all).
    """
    handler = _ChainHandler()
    opener = urllib.request.build_opener(handler)
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    t0 = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(max_bytes).decode(errors="ignore")
            return {"status": resp.status, "final_url": resp.geturl(),
                    "headers": resp.headers, "body": body, "chain": handler.chain,
                    "error": None, "elapsed_ms": int((time.time() - t0) * 1000)}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(max_bytes).decode(errors="ignore")
        except Exception:
            body = ""
        return {"status": exc.code, "final_url": exc.geturl(),
                "headers": exc.headers or {}, "body": body, "chain": handler.chain,
                "error": "HTTP %s" % exc.code, "elapsed_ms": int((time.time() - t0) * 1000)}
    except Exception as exc:
        return {"status": None, "final_url": url, "headers": {}, "body": "",
                "chain": handler.chain, "error": str(exc),
                "elapsed_ms": int((time.time() - t0) * 1000)}


def get(url, timeout=15, max_bytes=200000):
    return request(url, method="GET", timeout=timeout, max_bytes=max_bytes)


def head(url, timeout=10):
    return request(url, method="HEAD", timeout=timeout, max_bytes=0)
