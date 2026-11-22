import json
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener


class RequestFailed(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"HTTP request failed ({status})")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, url, data=None, headers=None, *, attempts=3, timeout=15):
    payload = json.dumps(data).encode() if data is not None else None
    req = Request(url, data=payload, headers={"Content-Type": "application/json",
                  "User-Agent": "juice-shop-appsec", **(headers or {})}, method=method)
    for attempt in range(attempts):
        delay = 2 ** attempt
        try:
            with build_opener(NoRedirect()).open(req, timeout=timeout) as response:
                raw = response.read(16_000_001)
                if len(raw) > 16_000_000:
                    raise ValueError("Response exceeded size limit")
                return json.loads(raw) if raw else None
        except HTTPError as error:
            status = error.code
            retry_after = error.headers.get("Retry-After", "")
            if retry_after.isdecimal():
                delay = min(30, max(delay, int(retry_after)))
            error.close()
            if status not in {429, 500, 502, 503, 504}:
                raise RequestFailed(status) from None
        except (URLError, TimeoutError):
            status = "network timeout or failure"
        if attempt + 1 < attempts:
            time.sleep(delay)
    raise RequestFailed(status)
