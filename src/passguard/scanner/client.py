import json
import os

import httpx
from pydantic import ValidationError

from passguard.scanner.errors import ERRORS, failure
from passguard.scanner.models import ScanResult


class ScannerClient:
    def __init__(self, url=None):
        self.http = httpx.Client(base_url=url or os.getenv("SCANNER_URL", "http://scanner:8002"),
                                 timeout=35, trust_env=False)

    def close(self):
        self.http.close()

    def scan(self, archive: bytes) -> ScanResult:
        try:
            with self.http.stream("POST", "/scan", content=archive,
                                  headers={"Content-Type": "application/zip"}) as response:
                content = bytearray()
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > 2 * 1024 * 1024:
                        raise failure("scanner_unavailable")
                    content.extend(chunk)
                data = json.loads(content)
                if response.status_code != 200:
                    code = data.get("code") if isinstance(data, dict) else None
                    if isinstance(code, str) and code in ERRORS and response.status_code == ERRORS[code][0]:
                        raise failure(code)
                    raise failure("scanner_unavailable")
                return ScanResult.model_validate(data)
        except (httpx.HTTPError, ValueError, ValidationError):
            raise failure("scanner_unavailable") from None
