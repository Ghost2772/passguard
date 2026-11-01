import asyncio

from starlette.requests import ClientDisconnect, Request

from passguard.scanner.errors import failure
from passguard.scanner.models import MAX_UPLOAD_BYTES


async def read_archive(request: Request) -> bytes:
    # Authentication/CSRF dependencies in the control API run before this reader.
    # Do not use request.body() or a multipart parser which can spool unbounded
    # inputs before our own limit is checked. Original filenames are unused.
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/zip":
        raise failure("unsupported_media_type")
    length = request.headers.get("content-length")
    if length:
        try:
            size = int(length)
        except ValueError:
            raise failure("invalid_archive") from None
        if size < 0:
            raise failure("invalid_archive")
        if size > MAX_UPLOAD_BYTES:
            raise failure("archive_too_large")
    data = bytearray()
    try:
        async with asyncio.timeout(20):
            async for chunk in request.stream():
                if len(data) + len(chunk) > MAX_UPLOAD_BYTES:
                    raise failure("archive_too_large")
                data.extend(chunk)
    except TimeoutError:
        raise failure("upload_timeout") from None
    except ClientDisconnect:
        raise failure("invalid_archive") from None
    return bytes(data)
