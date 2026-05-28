import hashlib
import hmac
import logging
import mimetypes
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote, urlencode

from core.config import settings
from schemas.storage import (
    BucketInfo,
    BucketListResponse,
    BucketRequest,
    BucketResponse,
    DeleteResponse,
    FileUpDownRequest,
    FileUpDownResponse,
    ObjectInfo,
    ObjectListResponse,
    ObjectRequest,
    OSSBaseModel,
    RenameRequest,
    RenameResponse,
)

logger = logging.getLogger(__name__)

STORAGE_ROOT = os.environ.get("LOCAL_STORAGE_ROOT", "/data/uploads")
SIGNED_URL_EXPIRY = 3600


_FRONTEND_PROXY_URL = "https://awqafmaintstaff.com"


def _get_backend_url() -> str:
    # Override with PUBLIC_URL env var if set.
    public = os.environ.get("PUBLIC_URL", "").rstrip("/")
    if public:
        return public
    # In production (Railway), route signed URLs through the frontend's
    # Vercel API proxy to avoid cross-origin ERR_BLOCKED_BY_RESPONSE.
    if os.environ.get("RAILWAY_PUBLIC_DOMAIN"):
        return _FRONTEND_PROXY_URL
    try:
        return settings.backend_url
    except Exception:
        return f"http://0.0.0.0:{os.environ.get('PORT', '8000')}"


def _signing_key() -> bytes:
    try:
        return settings.jwt_secret_key.encode()
    except Exception:
        return b"local-dev-key"


def sign_url_params(bucket: str, key: str, expires: int) -> str:
    msg = f"{bucket}:{key}:{expires}".encode()
    return hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()


def verify_signature(bucket: str, key: str, expires: int, sig: str) -> bool:
    if int(time.time()) > expires:
        return False
    expected = sign_url_params(bucket, key, expires)
    return hmac.compare_digest(expected, sig)


def _bucket_path(bucket_name: str) -> Path:
    safe = bucket_name.replace("..", "").replace("/", "")
    return Path(STORAGE_ROOT) / safe


def _object_path(bucket_name: str, object_key: str) -> Path:
    safe_key = object_key.replace("..", "")
    return _bucket_path(bucket_name) / safe_key


class StorageService:
    """Local filesystem storage service — drop-in replacement for Atoms Cloud OSS."""

    def __init__(self):
        os.makedirs(STORAGE_ROOT, exist_ok=True)

    async def create_bucket(self, request: BucketRequest) -> BucketResponse:
        bp = _bucket_path(request.bucket_name)
        bp.mkdir(parents=True, exist_ok=True)
        return BucketResponse(
            bucket_name=request.bucket_name,
            visibility=request.visibility,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    async def list_buckets(self) -> BucketListResponse:
        root = Path(STORAGE_ROOT)
        resp = BucketListResponse()
        if root.exists():
            for d in sorted(root.iterdir()):
                if d.is_dir():
                    resp.buckets.append(BucketInfo(bucket_name=d.name, visibility="public"))
        return resp

    async def list_objects(self, request: OSSBaseModel) -> ObjectListResponse:
        bp = _bucket_path(request.bucket_name)
        resp = ObjectListResponse()
        if bp.exists():
            for f in sorted(bp.rglob("*")):
                if f.is_file():
                    rel = str(f.relative_to(bp))
                    stat = f.stat()
                    resp.objects.append(
                        ObjectInfo(
                            bucket_name=request.bucket_name,
                            object_key=rel,
                            size=stat.st_size,
                            last_modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                            etag=hashlib.md5(rel.encode()).hexdigest(),
                        )
                    )
        return resp

    async def get_object_info(self, request: ObjectRequest) -> ObjectInfo:
        fp = _object_path(request.bucket_name, request.object_key)
        if not fp.exists():
            raise FileNotFoundError(f"Object not found: {request.object_key}")
        stat = fp.stat()
        return ObjectInfo(
            bucket_name=request.bucket_name,
            object_key=request.object_key,
            size=stat.st_size,
            last_modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            etag=hashlib.md5(request.object_key.encode()).hexdigest(),
        )

    async def rename_object(self, request: RenameRequest) -> RenameResponse:
        src = _object_path(request.bucket_name, request.source_key)
        dst = _object_path(request.bucket_name, request.target_key)
        if not src.exists():
            raise FileNotFoundError(f"Source not found: {request.source_key}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        return RenameResponse(success=True)

    async def delete_object(self, request: ObjectRequest) -> DeleteResponse:
        fp = _object_path(request.bucket_name, request.object_key)
        if fp.exists():
            fp.unlink()
        return DeleteResponse(success=True)

    async def create_upload_url(self, request: FileUpDownRequest) -> FileUpDownResponse:
        _bucket_path(request.bucket_name).mkdir(parents=True, exist_ok=True)
        expires = int(time.time()) + SIGNED_URL_EXPIRY
        sig = sign_url_params(request.bucket_name, request.object_key, expires)
        base = _get_backend_url()
        params = urlencode({
            "bucket": request.bucket_name,
            "key": request.object_key,
            "expires": expires,
            "sig": sig,
        })
        upload_url = f"{base}/api/v1/local-storage/upload?{params}"
        return FileUpDownResponse(
            upload_url=upload_url,
            expires_at=datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
        )

    async def create_download_url(self, request: FileUpDownRequest) -> FileUpDownResponse:
        expires = int(time.time()) + SIGNED_URL_EXPIRY
        sig = sign_url_params(request.bucket_name, request.object_key, expires)
        base = _get_backend_url()
        params = urlencode({
            "bucket": request.bucket_name,
            "key": request.object_key,
            "expires": expires,
            "sig": sig,
        })
        download_url = f"{base}/api/v1/local-storage/download?{params}"
        return FileUpDownResponse(
            download_url=download_url,
            expires_at=datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(),
        )

    def save_file(self, bucket_name: str, object_key: str, data: bytes) -> Path:
        fp = _object_path(bucket_name, object_key)
        fp.parent.mkdir(parents=True, exist_ok=True)
        fp.write_bytes(data)
        return fp

    def read_file(self, bucket_name: str, object_key: str) -> Optional[bytes]:
        fp = _object_path(bucket_name, object_key)
        if not fp.exists():
            return None
        return fp.read_bytes()
