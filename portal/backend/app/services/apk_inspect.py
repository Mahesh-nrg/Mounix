"""Parses an uploaded APK/XAPK/APKM/APKS using the `apkfile` library, which already handles
split-APK layout, per-device ABI/lang/dpi compatibility, and OBB files - see its `install.py` for
the compatibility-resolution logic we rely on (`bundle.install(device_id=...)` in adb_service).

Flutter detection is the one thing apkfile doesn't need to know about: Flutter apps embed their
own BoringSSL inside `libflutter.so` and pin *inside that library*, bypassing the Android
TrustManager entirely, so the standard Frida unpinning script (which hooks TrustManager/OkHttp)
does nothing for them - a Flutter-specific script must be selected instead (see frida_service.py).
"""

import asyncio
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Union

import apkfile

Bundle = Union[apkfile.ApkFile, apkfile.XapkFile, apkfile.ApkmFile, apkfile.ApksFile]

_BUNDLE_TYPES: dict[str, type] = {
    ".apk": apkfile.ApkFile,
    ".xapk": apkfile.XapkFile,
    ".apkm": apkfile.ApkmFile,
    ".apks": apkfile.ApksFile,
}


class UnsupportedFileType(ValueError):
    pass


@dataclass
class ParsedApp:
    bundle: Bundle
    package_name: str
    is_split: bool
    is_flutter: bool
    launchable_activity: str | None


def _find_zip_member_suffix(path: Path, suffix: str) -> bool:
    with zipfile.ZipFile(path) as zf:
        return any(name.endswith(suffix) for name in zf.namelist())


def _detect_flutter(path: Path, bundle: Bundle) -> bool:
    # A plain .apk is itself a zip we can scan directly; a bundle (.xapk/.apkm/.apks) is a zip of
    # zips, so check its base apk's raw bytes instead of re-extracting anything to disk.
    if isinstance(bundle, apkfile.ApkFile):
        return _find_zip_member_suffix(path, "libflutter.so")
    base_bytes = bundle.base.get_raw()
    import io

    with zipfile.ZipFile(io.BytesIO(base_bytes)) as zf:
        return any(name.endswith("libflutter.so") for name in zf.namelist())


def _parse_sync(path: Path) -> ParsedApp:
    suffix = path.suffix.lower()
    bundle_cls = _BUNDLE_TYPES.get(suffix)
    if bundle_cls is None:
        raise UnsupportedFileType(f"Unsupported upload type: {suffix or '(none)'}")

    bundle = bundle_cls(str(path))
    is_split = not isinstance(bundle, apkfile.ApkFile)
    is_flutter = _detect_flutter(path, bundle)

    return ParsedApp(
        bundle=bundle,
        package_name=bundle.package_name,
        is_split=is_split,
        is_flutter=is_flutter,
        launchable_activity=bundle.launchable_activity,
    )


async def parse_upload(path: Path) -> ParsedApp:
    return await asyncio.to_thread(_parse_sync, path)
