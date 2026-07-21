from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes


DPAPI_PREFIX = "dpapi:v1:"
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_byte))]


def _blob(value: bytes) -> tuple[DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(value)
    blob = DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte)))
    return blob, buffer


def _protect_windows(value: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DataBlob), wintypes.LPCWSTR, ctypes.POINTER(DataBlob), wintypes.LPVOID,
        wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    input_blob, input_buffer = _blob(value)
    output_blob = DataBlob()
    if not crypt32.CryptProtectData(
        ctypes.byref(input_blob), "MailScope provider credential", None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(ctypes.cast(output_blob.data, wintypes.HLOCAL))
        del input_buffer


def _unprotect_windows(value: bytes) -> bytes:
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DataBlob), ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(DataBlob),
        wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    input_blob, input_buffer = _blob(value)
    output_blob = DataBlob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(ctypes.cast(output_blob.data, wintypes.HLOCAL))
        del input_buffer


def protect_secret(value: str) -> str:
    if not value or value.startswith(DPAPI_PREFIX):
        return value
    if os.name != "nt":
        raise RuntimeError("MailScope credential protection requires Windows DPAPI")
    protected = _protect_windows(value.encode("utf-8"))
    return DPAPI_PREFIX + base64.b64encode(protected).decode("ascii")


def unprotect_secret(value: str) -> str:
    if not value or not value.startswith(DPAPI_PREFIX):
        # Accept legacy plaintext settings so they can be migrated on the next save.
        return value
    if os.name != "nt":
        raise RuntimeError("MailScope credential protection requires Windows DPAPI")
    encoded = value[len(DPAPI_PREFIX):]
    return _unprotect_windows(base64.b64decode(encoded, validate=True)).decode("utf-8")
