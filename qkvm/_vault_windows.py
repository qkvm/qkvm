"""Private Windows key files: owner, Administrators and SYSTEM only."""
from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
import msvcrt
import os
import sys
from pathlib import Path
from typing import Any

if sys.platform != "win32":
    raise ImportError("Windows vault ACL support is Windows-only")

P = ctypes.c_void_p
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)


def api(dll: Any, name: str, args: list[Any], result: Any = wt.BOOL) -> Any:
    fn = getattr(dll, name)
    fn.argtypes, fn.restype = args, result
    return fn


def checked(value: Any) -> Any:
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


free = api(kernel, "LocalFree", [P], P)
close = api(kernel, "CloseHandle", [P])


def sid_text(sid: Any) -> str:
    text = wt.LPWSTR()
    checked(api(advapi, "ConvertSidToStringSidW", [P, ctypes.POINTER(wt.LPWSTR)])(sid, ctypes.byref(text)))
    try:
        return str(text.value)
    finally:
        free(text)


def current_sid() -> str:
    token = P()
    checked(api(advapi, "OpenProcessToken", [P, wt.DWORD, ctypes.POINTER(P)])(
        api(kernel, "GetCurrentProcess", [], P)(), 8, ctypes.byref(token)))
    try:
        size = wt.DWORD()
        info = api(advapi, "GetTokenInformation", [P, ctypes.c_int, P, wt.DWORD, ctypes.POINTER(wt.DWORD)])
        info(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        checked(info(token, 1, data, size, ctypes.byref(size)))
        return sid_text(ctypes.cast(data, ctypes.POINTER(P))[0])
    finally:
        close(token)


class Attributes(ctypes.Structure):
    _fields_ = [("length", wt.DWORD), ("descriptor", P), ("inherit", wt.BOOL)]


def create_private(path: Path) -> int:
    """Create an empty file with a restrictive DACL from its first instant."""
    descriptor = P()
    sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{current_sid()})"
    checked(api(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(P), P])(
        sddl, 1, ctypes.byref(descriptor), None))
    try:
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor, False)
        handle = api(kernel, "CreateFileW", [wt.LPCWSTR, wt.DWORD, wt.DWORD, P, wt.DWORD, wt.DWORD, P], P)(
            str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == P(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return int(msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY))
        except BaseException:
            close(handle)
            raise
    finally:
        free(descriptor)


class AclSize(ctypes.Structure):
    _fields_ = [("count", wt.DWORD), ("used", wt.DWORD), ("free", wt.DWORD)]


def validate_private(path: Path) -> None:
    """Refuse a key readable or writable by principals beyond the server/OS administrators."""
    descriptor, dacl, owner = P(), P(), P()
    error = api(advapi, "GetNamedSecurityInfoW", [wt.LPCWSTR, ctypes.c_int, wt.DWORD, P, P, ctypes.POINTER(P), P, ctypes.POINTER(P)], wt.DWORD)(
        str(path), 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if error:
        raise ctypes.WinError(error)
    try:
        if not dacl:
            raise PermissionError("the vault key has no access restrictions")
        size = AclSize()
        checked(api(advapi, "GetAclInformation", [P, P, wt.DWORD, ctypes.c_int])(dacl, ctypes.byref(size), ctypes.sizeof(size), 2))
        allowed = {current_sid(), "S-1-5-18", "S-1-5-32-544"}
        if not owner or sid_text(owner) not in allowed:
            raise PermissionError("the vault key is owned by another Windows account; use the server account")
        for index in range(size.count):
            ace = P()
            checked(api(advapi, "GetAce", [P, wt.DWORD, ctypes.POINTER(P)])(dacl, index, ctypes.byref(ace)))
            header = ctypes.string_at(ace, 4)
            if header[1] & 8 or header[0] == 1:  # inherit-only or an access denial
                continue
            if header[0] != 0 or sid_text(P(int(ace.value or 0) + 8)) not in allowed:
                raise PermissionError("the vault key is accessible to another Windows account; restrict its ACL")
    finally:
        free(descriptor)
