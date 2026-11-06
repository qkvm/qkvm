"""On Windows: who may change or read a folder or a file, and a folder made its owner's alone (never one that is found).

Standard library only, and no import of the rest of the package: the starter (__main__) loads this file from beside itself,
under a name of its own, to judge an installed update's folders with the installed copy's code; the program proper (cli,
vault_storage, unlock) imports it as qkvm._folders, its own copy's. Never imported by the starter under the package's name:
what the starter loads so is kept, as installed, for the whole process, and an update's code would get that copy of it
(an in-app update from 0.2.0 that asked 0.2.0's _where for these names ended in an ImportError: the review of 2026-11-01).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

# What a Windows access entry may grant, as far as it lets somebody change what is there: write, append, extended
# attributes, delete what is in a folder, attributes, delete, change the ACL, take the ownership, and the generic all and
# write. And what lets somebody read it: read (a file's data, a folder's list), and the generic all and read.
WRITE = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
READ = 0x1 | 0x10000000 | 0x80000000
TRUSTED = ("S-1-5-18", "S-1-5-32-544")  # SYSTEM, the Administrators: they can do anything with the computer anyway
OWNER_RIGHTS = "S-1-3-4"  # stands for whoever owns it (who is checked by itself); Python's mkdir(mode=0o700) grants it
CREATOR_OWNER = "S-1-3-0"  # stands, in an entry passed to what is made in a folder, for whoever makes it


_calls: list[Any] = []  # (the calls below, once made)


def _windows() -> Any:
    """The few Windows calls the ACL of a folder takes (ctypes: the standard library). Made when first asked for."""
    if sys.platform != "win32":
        raise OSError("who may write a folder is kept in its ACL on Windows only")
    if _calls:
        return _calls[0]
    import ctypes
    from ctypes import wintypes as w

    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    p = ctypes.c_void_p

    def call(dll: Any, name: str, args: list[Any], result: Any = w.BOOL) -> Any:
        fn = getattr(dll, name)
        fn.argtypes, fn.restype = args, result
        return fn

    class Calls:
        c = ctypes
        P = p
        free = call(kernel, "LocalFree", [p], p)
        close = call(kernel, "CloseHandle", [p])
        process = call(kernel, "GetCurrentProcess", [], p)
        token = call(advapi, "OpenProcessToken", [p, w.DWORD, ctypes.POINTER(p)])
        token_info = call(advapi, "GetTokenInformation", [p, ctypes.c_int, p, w.DWORD, ctypes.POINTER(w.DWORD)])
        sid_text = call(advapi, "ConvertSidToStringSidW", [p, ctypes.POINTER(w.LPWSTR)])
        get = call(advapi, "GetNamedSecurityInfoW", [w.LPCWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(p), p, ctypes.POINTER(p), p, ctypes.POINTER(p)], w.DWORD)
        acl_size = call(advapi, "GetAclInformation", [p, p, w.DWORD, ctypes.c_int])
        ace = call(advapi, "GetAce", [p, w.DWORD, ctypes.POINTER(p)])
        from_text = call(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, ctypes.POINTER(p), p])
        make = call(kernel, "CreateDirectoryW", [w.LPCWSTR, p])
        create = call(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, p, w.DWORD, w.DWORD, p], p)
        volume_path = call(kernel, "GetVolumePathNameW", [w.LPCWSTR, w.LPWSTR, w.DWORD])
        volume_info = call(kernel, "GetVolumeInformationW", [w.LPCWSTR, w.LPWSTR, w.DWORD, p, p, ctypes.POINTER(w.DWORD), w.LPWSTR, w.DWORD])
        sid_of_text = call(advapi, "ConvertStringSidToSidW", [w.LPCWSTR, ctypes.POINTER(p)])
        lookup = call(advapi, "LookupAccountSidW", [w.LPCWSTR, p, w.LPWSTR, ctypes.POINTER(w.DWORD), w.LPWSTR, ctypes.POINTER(w.DWORD), ctypes.POINTER(ctypes.c_int)])

        class Attributes(ctypes.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", p), ("inherit", w.BOOL)]

    _calls.append(Calls)
    return Calls


def _sid(win: Any, sid: Any) -> str:
    text = win.c.c_wchar_p()
    if not win.sid_text(sid, win.c.byref(text)):
        raise win.c.WinError(win.c.get_last_error())
    try:
        return str(text.value)
    finally:
        win.free(text)


def _me(win: Any) -> str:
    """The account this program runs as (TokenUser)."""
    token = win.P()
    if not win.token(win.process(), 8, win.c.byref(token)):  # TOKEN_QUERY
        raise win.c.WinError(win.c.get_last_error())
    try:
        size = win.c.c_ulong()
        win.token_info(token, 1, None, 0, win.c.byref(size))  # TokenUser
        buffer = win.c.create_string_buffer(size.value)
        if not win.token_info(token, 1, buffer, size, win.c.byref(size)):
            raise win.c.WinError(win.c.get_last_error())
        return _sid(win, win.c.cast(buffer, win.c.POINTER(win.P))[0])
    finally:
        win.close(token)


def _security(win: Any, path: Path) -> tuple[str, list[tuple[int, int, int, str]] | None]:
    """Who owns what is at `path`, and its access entries: (kind, flags, rights, whose); None for no ACL at all (everybody)."""
    owner, dacl, descriptor = win.P(), win.P(), win.P()
    error = win.get(str(path), 1, 1 | 4, win.c.byref(owner), None, win.c.byref(dacl), None, win.c.byref(descriptor))  # owner, DACL
    if error:
        raise win.c.WinError(error)
    try:
        if not dacl:
            return _sid(win, owner), None
        size = (win.c.c_ulong * 3)()
        if not win.acl_size(dacl, win.c.byref(size), win.c.sizeof(size), 2):  # AclSizeInformation: the count comes first
            raise win.c.WinError(win.c.get_last_error())
        found = []
        for index in range(size[0]):
            ace = win.P()
            if not win.ace(dacl, index, win.c.byref(ace)):
                raise win.c.WinError(win.c.get_last_error())
            kind, flags = win.c.string_at(ace, 2)
            rights = int.from_bytes(win.c.string_at(int(ace.value or 0) + 4, 4), "little")
            # (Whose: where an entry of the two plain kinds, allowed and denied, keeps it. Another kind is judged by its kind.)
            found.append((kind, flags, rights, _sid(win, win.P(int(ace.value or 0) + 8)) if kind in (0, 1) else ""))
        return _sid(win, owner), found
    finally:
        win.free(descriptor)


GENERAL = "in its Properties, Security: leave it to your account, SYSTEM and the Administrators"


def fix_line(path: Path, link: bool = False) -> str:
    """The line that leaves what is at `path` this account's, SYSTEM's and the Administrators' alone (Windows).

    Its own entries only (no /T): a folder's are inherited by what is in it, and Windows does not carry them through a
    junction inside, which /T would have followed out of the folder (the round 3 review, L6). `link`: the link itself, not
    where it leads (/L).
    """
    win = _windows()
    grants = "(OI)(CI)F" if os.path.isdir(path) else "F"
    line = f'icacls "{path}" /inheritance:r /grant:r "{_name(win, _me(win))}:{grants}" "*S-1-5-18:{grants}" "*S-1-5-32-544:{grants}"'
    return line + (" /L" if link else "")


def setowner_line(path: Path, link: bool = False) -> str:
    """The line that makes what is at `path` the account qKVM runs as here, named (Windows): not what is in it (no /T); `link`:
    the link itself (/L)."""
    win = _windows()
    return f'icacls "{path}" /setowner "{_name(win, _me(win))}"' + (" /L" if link else "")


def owner_line(path: Path, link: bool = False) -> str:
    """What to do where what is at `path` is another account's (Windows): give it to the account qKVM runs as, named, or to
    the console's own; neither goes into what is in it (no /T, no /R)."""
    named = setowner_line(path, link)
    console = "" if link else f', or takeown /F "{path}" the console\'s own'
    return (
        f"take it over, in an elevated console: {named} makes it the account qKVM runs as here (where it runs as a service, "
        f"name the service's account instead){console}; or run qKVM as the account that owns it"
    )


# A line given on Windows, as fix_line, owner_line, judged and the start give them: icacls, takeown, del, rmdir.
_COMMAND = re.compile(r'(?:icacls|takeown /F|del|rmdir(?: /S /Q)?) "[^"]*"(?: (?:/[A-Za-z]+(?::[a-z])?|"[^"]*"|\*S-[0-9-]+))*')


def for_consoles(advice: str) -> str:
    """What to do, with the console its lines are for (Windows): "in Command Prompt: ...". Where a path in them holds a
    character PowerShell would expand ($, a backtick), the PowerShell form too: pasted there, "qkvm$zz9" was "qkvm", and the
    line made the folder beside the data folder private (the round 4 review, L2). In it every quoted part is in single
    quotes (taken as it is), and a removal is PowerShell's own (_in_powershell). Advice without such a line is given as it
    is."""
    commands = _COMMAND.findall(advice)
    if not commands:
        return advice
    said = f"in Command Prompt: {advice}"
    if any(sign in command for command in commands for sign in "$`"):
        said += "; in PowerShell: " + "; ".join(_in_powershell(command) for command in commands)
    return said


def _in_powershell(command: str) -> str:
    """The PowerShell form of a line given for Command Prompt: each quoted part in single quotes. A removal never through
    cmd /c, where the quotes were lost and cmd got the path bare: a data folder named "wall$1&old" had the form that removes
    its tls folder remove the folder beside it (the round 5 review). del as Remove-Item -LiteralPath, rmdir /S /Q (a folder,
    no link) with -Recurse; rmdir of a link to a folder as [System.IO.Directory]::Delete, which removes the link alone
    (Windows PowerShell's Remove-Item asks there whether to remove all its children too, and fails where it may not ask)."""

    def quoted(text: str) -> str:
        return "'" + text.replace("'", "''") + "'"

    removal = re.fullmatch(r'(del|rmdir /S /Q|rmdir) "([^"]*)"', command)
    if removal is None:
        return re.sub(r'"([^"]*)"', lambda found: quoted(found.group(1)), command)
    verb, path = removal.groups()
    if verb == "del":
        return f"Remove-Item -LiteralPath {quoted(path)}"
    return f"Remove-Item -LiteralPath {quoted(path)} -Recurse" if verb == "rmdir /S /Q" else f"[System.IO.Directory]::Delete({quoted(path)})"


def not_alone(path: Path, rights: int = WRITE, drive_known: bool = False) -> str | None:
    """Windows: why what is at `path` is not this account's alone (with SYSTEM and the Administrators) to change, or with
    `rights=READ` to read, in a few words; None where it is. (judged, without what to do about it.)"""
    found = judged(path, rights, drive_known=drive_known)
    return None if found is None else found[0]


def judged(path: Path, rights: int = WRITE, link: bool = False, drive_known: bool = False) -> tuple[str, str] | None:
    """Windows: why what is at `path` is not this account's alone to change (or with `rights=READ`, to read), and what to do
    about it; None where it is.

    As _vault_windows.validate_private judges a key: its owner has to be this account, SYSTEM or the Administrators, and no
    entry may grant those rights to anybody else. An entry that only says what is inherited by what is made inside, or that
    denies, grants nothing here; one of another kind than the two plain ones is not taken for nothing. A drive whose file
    system keeps no permissions at all (FAT, exFAT) is said as such: no setting of the folder changes that. Another owner
    is to be taken over (its entries do not change who owns it); an entry of one account of its own is named, with how to
    remove it if it is not meant (Explorer's Continue gives one to the account that presses it, an admin's start keeps the
    admin's, a grant on purpose is one: which of these it is, nobody can tell from the entry). Each with the line that does
    it (fix_line, owner_line); `link`: what is at `path` is a link, and the line sets the link itself (/L). `drive_known`:
    what is at `path` lies in a folder judged already, with no link between (the starter's walk through an update): its
    drive keeps permissions, and is not asked again (asking is most of what judging an entry costs).
    """
    # (The two masks share GENERIC_ALL: what is asked is told by the bits only writing has.)
    said = "can be written to by other users of this computer" if rights & WRITE & ~READ else "can be read by other users of this computer"
    try:
        win = _windows()
        me = _me(win)
        kept, system = (True, "") if drive_known else _kept(win, path)
        if not kept:
            return (
                f"is on a drive whose file system ({system or 'FAT'}) keeps no permissions: anybody who uses this computer may read and change it",
                "keep it on an NTFS drive",
            )
        owner, found = _security(win, path)
    except OSError:
        return "cannot be looked at", ""
    lines = _entries_lines(win, me, path, found, rights, link)
    if owner not in (me, *TRUSTED):
        # (takeown makes the console's own account the owner; a service's folder is to be the service account's: named.) Where
        # it is open to others as well, every line at once, the owner's first (whoever owns it may change its entries): one
        # start said the owner, and the next, once that was done, the entries (the round 4 review, L4).
        if not lines:
            return "belongs to another user", owner_line(path, link)
        return f"belongs to another user, and {said}", f"{owner_line(path, link)}; and then {'; '.join(lines)}"
    return None if not lines else (said, "; ".join(lines))


def _entries_lines(win: Any, me: str, path: Path, found: list[tuple[int, int, int, str]] | None, rights: int, link: bool) -> list[str]:
    """The lines that leave what is at `path` its owner's, SYSTEM's and the Administrators' alone by its entries (judged); none
    where its entries grant nobody else `rights`."""
    if found is None:
        return [fix_line(path, link)]
    # (Denials grant nothing. An entry the folder holds inherit-only grants nothing on the folder, and is passed to what is made
    # in it: it counts. CREATOR OWNER stands for whoever makes a thing in it, and is of those who may.)
    others = [
        (flags, whose)
        for kind, flags, granted, whose in found
        if kind != 1 and granted & rights and (kind != 0 or whose not in (me, *TRUSTED, OWNER_RIGHTS, CREATOR_OWNER))
    ]
    # What to do: entries taken from above go with the folder's own line (fix_line, which sets its own entries); an entry
    # granted on it itself stays through that line, and is removed by one of its own, named. (One of another kind, granted
    # on it itself, names nobody icacls could be told: the words.)
    lines = [fix_line(path, link)] if any(flags & 0x10 for flags, _ in others) else []
    for flags, whose in others:
        if flags & 0x10:
            continue
        if not whose:
            lines.append(GENERAL)
            continue
        removal = f'icacls "{path}" /remove:g *{whose}' + (" /L" if link else "")
        name = _account(win, whose)
        if name is not None:
            lines.append(f"{name} has an entry of its own (it may come from Explorer's Continue, an admin's start, or a grant on purpose): if it is not meant, remove it with {removal}")
        else:
            lines.append(f"remove the entry granted on it to {_name(win, whose)}: {removal}")
    return list(dict.fromkeys(lines))


def _name(win: Any, sid: str) -> str:
    """An account's name as icacls takes it (DOMAIN\\name, or NT AUTHORITY\\LOCAL SERVICE); its SID, as `*S-1-...`, where
    it has no name to be found."""
    found = win.P()
    if not win.sid_of_text(sid, win.c.byref(found)):
        return f"*{sid}"
    try:
        name, domain = win.c.create_unicode_buffer(256), win.c.create_unicode_buffer(256)
        named, domained, use = win.c.c_ulong(256), win.c.c_ulong(256), win.c.c_int()
        if not win.lookup(None, found, name, win.c.byref(named), domain, win.c.byref(domained), win.c.byref(use)):
            return f"*{sid}"
        return f"{domain.value}\\{name.value}" if domain.value else str(name.value)
    finally:
        win.free(found)


def _kept(win: Any, path: Path) -> tuple[bool, str]:
    """Whether the drive `path` is on keeps permissions (an ACL for each file: NTFS, ReFS; not FAT, exFAT), and the name of its
    file system. Where that cannot be asked, it is taken to keep them, and the ACL is read as it comes."""
    root = win.c.create_unicode_buffer(1024)
    if not win.volume_path(str(path), root, 1024):
        return True, ""
    flags, system = win.c.c_ulong(), win.c.create_unicode_buffer(64)
    if not win.volume_info(root.value, None, 0, None, None, win.c.byref(flags), system, 64):
        return True, ""
    return bool(flags.value & 0x8), str(system.value)  # FILE_PERSISTENT_ACLS


def keeps_no_permissions(path: Path) -> str | None:
    """The name of the file system of the drive `path` is on, where it keeps no permissions (FAT, exFAT: no owner, no ACL;
    Windows answers with the world's for every file); None where it keeps them, where that cannot be asked, and off Windows.

    Nothing there is refused for its owner or its ACL (the round 5 review, M3: a new wall's key folder was refused, and an
    existing wall refused at every start, its own files "another account's"): it is said, once at every start (cli)."""
    if sys.platform != "win32":
        return None
    try:
        kept, system = _kept(_windows(), path)
    except OSError:
        return None
    return None if kept else system or "FAT"


def _account(win: Any, sid: str) -> str | None:
    """The name of the account a SID is (DOMAIN\\name), where it is one account: not a group, nor a well-known SID."""
    found = win.P()
    if not win.sid_of_text(sid, win.c.byref(found)):
        return None
    try:
        name, domain = win.c.create_unicode_buffer(256), win.c.create_unicode_buffer(256)
        named, domained, use = win.c.c_ulong(256), win.c.c_ulong(256), win.c.c_int()
        if not win.lookup(None, found, name, win.c.byref(named), domain, win.c.byref(domained), win.c.byref(use)):
            return None
        return f"{domain.value}\\{name.value}" if use.value == 1 else None  # SidTypeUser
    finally:
        win.free(found)


def private_folder(folder: Path) -> None:
    """Windows: make `folder` (and the folders above it) where it is not there, its owner's alone from its first instant: a
    protected ACL of this account, SYSTEM and the Administrators, inherited by everything made in it, given in the same call
    that makes it (CreateDirectoryW with its security). (Python's mkdir is given mode 0o700, and before 3.12.4 ignores it on
    Windows: the folder took whatever its drive gives, Authenticated Users' Modify on a drive other than the system's.)

    A folder that is there already is left exactly as it is found, by every command (the owner's decision, 2026-11-01: on
    Windows as on Linux): changing found folders cost a stopped service its group's access, and left what another account
    had planted while the folder was open with that account. What a found folder lets others do is said at every real
    start, with a fix that works (cli). OSError where the folder cannot be made; FileExistsError where it is no folder.
    """
    win = _windows()
    if not folder.exists():
        if not folder.parent.exists():
            if folder.parent == folder:
                raise FileNotFoundError(2, "no such drive", str(folder))
            private_folder(folder.parent)  # (the folders above it that it makes: its own as well)
        descriptor = win.P()
        if not win.from_text(f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{_me(win)})", 1, win.c.byref(descriptor), None):
            raise win.c.WinError(win.c.get_last_error())
        try:
            attributes = win.Attributes(win.c.sizeof(win.Attributes), descriptor, False)
            if win.make(str(folder), win.c.byref(attributes)):
                return
            error = win.c.get_last_error()
            if error != 183:  # ERROR_ALREADY_EXISTS: made meanwhile by somebody: found, and left as it is
                raise win.c.WinError(error)
        finally:
            win.free(descriptor)
    if not folder.is_dir():
        raise FileExistsError(17, "not a folder", str(folder))


def own_folder(folder: Path) -> None:
    """Make `folder` (and those above it) where it is not there, its owner's alone from its first instant, on every system:
    private_folder on Windows, mode 0700 elsewhere. One that is there is left as it is.

    Not Python's mkdir(mode=0o700) on Windows: since 3.12.4 it gives SYSTEM, the Administrators and OWNER RIGHTS, and a
    folder an elevated run makes is the Administrators' (the owner of what an elevated token makes): the same person's plain
    run is none of them, and was locked out of ~/.qkvm and of an update's folders (the round 4 review, M3). private_folder
    names this account.
    """
    if sys.platform == "win32":
        private_folder(folder)
        return
    missing, at = [], folder  # (the folders above it it makes as well, each 0700: mkdir(parents=True) gives those the umask's mode)
    while not at.exists() and at.parent != at:
        missing.append(at)
        at = at.parent
    for each in reversed(missing):
        try:
            each.mkdir(mode=0o700)
        except FileExistsError:
            pass
    if not folder.is_dir():
        raise FileExistsError(17, "not a folder", str(folder))


def open_private(path: Path | str, flags: int) -> int:
    """os.open, where what it makes is this account's, SYSTEM's and the Administrators' alone from its first moment, whatever
    the folder it is made in lets others do: on Windows a protected ACL given in the call that makes it (CreateFileW with its
    security); on POSIX mode 0600. What is there already is opened as it is (its ACL or mode not changed).

    Every file qKVM writes in its data folder is made so, in a folder it found too (the round 4 review, M1: in a found open
    folder they took the folder's entries, and the log, which holds the setup code, was everybody's to read). The flags as
    os.open takes them: O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_EXCL, O_TRUNC, O_APPEND; on Windows O_TEMPORARY (gone when
    closed) as well. The descriptor is binary and not inherited.
    """
    if sys.platform != "win32":
        return os.open(path, flags, 0o600)
    import msvcrt

    win = _windows()
    access = {os.O_RDONLY: 0x80000000, os.O_WRONLY: 0x40000000, os.O_RDWR: 0xC0000000}[flags & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR)]
    if flags & os.O_CREAT:
        disposition = 1 if flags & os.O_EXCL else 2 if flags & os.O_TRUNC else 4  # CREATE_NEW, CREATE_ALWAYS, OPEN_ALWAYS
    else:
        disposition = 5 if flags & os.O_TRUNC else 3  # TRUNCATE_EXISTING, OPEN_EXISTING
    # FILE_ATTRIBUTE_NORMAL, and FILE_FLAG_DELETE_ON_CLOSE for O_TEMPORARY. (The security given counts only where the file is
    # made: CREATE_ALWAYS and OPEN_ALWAYS keep what an existing file has.)
    attributes = 0x80 | (0x04000000 if flags & getattr(os, "O_TEMPORARY", 0) else 0)
    descriptor = win.P()
    if not win.from_text(f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{_me(win)})", 1, win.c.byref(descriptor), None):
        raise win.c.WinError(win.c.get_last_error())
    try:
        security = win.Attributes(win.c.sizeof(win.Attributes), descriptor, False)
        # Shared for reading, writing and deleting, as Python's own open shares a file (and deleting: a log is renamed
        # while it is read).
        handle = win.create(str(path), access, 7, win.c.byref(security), disposition, attributes, None)
        if handle is None or handle == win.P(-1).value:
            error = win.c.get_last_error()
            raise OSError(0, win.c.FormatError(error).strip(), str(path), error)
    finally:
        win.free(descriptor)
    try:
        return int(msvcrt.open_osfhandle(handle, (flags & os.O_APPEND) | os.O_NOINHERIT))
    except BaseException:
        win.close(handle)
        raise


_MODES = {
    "r": os.O_RDONLY,
    "w": os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
    "a": os.O_WRONLY | os.O_CREAT | os.O_APPEND,
    "x": os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    "r+": os.O_RDWR,
    "w+": os.O_RDWR | os.O_CREAT | os.O_TRUNC,
    "a+": os.O_RDWR | os.O_CREAT | os.O_APPEND,
    "x+": os.O_RDWR | os.O_CREAT | os.O_EXCL,
}


def private(path: Path | str, mode: str = "w", **how: Any) -> Any:
    """open(path, mode, ...) where what is made is its owner's alone from its first moment (open_private): "w", "a", "x" and
    their "+" and "b" forms; `how`: encoding, errors, newline, buffering, as open takes them."""
    flags = _MODES[mode.replace("b", "").replace("t", "")] | getattr(os, "O_BINARY", 0)
    return os.fdopen(open_private(path, flags), mode.replace("x", "w"), **how)


def not_ours(path: Path) -> str | None:
    """Why what is at `path` is not to be taken for qKVM's own, on any system: "is a link", or "belongs to another account"
    (another than this one and root; on Windows than this one, SYSTEM and the Administrators); None where it is ours.

    Whoever owns a file may read and change its permissions, whatever the folder above says: what another account put in a
    folder while it was open stays that account's (the round 3 review, M1).
    """
    if _a_link(path):
        return "is a link"
    if sys.platform == "win32":
        if keeps_no_permissions(path) is not None:
            return None  # (no owner is kept there: the world's is told for every file. Said at every start instead.)
        try:
            win = _windows()
            owner, me = _security(win, path)[0], _me(win)
        except OSError:
            return "cannot be looked at"
        return None if owner in (me, *TRUSTED) else "belongs to another account"
    try:
        found = os.lstat(path)
    except OSError:
        return "cannot be looked at"
    return None if found.st_uid in (os.getuid(), 0) else "belongs to another account"


LINKS = 40  # links followed on the way to a folder; a way through more (or a loop) cannot be looked at
_VOLUME = re.compile(r"(\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\)(.*)", re.DOTALL)  # \\?\Volume{...}\ and what follows


def places(folder: Path) -> list[Path]:
    """`folder` as given; every link on its way, each by its own path (a junction or a symlink, on any folder of the path,
    and where a link leads to another, that one too); and the folder where what is in it lies, last.

    The security of a link is its own (GetNamedSecurityInfoW reads the link, not where it leads), and all of them count:
    the folder for what is in it, each link for who may point it elsewhere (a link in the middle of a chain, re-pointed by
    anybody who may change it, had the wall start on another folder as a new wall). (_walk says whether all were seen.)
    """
    return _walk(folder)[0]


def way(folder: Path) -> tuple[list[Path], bool]:
    """places, and whether the whole way was followed (_walk): what the starter judges before it runs an update."""
    return _walk(folder)


def _walk(folder: Path) -> tuple[list[Path], bool]:
    """places, and whether the whole way was followed: not where it goes through more than LINKS links (or a loop), nor
    where a link on it cannot be read. A target written by the volume's own name (\\\\?\\Volume{...}\\) is followed with
    that name as its anchor, on every Python (before 3.12 pathlib does not take it for one)."""
    given = Path(os.path.abspath(folder))
    found = [given]
    current, pending = _anchor_and_parts(str(given))
    hops = 0
    while pending:
        current = os.path.join(current, pending.pop(0))
        if not _a_link(Path(current)):
            continue
        hops += 1
        if Path(current) not in found:
            found.append(Path(current))
        target = _target(current)
        if target is None or hops > LINKS:
            return found, False
        current, rest = _anchor_and_parts(target)
        pending = rest + pending
    try:
        real = folder.resolve()
    except (OSError, RuntimeError):  # (a link that leads to itself, as Python before 3.13 says it)
        return found, False
    if not any(os.path.normcase(str(real)) == os.path.normcase(str(place)) for place in found):
        found.append(real)
    return found, True


def _anchor_and_parts(text: str) -> tuple[str, list[str]]:
    """A whole path's anchor (a drive, a share, a volume's own name) and the names after it."""
    volume = _VOLUME.fullmatch(text)
    if volume:
        return volume.group(1), [part for part in volume.group(2).split("\\") if part]
    path = Path(text)
    return path.anchor, list(path.parts[1:])


def _a_link(path: Path) -> bool:
    """Whether what is at `path` is a link to a folder or a file: a symlink, or a junction (a mount point of a folder)."""
    try:
        found = os.lstat(path)
    except OSError:
        return False
    attributes, tag = getattr(found, "st_file_attributes", 0), getattr(found, "st_reparse_tag", 0)
    return bool(attributes & 0x400 and tag in (0xA000000C, 0xA0000003)) or os.path.islink(path)  # (IO_REPARSE_TAG_SYMLINK, _MOUNT_POINT)


def _target(link: str) -> str | None:
    """Where a link leads, as a whole path (one written relative to the link's folder made whole; one written by the
    volume's own name kept so); None where it cannot be read."""
    try:
        text = os.readlink(link)
    except (OSError, ValueError):
        return None
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\") and not _VOLUME.fullmatch(text):
        text = text[4:]
    if _VOLUME.fullmatch(text):
        return text
    if not _anchor_and_parts(text)[0]:  # (written relative to the folder the link is in)
        text = os.path.join(os.path.dirname(link), text)
    return os.path.normpath(text)


def folder_not_alone(folder: Path) -> str | None:
    """not_alone, of a folder and of where it leads where it is a link: why either is not this account's alone to change."""
    found = folder_judged(folder)
    return None if found is None else found[0]


def folder_judged(folder: Path) -> tuple[str, str] | None:
    """judged, of a folder and of where it leads where it is a link: why either is not this account's alone to change, and
    what to do about it."""
    # (Said after the folder's name as given: "<folder> leads to <where its files lie>, which ...", "<folder> leads through the
    # link <link>, which ...", or of the folder given itself where that is a link: "<folder> (a link to <...>) ...".)
    found, whole = _walk(folder)
    if not whole:
        return (
            f"cannot be looked at: the way to it goes through more than {LINKS} links, or a link on it cannot be read",
            "name the folder itself, not a link to it",
        )
    # (What is said is of the first of them that is open, where what is in it lies first, then each link on the way; what to do
    # is each one's own line: the folder's, and each link's by itself, /L.)
    first, lines = None, []
    for place in reversed(found):
        said = judged(place, link=place != found[-1] and _a_link(place))
        if said is None:
            continue
        lines.append(said[1])
        if first is None:
            if place == found[0]:
                first = f"(a link to {found[-1]}) {said[0]}" if len(found) > 1 and _a_link(place) else said[0]
            else:
                first = f"{'leads to' if place == found[-1] else 'leads through the link'} {place}, which {said[0]}"
    return None if first is None else (first, "; and ".join(line for line in lines if line))
