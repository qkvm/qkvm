"""Windows native-video process: capability-free AppContainer and a constrained job.

Only public Python/PyAV runtime files are copied into a read/execute-only bundle.
Each worker gets a distinct AppContainer identity, no network capabilities, three
explicit pipe handles, no child processes, restricted UI access, two of the
machine's processors at most for all its threads together (see processors_for),
and a desktop of its own that only it may use (see worker_desktop).
"""
from __future__ import annotations

from collections.abc import Iterator
import contextlib
import ctypes
from ctypes import wintypes as wt
import io
import msvcrt
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from typing import Any

if sys.platform != "win32":
    raise ImportError("Windows video launcher is Windows-only")

P = ctypes.c_void_p
SIZE = ctypes.c_size_t
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
user = ctypes.WinDLL("user32", use_last_error=True)


def api(dll: Any, name: str, args: list[Any], result: Any = wt.BOOL) -> Any:
    function = getattr(dll, name)
    function.argtypes, function.restype = args, result
    return function


close_handle = api(kernel, "CloseHandle", [P])
local_free = api(kernel, "LocalFree", [P], P)
free_sid = api(advapi, "FreeSid", [P], P)
create_profile = api(userenv, "CreateAppContainerProfile", [wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, P, wt.DWORD, ctypes.POINTER(P)], ctypes.c_long)
delete_profile = api(userenv, "DeleteAppContainerProfile", [wt.LPCWSTR], ctypes.c_long)
# A function of its own, not kernel's attribute: whatever sets the argument types of kernel.GetProcessTimes for its own use
# does not change this one's. It keeps Python's lock (PYFUNCTYPE; one calling convention on 64-bit Windows): it returns in
# microseconds, and letting the lock go meant waiting to have it back behind whatever else ran in Python meanwhile.
get_process_times = ctypes.PYFUNCTYPE(wt.BOOL, P, *[ctypes.POINTER(wt.FILETIME)] * 4)(("GetProcessTimes", kernel))


def checked(value: Any) -> Any:
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


class Attributes(ctypes.Structure):
    _fields_ = [("length", wt.DWORD), ("descriptor", P), ("inherit", wt.BOOL)]


class Startup(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("reserved", wt.LPWSTR), ("desktop", wt.LPWSTR), ("title", wt.LPWSTR),
                ("x", wt.DWORD), ("y", wt.DWORD), ("width", wt.DWORD), ("height", wt.DWORD),
                ("chars_x", wt.DWORD), ("chars_y", wt.DWORD), ("fill", wt.DWORD), ("flags", wt.DWORD),
                ("show", wt.WORD), ("reserved_size", wt.WORD), ("reserved_bytes", P),
                ("stdin", P), ("stdout", P), ("stderr", P)]


class StartupEx(ctypes.Structure):
    _fields_ = [("startup", Startup), ("attributes", P)]


class ProcessInfo(ctypes.Structure):
    _fields_ = [("process", P), ("thread", P), ("pid", wt.DWORD), ("tid", wt.DWORD)]


class Capabilities(ctypes.Structure):
    _fields_ = [("sid", P), ("capabilities", P), ("count", wt.DWORD), ("reserved", wt.DWORD)]


class BasicLimits(ctypes.Structure):
    _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64), ("flags", wt.DWORD),
                ("minimum_working_set", SIZE), ("maximum_working_set", SIZE), ("active_processes", wt.DWORD),
                ("affinity", SIZE), ("priority", wt.DWORD), ("scheduling", wt.DWORD)]


class ExtendedLimits(ctypes.Structure):
    _fields_ = [("basic", BasicLimits), ("io", ctypes.c_uint64 * 6), ("process_memory", SIZE),
                ("job_memory", SIZE), ("peak_process_memory", SIZE), ("peak_job_memory", SIZE)]


class CpuRate(ctypes.Structure):
    _fields_ = [("flags", wt.DWORD), ("rate", wt.DWORD)]


def processors_for(available: list[int], index: int) -> int:
    """The processors the index-th worker may run on, as an affinity mask: two of qKVM's
    own, half of them apart, or one where it has fewer than four; each worker the next.

    The Linux worker runs one thread (its syscall filter allows no clone), so it never runs
    on more than one processor at a time. Windows cannot forbid a second thread; the job
    holds all the worker's threads to these processors instead, and a process in such a job
    cannot change its own. The worker's own work is one thread (every codec and scaler is
    opened with one); a second processor lets it go round one that is busy. Half of them
    apart, the two are not one core's two hyperthreads.

    Not a CPU rate cap: Windows gives the threads of a rate-capped job less time than other
    threads on busy processors, on slow cores most. On two slow cores shared with four busy
    threads, 4K H.264 at 30 frames a second was decoded at 13.6 to 60.4 frames a second
    with the job capped at two processors' worth, at 58.5 to 67.0 held to those two
    processors, and at 61.2 to 70.8 with neither. The cost of two fixed processors: when
    both are busy and others are free, the worker cannot move (decoding with a full-size
    JPEG of each 4K frame went from 18 to 25 frames a second down to 12 to 16).
    """
    count = len(available)
    if not count:
        raise OSError("no processor to run the video worker on")
    take = max(1, min(2, count // 2))
    return sum({1 << available[(index + step * (count // take)) % count] for step in range(take)})


def cpu_rate(processors: int) -> int:
    """With more than 64 processors, which Windows splits into groups, a job's affinity
    covers one group: there the job caps the CPU time of all the worker's threads together
    instead, at two processors' worth (half the machine where that is less), in hundredths
    of a percent of all the processors. Such machines are servers with processors of one
    kind; the cap cost most on slow cores beside fast ones."""
    return max(-(-10000 // processors), min(-(-20000 // processors), 5000))


def processor_groups() -> int:
    return int(checked(api(kernel, "GetActiveProcessorGroupCount", [], wt.WORD)()))


def own_processors() -> list[int]:
    """The processors qKVM itself may run on (of its one group)."""
    mine, system = SIZE(), SIZE()
    current = api(kernel, "GetCurrentProcess", [], P)()
    checked(api(kernel, "GetProcessAffinityMask", [P, ctypes.POINTER(SIZE), ctypes.POINTER(SIZE)])(current, ctypes.byref(mine), ctypes.byref(system)))
    return [bit for bit in range(ctypes.sizeof(SIZE) * 8) if mine.value >> bit & 1]


SUSPECT_FOR = 60.0  # seconds every placement passes over a pair whose worker missed its deadline

_pairs_lock = threading.Lock()
_pair_load: dict[int, int] = {}  # processor-pair index -> how many live workers hold it
_suspect: dict[int, float] = {}  # processor-pair index -> monotonic time until which it is passed over
# Where this process begins among equally free pairs, drawn at random as it starts. Each qKVM on a computer knows only its
# own workers: ranked from pair 0 in each, the first worker of every one of them went on processors 0 and 1 (where Windows
# takes most interrupts, too). Begun at random, two qKVMs' first workers share a pair one time in as many as there are
# pairs. Not pair loads kept for the whole computer: that would need a store every qKVM there could write, which a
# process of another account could fill with whatever keeps workers together.
_first_pair = int.from_bytes(os.urandom(4), "little")


def _pair_count(own: list[int]) -> int:
    return len(own) // max(1, min(2, len(own) // 2))


def next_processors(avoid: int | None = None) -> tuple[int, int]:
    """The pair with the fewest live workers, and its affinity mask. A worker is placed on the
    least-crowded pair and gives it back when it ends (release_processors), so a pair that falls
    empty is reused before any pair is shared. A worker taken over can hold its own two processors
    (it can raise its threads to priority 15, which no job setting undoes), but while a free pair
    exists it is never placed on another worker's, so it cannot stall a legitimate decoder.

    A worker that missed its deadline may have been stalled by one taken over beside it, so while
    any worker still runs on its pair, that pair is passed over for SUSPECT_FOR seconds
    (mark_stalled), unless every pair is. `avoid` is the pair of a worker that has just died: its
    replacement does not go back there while another pair is as free. Without these, the death
    itself made that pair the least crowded, and a worker stalled by its neighbour was started again
    beside it. An empty pair always comes first, marked or avoided or not: there is nobody there to
    stall or be stalled, and passing it over would put a worker beside another while a pair stands
    free. (A worker being stopped counts on its pair until it ends, and one taken over can delay
    that: where no pair is empty meanwhile, its feed's next worker goes beside another feed's.
    SECURITY.md says so.) Among pairs as free, this process's own order: from _first_pair on.
    Within one process none of this changes; between qKVMs on one computer it is only likelier."""
    own = own_processors()
    if not own:
        raise OSError("no processor to run the video worker on")
    now = time.monotonic()
    with _pairs_lock:
        count = _pair_count(own)

        def rank(i: int) -> tuple[bool, int, bool, int]:
            load = _pair_load.get(i, 0)
            return (load > 0 and _suspect.get(i, 0.0) > now, load, i == avoid, (i - _first_pair) % count)

        index = min(range(count), key=rank)
        _pair_load[index] = _pair_load.get(index, 0) + 1
    return index, processors_for(own, index)


def mark_stalled(index: int) -> None:
    """The worker on this pair missed its deadline: pass the pair over for SUSPECT_FOR seconds."""
    with _pairs_lock:
        _suspect[index] = time.monotonic() + SUSPECT_FOR


def release_processors(index: int) -> None:
    with _pairs_lock:
        remaining = _pair_load.get(index, 0) - 1
        if remaining > 0:
            _pair_load[index] = remaining
        else:
            _pair_load.pop(index, None)


# Held while a worker's pipe ends can be inherited, which is for its own CreateProcessW
# alone (that call lists the three the worker gets). Code in qKVM that started a process
# inheriting handles without such a list would have to hold it too; there is none: the
# other processes are started by subprocess, which on Windows lists the handles a child
# gets or gives it none.
inheriting = threading.Lock()


def sid_text(sid: Any) -> str:
    """A SID as its string (S-1-5-21-...)."""
    text = wt.LPWSTR()
    checked(api(advapi, "ConvertSidToStringSidW", [P, ctypes.POINTER(wt.LPWSTR)])(sid, ctypes.byref(text)))
    try:
        return str(text.value)
    finally:
        local_free(text)


def user_sid_text() -> str:
    """The user qKVM runs as, as a SID string."""
    token = P()
    current = api(kernel, "GetCurrentProcess", [], P)()
    checked(api(advapi, "OpenProcessToken", [P, wt.DWORD, ctypes.POINTER(P)])(current, 8, ctypes.byref(token)))
    try:
        size = wt.DWORD()
        info = api(advapi, "GetTokenInformation", [P, ctypes.c_int, P, wt.DWORD, ctypes.POINTER(wt.DWORD)])
        info(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        checked(info(token, 1, data, size, ctypes.byref(size)))
        return sid_text(ctypes.cast(data, ctypes.POINTER(P))[0])
    finally:
        close_handle(token)


def runtime_acl(path: Path) -> None:
    """Only the owner/admin/system may modify this public-code bundle."""
    # All AppContainers can read public runtime code, but cannot modify it.
    # No application data, user profile, environment or credentials are copied.
    sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user_sid_text()})(A;OICI;GRGX;;;S-1-15-2-1)"
    descriptor = P()
    checked(api(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(P), P])(sddl, 1, ctypes.byref(descriptor), None))
    try:
        present, defaulted, dacl = wt.BOOL(), wt.BOOL(), P()
        checked(api(advapi, "GetSecurityDescriptorDacl", [P, ctypes.POINTER(wt.BOOL), ctypes.POINTER(P), ctypes.POINTER(wt.BOOL)])(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
        error = api(advapi, "SetNamedSecurityInfoW", [wt.LPWSTR, ctypes.c_int, wt.DWORD, P, P, P, P], wt.DWORD)(str(path), 1, 0x80000004, None, None, dacl, None)
        if error:
            raise ctypes.WinError(error)
    finally:
        local_free(descriptor)


# A worker's user32.dll connects to a window station and a desktop as it loads, and Python's _ctypes (through ole32 and
# oleaut32) and PyAV's avutil load it: where the worker may not connect, they fail with "A dynamic link library (DLL)
# initialization routine failed", and no picture is made. An AppContainer may connect only where the station's and the
# desktop's DACLs let in its SID or ALL APPLICATION PACKAGES. Windows lets every AppContainer onto the interactive WinSta0
# and its desktop Default, and onto no other: not a service's station, nor an SSH session's.
# What user32 needs, found by trying from a service's station on Windows 11 (less of either and it fails to initialize):
STATION_RIGHTS = 0x00020020  # READ_CONTROL | WINSTA_ACCESSGLOBALATOMS (WinSta0 gives every AppContainer 0x20327)
DESKTOP_RIGHTS = 0x00000081  # DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS (Default gives every AppContainer 0xF00FF)
DESKTOP_HEAP = 512  # KiB; the worker makes no window (a desktop on WinSta0 is given 20 MiB of the session's space otherwise)
ALL_APPLICATION_PACKAGES = "S-1-15-2-1"
SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE = 7, 4, 0x08
SE_DACL_PROTECTED, PROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION = 0x1000, 0x80000000, 0x20000000


class AclSize(ctypes.Structure):
    _fields_ = [("count", wt.DWORD), ("used", wt.DWORD), ("free", wt.DWORD)]


get_security_info = api(advapi, "GetSecurityInfo", [P, ctypes.c_int, wt.DWORD, P, P, ctypes.POINTER(P), P, ctypes.POINTER(P)], wt.DWORD)
set_security_info = api(advapi, "SetSecurityInfo", [P, ctypes.c_int, wt.DWORD, P, P, P, P], wt.DWORD)
acl_size = api(advapi, "GetAclInformation", [P, ctypes.POINTER(AclSize), wt.DWORD, ctypes.c_int])
get_ace = api(advapi, "GetAce", [P, wt.DWORD, ctypes.POINTER(P)])
delete_ace = api(advapi, "DeleteAce", [P, wt.DWORD])
add_allowed_ace = api(advapi, "AddAccessAllowedAce", [P, wt.DWORD, wt.DWORD, P])
equal_sid = api(advapi, "EqualSid", [P, P])
sid_length = api(advapi, "GetLengthSid", [P], wt.DWORD)
copy_sid = api(advapi, "CopySid", [wt.DWORD, P, P])
descriptor_control = api(advapi, "GetSecurityDescriptorControl", [P, ctypes.POINTER(wt.WORD), ctypes.POINTER(wt.DWORD)])
string_to_sid = api(advapi, "ConvertStringSidToSidW", [wt.LPCWSTR, ctypes.POINTER(P)])
string_to_descriptor = api(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(P), P])
create_desktop = api(user, "CreateDesktopExW", [wt.LPCWSTR, P, P, wt.DWORD, wt.DWORD, ctypes.POINTER(Attributes), wt.ULONG, P], P)
close_desktop = api(user, "CloseDesktop", [P])
create_mutex = api(kernel, "CreateMutexExW", [ctypes.POINTER(Attributes), wt.LPCWSTR, wt.DWORD, wt.DWORD], P)
release_mutex = api(kernel, "ReleaseMutex", [P])
wait_for = api(kernel, "WaitForSingleObject", [P, wt.DWORD], wt.DWORD)
object_name = api(user, "GetUserObjectInformationW", [P, ctypes.c_int, P, wt.DWORD, ctypes.POINTER(wt.DWORD)])

# Windows writes a DACL only whole: read, changed, written back. This qKVM's threads change a station's one at a time
# (_station_lock), and every qKVM of this account in this session with them (_editing).
_station_lock = threading.Lock()
_dacl_mutexes: dict[str, Any] = {}  # a window object's name -> the mutex its DACL's changes are made under (kept open)
_dacl_mutexes_lock = threading.Lock()  # (held only to look one up or make it, never while one is waited for)
SHARED_WAIT = 2000  # ms that a change waits for another qKVM's change of the same DACL (each takes a few milliseconds)
WAIT_OBJECT_0, WAIT_ABANDONED = 0x0, 0x80


def _name_of(window_object: Any) -> str:
    buffer, size = ctypes.create_unicode_buffer(256), wt.DWORD()
    checked(object_name(window_object, 2, buffer, ctypes.sizeof(buffer), ctypes.byref(size)))  # UOI_NAME
    return buffer.value


def own_station() -> tuple[Any, str]:
    """The window station qKVM runs on (a handle that is not to be closed), and its name."""
    station = checked(api(user, "GetProcessWindowStation", [], P)())
    return station, _name_of(station)


def _shared(name: str) -> Any:
    """The mutex every qKVM of this account in this session takes to change the DACL of the window object `name`
    (Local\\qkvm-dacl-<name>), which only this account and SYSTEM may use; None where it cannot be had (another account
    made one of that name first)."""
    with _dacl_mutexes_lock:
        mutex = _dacl_mutexes.get(name)
        if mutex is None:
            descriptor = P()
            checked(string_to_descriptor(f"D:P(A;;GA;;;SY)(A;;GA;;;{user_sid_text()})", 1, ctypes.byref(descriptor), None))
            try:
                attributes = Attributes(ctypes.sizeof(Attributes), descriptor.value, False)  # (never inherited)
                mutex = create_mutex(ctypes.byref(attributes), "Local\\qkvm-dacl-" + name, 0, 0x00100001)  # SYNCHRONIZE | MUTEX_MODIFY_STATE
            finally:
                local_free(descriptor)
            if not mutex:
                return None
            _dacl_mutexes[name] = mutex
        return mutex


@contextlib.contextmanager
def _editing(window_object: Any) -> Iterator[None]:
    """Held around a read, change and write of a window object's DACL. Two qKVMs of one account share a station where they
    run as services, as a test runner's processes over one SSH session do; each changing the DACL on its own, one wrote
    over the other's entry before its worker could use it, or brought back an entry the other had taken out, left for the
    life of the station. A qKVM that cannot have the mutex (another account made one of that name first), or waits
    SHARED_WAIT for it in vain (one held by a process that hangs, or by another account's on purpose), changes the DACL
    under its own lock alone: slower, or not safe from the other's changes then, and never refused. The mutex is waited
    for with no lock of this process held (a mutex is a thread's: this process's threads wait their turns at it too), so
    one that is held keeps only the starts and ends that change this DACL waiting, and each for SHARED_WAIT at most."""
    mutex = _shared(_name_of(window_object))
    # (WAIT_ABANDONED: the holder ended while it held it. The DACL it was changing was written whole, or not at all.)
    owned = mutex is not None and wait_for(mutex, SHARED_WAIT) in (WAIT_OBJECT_0, WAIT_ABANDONED)
    try:
        with _station_lock:
            yield
    finally:
        if owned:
            release_mutex(mutex)


def _dacl(station: Any) -> tuple[bytes | None, int]:
    """A copy of the station's DACL (None: it has none, which lets everybody in), and how to write one back as it was:
    protected or not (SetSecurityInfo takes the protection away unless it is told to keep it). The other DACL flag, AI,
    Windows does not keep on a window station."""
    dacl, descriptor = P(), P()
    for _ in range(3):  # (ERROR_INSUFFICIENT_BUFFER: the DACL grew while it was read, by a change made without the mutex)
        error = get_security_info(station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if error != 122:
            break
    if error:
        raise ctypes.WinError(error)
    try:
        control, revision = wt.WORD(), wt.DWORD()
        checked(descriptor_control(descriptor, ctypes.byref(control), ctypes.byref(revision)))
        protection = PROTECTED_DACL_SECURITY_INFORMATION if control.value & SE_DACL_PROTECTED else UNPROTECTED_DACL_SECURITY_INFORMATION
        if not dacl.value:
            return None, protection
        size = AclSize()
        checked(acl_size(dacl, ctypes.byref(size), ctypes.sizeof(size), 2))  # AclSizeInformation
        return ctypes.string_at(dacl.value, size.used), protection
    finally:
        local_free(descriptor)


def _entries(acl: Any, count: int) -> list[tuple[int, int, int, int, int]]:
    """Each entry of an ACL as (index, type, flags, mask, address of its SID)."""
    found = []
    for index in range(count):
        ace = P()
        checked(get_ace(acl, index, ctypes.byref(ace)))
        address = int(ace.value or 0)
        kind, flags = ctypes.string_at(address, 2)
        mask = int.from_bytes(ctypes.string_at(address + 4, 4), "little")
        found.append((index, kind, flags, mask, address + 8))  # ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE: header, mask, SID
    return found


def station_admits_app_containers(station: Any) -> bool:
    """Whether the station lets every AppContainer connect, as Windows has it on the interactive WinSta0."""
    return _admits(_dacl(station)[0])


def _admits(acl: bytes | None) -> bool:
    """The DACL read as Windows reads it, in order, each right decided by the first entry naming ALL APPLICATION PACKAGES
    that names it, entries only to be inherited left out. An entry with a generic right in it is not reckoned with, and no
    NULL DACL is ever changed (it lets everybody in): where in doubt, the worker is given an entry of its own, no harm."""
    if acl is None:
        return True
    everyone = P()
    checked(string_to_sid(ALL_APPLICATION_PACKAGES, ctypes.byref(everyone)))
    try:
        buffer = ctypes.create_string_buffer(acl, len(acl))
        decided = allowed = 0
        for _, kind, flags, mask, sid in _entries(buffer, int.from_bytes(acl[4:6], "little")):
            if flags & INHERIT_ONLY_ACE or kind not in (0, 1) or not equal_sid(sid, everyone):
                continue
            if mask & 0xF0000000:
                return False
            if kind == 0:  # ACCESS_ALLOWED_ACE_TYPE
                allowed |= mask & ~decided
            decided |= mask
        return allowed & STATION_RIGHTS == STATION_RIGHTS
    finally:
        local_free(everyone)


def grant_station(station: Any, sid: Any) -> bool:
    """Let one AppContainer, a worker's own SID, connect to qKVM's window station where the station does not let every
    AppContainer in (a service's, an SSH session's): an entry of its own with STATION_RIGHTS, at the end of the DACL, after
    every entry that denies. False where none was needed. The DACL is otherwise left as it was, entry for entry. Taken
    out when the worker is waited for (AppProcess.wait): a qKVM that ends without that (TerminateProcess, a crash) leaves
    its workers' entries until the station ends, on a service's until the computer restarts; about 1,300 fill the DACL,
    and then this refuses ("no room") until then (SECURITY.md). Judged
    first without the mutex (on WinSta0 every start): a station that needs no entry waits for nothing."""
    if station_admits_app_containers(station):
        return False
    with _editing(station):
        acl, protection = _dacl(station)
        if acl is None or _admits(acl):
            return False
        total = len(acl) + 8 + sid_length(sid)  # ACCESS_ALLOWED_ACE: header, mask, then the SID
        if total > 0xFFFF:
            raise OSError("the window station's DACL has no room for the video worker's entry")
        buffer = ctypes.create_string_buffer(acl[:2] + total.to_bytes(2, "little") + acl[4:], total)  # AclSize: room for it
        checked(add_allowed_ace(buffer, acl[0], STATION_RIGHTS, sid))  # (at the end, in the ACL's own revision)
        error = set_security_info(station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION | protection, None, None, buffer, None)
        if error:
            raise ctypes.WinError(error)
        return True


def revoke_station(station: Any, sid: Any) -> None:
    """Take a worker's own entry (grant_station) out of the station's DACL again, leaving every other as it is."""
    with _editing(station):
        acl, protection = _dacl(station)
        if acl is None:
            return
        buffer = ctypes.create_string_buffer(acl[:2] + len(acl).to_bytes(2, "little") + acl[4:], len(acl))  # AclSize: what is in use
        theirs = [index for index, kind, _, _, entry in _entries(buffer, int.from_bytes(acl[4:6], "little")) if kind == 0 and equal_sid(entry, sid)]
        if not theirs:
            return
        for index in reversed(theirs):
            checked(delete_ace(buffer, index))
        error = set_security_info(station, SE_WINDOW_OBJECT, DACL_SECURITY_INFORMATION | protection, None, None, buffer, None)
        if error:
            raise ctypes.WinError(error)


def worker_desktop(name: str, sid: Any) -> Any:
    """A desktop of its own for one worker, on qKVM's window station. Its DACL lets in SYSTEM, qKVM's user, and of all
    AppContainers that worker's alone, with what its user32.dll needs to connect (DESKTOP_RIGHTS). No other process is on
    it; the worker makes no window there, and its job can neither make nor switch desktops nor use another's windows.
    Not a boundary in a signed-in session: a worker taken over can open WinSta0's Default, which Windows lets every
    AppContainer use, move a thread to it (SetThreadDesktop, which the job does not stop) and read the screen there, as it
    could on Default before 0.4.0 (SECURITY.md). On a service's or SSH session's station there is no other it may use.
    Before, a worker shared the desktop it was started from: the user's own (WinSta0\\Default) where qKVM runs in a
    signed-in session, and one it could not connect to where qKVM runs as a service. The handle is qKVM's alone (not
    inherited); the desktop goes when it and the worker's are closed."""
    sddl = f"D:P(A;;GA;;;SY)(A;;GA;;;{user_sid_text()})(A;;{DESKTOP_RIGHTS:#x};;;{sid_text(sid)})"
    descriptor = P()
    checked(string_to_descriptor(sddl, 1, ctypes.byref(descriptor), None))
    try:
        attributes = Attributes(ctypes.sizeof(Attributes), descriptor.value, False)
        # READ_CONTROL | DESKTOP_CREATEWINDOW for qKVM's own handle: without the second, Windows cannot make the desktop's
        # own window and refuses with ERROR_NOT_ENOUGH_MEMORY.
        return checked(create_desktop(name, None, None, 0, 0x00020002, ctypes.byref(attributes), DESKTOP_HEAP, None))
    finally:
        local_free(descriptor)


_bundle: Path | None = None
_bundle_lock = threading.Lock()


def bundle(package: Path, script: Path) -> Path:
    global _bundle
    with _bundle_lock:
        if _bundle is not None:
            return _bundle
        root = Path(tempfile.mkdtemp(prefix="qkvm-video-runtime-"))
        runtime_acl(root)
        base = Path(sys.base_prefix)
        version = f"python{sys.version_info.major}{sys.version_info.minor}"
        shutil.copyfile(base / "python.exe", root / "python.exe")
        for pattern in ("python*.dll", "vcruntime*.dll"):
            for source in base.glob(pattern):
                shutil.copyfile(source, root / source.name)
        shutil.copytree(base / "DLLs", root / "DLLs", ignore=shutil.ignore_patterns("__pycache__"))
        with zipfile.ZipFile(root / (version + ".zip"), "w", compression=zipfile.ZIP_STORED) as archive:
            for source in (base / "Lib").rglob("*.py"):
                relative = source.relative_to(base / "Lib")
                if not {"site-packages", "test", "tests", "idlelib", "tkinter", "ensurepip"}.intersection(relative.parts):
                    archive.write(source, relative.as_posix())
        site = root / "site-packages"
        site.mkdir()
        for name in ("av", "av.libs"):
            shutil.copytree(package / name, site / name, ignore=shutil.ignore_patterns("__pycache__"))
        (root / (version + "._pth")).write_text(f"{version}.zip\n.\nDLLs\nsite-packages\n", encoding="utf-8")
        shutil.copyfile(script, root / "worker.py")
        _bundle = root
        return root


class AppProcess:
    def __init__(self, package: Path, script: Path, avoid: int | None = None) -> None:
        self._state_lock = threading.RLock()
        self._handle: Any = None
        self._job: Any = None
        self._profile: str | None = None
        self._pair: int | None = None  # the processor pair this worker holds, given back when it ends
        self._desktop: Any = None  # the desktop made for it (worker_desktop), closed when it ends
        self._station: Any = None  # qKVM's window station, where it was given an entry for this worker (grant_station)
        self._sid: Any = None  # a copy of the worker's SID, whose entry is taken out of the station's DACL when it ends
        self.returncode: int | None = None
        self.stdin: Any = None
        self.stdout: Any = None
        root = bundle(package, script)
        sid = P()
        ident = uuid.uuid4().hex
        profile = "qkvm.video." + ident
        result = create_profile(profile, "qKVM isolated video", "Credential-free video worker", None, 0, ctypes.byref(sid))
        if result != 0:
            raise OSError(f"Cannot create video AppContainer ({result & 0xFFFFFFFF:#x})")
        self._profile = profile
        handles: list[Any] = []
        attribute_list: Any = None
        info = ProcessInfo()
        try:
            # Every end is made non-inheritable: a process started meanwhile cannot take one.
            read_in, write_in, read_out, write_out = P(), P(), P(), P()
            pipe = api(kernel, "CreatePipe", [ctypes.POINTER(P), ctypes.POINTER(P), ctypes.POINTER(Attributes), wt.DWORD])
            checked(pipe(ctypes.byref(read_in), ctypes.byref(write_in), None, 0))
            handles.extend([read_in, write_in])
            checked(pipe(ctypes.byref(read_out), ctypes.byref(write_out), None, 0))
            handles.extend([read_out, write_out])
            set_flags = api(kernel, "SetHandleInformation", [P, wt.DWORD, wt.DWORD])
            # stderr shares a separate write-only NUL handle, never a parent log/file.
            null = api(kernel, "CreateFileW", [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.POINTER(Attributes), wt.DWORD, wt.DWORD, P], P)("NUL", 0x40000000, 3, None, 3, 0, None)
            if null == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(null)
            size = SIZE()
            initialize = api(kernel, "InitializeProcThreadAttributeList", [P, wt.DWORD, wt.DWORD, ctypes.POINTER(SIZE)])
            initialize(None, 2, 0, ctypes.byref(size))
            attribute_list = ctypes.create_string_buffer(size.value)
            checked(initialize(attribute_list, 2, 0, ctypes.byref(size)))
            update = api(kernel, "UpdateProcThreadAttribute", [P, wt.DWORD, SIZE, P, SIZE, P, P])
            capabilities = Capabilities(sid, None, 0, 0)
            inherited = (P * 3)(read_in.value, write_out.value, null)
            # The active-process job limit prevents children. Win32k-disable and
            # child-process mitigation attributes prevent Python DLL initialization
            # on supported Windows builds; AppContainer and job restrictions apply
            # before the first instruction, without relying on either mitigation.
            for key, value in [(0x20009, capabilities), (0x20002, inherited)]:
                checked(update(attribute_list, 0, key, ctypes.byref(value), ctypes.sizeof(value), None, None))
            # The worker is started on a desktop of its own, on qKVM's window station, which its SID alone of all
            # AppContainers may use; where the station lets no AppContainer in, its SID is given an entry there too.
            station, station_name = own_station()
            self._desktop = worker_desktop("qkvm-video-" + ident, sid)
            own_sid = ctypes.create_string_buffer(sid_length(sid))
            checked(copy_sid(len(own_sid), own_sid, sid))
            if grant_station(station, own_sid):
                self._station, self._sid = station, own_sid
            desktop = ctypes.create_unicode_buffer(station_name + "\\qkvm-video-" + ident)
            startup = StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
            startup.startup.desktop = ctypes.cast(desktop, wt.LPWSTR)
            startup.startup.flags = 0x101  # STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW
            startup.startup.show = 0
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = read_in.value, write_out.value, null
            startup.attributes = ctypes.cast(attribute_list, P)
            windows = ctypes.create_unicode_buffer(32768)
            checked(api(kernel, "GetWindowsDirectoryW", [wt.LPWSTR, wt.UINT], wt.UINT)(windows, len(windows)))
            environment = ctypes.create_unicode_buffer("LOCALAPPDATA=" + os.environ["LOCALAPPDATA"] + "\0OMP_NUM_THREADS=1\0OPENBLAS_NUM_THREADS=1\0SystemRoot=" + windows.value + "\0\0")
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(root / "python.exe"), "-I", "-S", "-u", str(root / "worker.py"), str(root / "site-packages")]))
            create = api(kernel, "CreateProcessW", [wt.LPCWSTR, wt.LPWSTR, P, P, wt.BOOL, wt.DWORD, P, wt.LPCWSTR, ctypes.POINTER(StartupEx), ctypes.POINTER(ProcessInfo)])
            with inheriting:
                try:
                    for handle in inherited:
                        checked(set_flags(handle, 1, 1))  # HANDLE_FLAG_INHERIT, for this one call
                    checked(create(str(root / "python.exe"), command, None, None, True, 0x08080404, environment, str(root), ctypes.byref(startup), ctypes.byref(info)))
                finally:
                    # The worker holds its own copies now (or none: it was not made). These are
                    # closed before any other process can be started from here.
                    for child_end in (read_in, write_out, null):
                        handles.remove(child_end)
                        close_handle(child_end)
            self._handle = info.process
            self.pid = info.pid
            self._job = checked(api(kernel, "CreateJobObjectW", [P, wt.LPCWSTR], P)(None, None))
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000 | 0x100 | 0x8
            limits.basic.active_processes = 1
            limits.process_memory = 1024**3
            grouped = processor_groups() > 1
            if not grouped:
                limits.basic.flags |= 0x10  # JOB_OBJECT_LIMIT_AFFINITY
                self._pair, limits.basic.affinity = next_processors(avoid)
            set_job = api(kernel, "SetInformationJobObject", [P, ctypes.c_int, P, wt.DWORD])
            checked(set_job(self._job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            ui = wt.DWORD(0xFF)
            checked(set_job(self._job, 4, ctypes.byref(ui), ctypes.sizeof(ui)))
            if grouped:
                processors = checked(api(kernel, "GetActiveProcessorCount", [wt.WORD], wt.DWORD)(0xFFFF))  # every group
                rate = CpuRate(0x1 | 0x4, cpu_rate(processors))  # JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | _HARD_CAP
                checked(set_job(self._job, 15, ctypes.byref(rate), ctypes.sizeof(rate)))  # JobObjectCpuRateControlInformation
            checked(api(kernel, "AssignProcessToJobObject", [P, P])(self._job, self._handle))
            # Only start after the process/job restrictions are in place.
            if api(kernel, "ResumeThread", [P], wt.DWORD)(info.thread) == 0xFFFFFFFF:
                raise ctypes.WinError(ctypes.get_last_error())
            if write_in.value is None or read_out.value is None:
                raise OSError("video pipe handles are unavailable")
            self.stdin = io.open(msvcrt.open_osfhandle(write_in.value, os.O_WRONLY | os.O_BINARY), "wb")
            handles.remove(write_in)
            self.stdout = io.open(msvcrt.open_osfhandle(read_out.value, os.O_RDONLY | os.O_BINARY), "rb")
            handles.remove(read_out)
        except BaseException:
            for stream in (self.stdin, self.stdout):
                if stream is not None:
                    stream.close()
            self.kill()
            self.wait(timeout=2)
            raise
        finally:
            if info.thread:
                close_handle(info.thread)
            if attribute_list is not None:
                api(kernel, "DeleteProcThreadAttributeList", [P], None)(attribute_list)
            for handle in handles:
                close_handle(handle)
            free_sid(sid)

    def cpu_seconds(self) -> float | None:
        """The processor time this worker has used so far, kernel and user, by Windows' count (counted at each tick of the
        system's clock, 15.6 ms: a request's share of it is right on the whole, not request by request); None once it has
        ended or where Windows does not say."""
        with self._state_lock:
            if self._handle is None:
                return None
            created, ended, kernel_time, user_time = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
            if not get_process_times(self._handle, ctypes.byref(created), ctypes.byref(ended), ctypes.byref(kernel_time), ctypes.byref(user_time)):
                return None
        return sum((spent.dwHighDateTime << 32 | spent.dwLowDateTime) for spent in (kernel_time, user_time)) / 1e7

    def mark_stalled(self) -> None:
        """This worker missed its deadline: its pair is passed over by placements for a while."""
        pair = self._pair
        if pair is not None:
            mark_stalled(pair)

    def kill(self) -> None:
        with self._state_lock:
            if self._handle is not None and self.returncode is None:
                api(kernel, "TerminateProcess", [P, wt.UINT])(self._handle, 1)

    def wait(self, timeout: float | None = None) -> int:
        with self._state_lock:
            code = self._wait(timeout)
            # (Its entry in the station's DACL is taken out after the lock is let go: that change may wait SHARED_WAIT for
            # another qKVM's, and kill(), cpu_seconds() and the reaper's waits need the lock meanwhile.)
            station, self._station = self._station, None
        if station is not None:
            revoke_station(station, self._sid)  # (last: where it cannot be done, everything else has been given back)
        return code

    def _wait(self, timeout: float | None) -> int:
        if self._handle is not None:
            result = api(kernel, "WaitForSingleObject", [P, wt.DWORD], wt.DWORD)(self._handle, 0xFFFFFFFF if timeout is None else int(timeout * 1000))
            if result == 258:
                raise subprocess.TimeoutExpired("isolated video worker", timeout or 0)
            if result != 0:
                raise ctypes.WinError(ctypes.get_last_error())
            code = wt.DWORD()
            checked(api(kernel, "GetExitCodeProcess", [P, ctypes.POINTER(wt.DWORD)])(self._handle, ctypes.byref(code)))
            self.returncode = code.value
            close_handle(self._handle)
            self._handle = None
        if self._job is not None:
            close_handle(self._job)
            self._job = None
        if self._profile is not None:
            delete_profile(self._profile)
            self._profile = None
        if self._pair is not None:
            release_processors(self._pair)
            self._pair = None
        if self._desktop is not None:
            close_desktop(self._desktop)
            self._desktop = None
        return self.returncode or 0


def cleanup_runtime() -> None:
    global _bundle
    with _bundle_lock:
        root, _bundle = _bundle, None
        if root is not None:
            resolved = root.resolve()
            if resolved.parent != Path(tempfile.gettempdir()).resolve() or not resolved.name.startswith("qkvm-video-runtime-"):
                raise RuntimeError("unexpected video runtime cleanup path")
            shutil.rmtree(resolved)
