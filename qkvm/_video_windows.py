"""Windows native-video process: capability-free AppContainer and a constrained job.

Only public Python/PyAV runtime files are copied into a read/execute-only bundle.
Each worker gets a distinct AppContainer identity, no network capabilities, three
explicit pipe handles, no child processes, restricted UI access, and two of the
machine's processors at most for all its threads together (see processors_for).
"""
from __future__ import annotations

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


def api(dll: Any, name: str, args: list[Any], result: Any = wt.BOOL) -> Any:
    function = getattr(dll, name)
    function.argtypes, function.restype = args, result
    return function


close_handle = api(kernel, "CloseHandle", [P])
local_free = api(kernel, "LocalFree", [P], P)
free_sid = api(advapi, "FreeSid", [P], P)
create_profile = api(userenv, "CreateAppContainerProfile", [wt.LPCWSTR, wt.LPCWSTR, wt.LPCWSTR, P, wt.DWORD, ctypes.POINTER(P)], ctypes.c_long)
delete_profile = api(userenv, "DeleteAppContainerProfile", [wt.LPCWSTR], ctypes.c_long)


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
    SECURITY.md says so.)"""
    own = own_processors()
    if not own:
        raise OSError("no processor to run the video worker on")
    now = time.monotonic()
    with _pairs_lock:
        def rank(i: int) -> tuple[bool, int, bool, int]:
            load = _pair_load.get(i, 0)
            return (load > 0 and _suspect.get(i, 0.0) > now, load, i == avoid, i)

        index = min(range(_pair_count(own)), key=rank)
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


def runtime_acl(path: Path) -> None:
    """Only the owner/admin/system may modify this public-code bundle."""
    token = P()
    current = api(kernel, "GetCurrentProcess", [], P)()
    checked(api(advapi, "OpenProcessToken", [P, wt.DWORD, ctypes.POINTER(P)])(current, 8, ctypes.byref(token)))
    try:
        size = wt.DWORD()
        info = api(advapi, "GetTokenInformation", [P, ctypes.c_int, P, wt.DWORD, ctypes.POINTER(wt.DWORD)])
        info(token, 1, None, 0, ctypes.byref(size))
        data = ctypes.create_string_buffer(size.value)
        checked(info(token, 1, data, size, ctypes.byref(size)))
        owner = ctypes.cast(data, ctypes.POINTER(P))[0]
        text = wt.LPWSTR()
        checked(api(advapi, "ConvertSidToStringSidW", [P, ctypes.POINTER(wt.LPWSTR)])(owner, ctypes.byref(text)))
        try:
            # All AppContainers can read public runtime code, but cannot modify it.
            # No application data, user profile, environment or credentials are copied.
            sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{text.value})(A;OICI;GRGX;;;S-1-15-2-1)"
        finally:
            local_free(text)
    finally:
        close_handle(token)
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
        self.returncode: int | None = None
        self.stdin: Any = None
        self.stdout: Any = None
        root = bundle(package, script)
        sid = P()
        profile = "qkvm.video." + uuid.uuid4().hex
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
            startup = StartupEx()
            startup.startup.cb = ctypes.sizeof(startup)
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
            return self._wait(timeout)

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
