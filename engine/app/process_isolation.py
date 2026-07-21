from __future__ import annotations

import ctypes
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
CREATE_NEW_PROCESS_GROUP = 0x00000200 if os.name == "nt" else 0
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class WindowsJob:
    """Best-effort Windows Job Object used to contain a complete worker tree."""

    def __init__(self, memory_limit_bytes: int) -> None:
        self.handle: int | None = None
        self.error = ""
        if os.name != "nt":
            self.error = "Windows Job Objects are unavailable on this platform"
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateJobObjectW.restype = ctypes.c_void_p
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            self.error = f"CreateJobObjectW failed: {ctypes.get_last_error()}"
            return
        information = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        information.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        )
        information.ProcessMemoryLimit = memory_limit_bytes
        ok = kernel32.SetInformationJobObject(
            ctypes.c_void_p(handle),
            JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        )
        if not ok:
            self.error = f"SetInformationJobObject failed: {ctypes.get_last_error()}"
            kernel32.CloseHandle(ctypes.c_void_p(handle))
            return
        self.handle = int(handle)

    def assign(self, process: subprocess.Popen[Any]) -> bool:
        if self.handle is None or os.name != "nt":
            return False
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ok = kernel32.AssignProcessToJobObject(
            ctypes.c_void_p(self.handle), ctypes.c_void_p(int(process._handle))  # type: ignore[attr-defined]
        )
        if not ok:
            self.error = f"AssignProcessToJobObject failed: {ctypes.get_last_error()}"
            return False
        return True

    def close(self) -> None:
        if self.handle is not None and os.name == "nt":
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(ctypes.c_void_p(self.handle))
            self.handle = None


def worker_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for key in (
        "PYTHONHOME", "PYTHONPATH", "PERL5LIB", "PERLLIB", "HTTP_PROXY",
        "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "http_proxy", "https_proxy", "all_proxy",
    ):
        environment.pop(key, None)
    environment.update({
        "NO_COLOR": "1",
        "TERM": "dumb",
        "NO_PROXY": "*",
        "no_proxy": "*",
        "MAILSCOPE_STATIC_WORKER": "1",
    })
    return environment


def run_contained_json_worker(
    command: list[str],
    *,
    timeout_seconds: int = 240,
    memory_limit_mb: int = 768,
    cwd: Path | None = None,
    max_output_bytes: int = 8 * 1024 * 1024,
) -> dict[str, Any]:
    """Run a worker with a wall-clock timeout and a Windows process-tree memory boundary."""
    flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    job = WindowsJob(memory_limit_mb * 1024 * 1024)
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                cwd=str(cwd) if cwd else None,
                env=worker_environment(),
                shell=False,
                creationflags=flags,
            )
            memory_enforced = job.assign(process)
            try:
                return_code = process.wait(timeout=timeout_seconds)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                job.close()  # Kills the worker and every child assigned to the job.
                try:
                    process.kill()
                except Exception:
                    pass
                process.wait(timeout=10)
                return_code = None

            stdout_file.flush()
            stderr_file.flush()
            stdout_size = stdout_file.tell()
            stderr_size = stderr_file.tell()
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(max_output_bytes).decode("utf-8", errors="replace")
            stderr = stderr_file.read(max_output_bytes).decode("utf-8", errors="replace")
            truncated = stdout_size > max_output_bytes or stderr_size > max_output_bytes
        return {
            "success": return_code == 0 and not timed_out,
            "return_code": return_code,
            "stdout": stdout.strip(),
            "stderr": stderr.strip(),
            "timed_out": timed_out,
            "output_truncated": truncated,
            "isolation": {
                "process_tree": "windows_job_object" if memory_enforced else "separate_process",
                "memory_limit_mb": memory_limit_mb if memory_enforced else None,
                "wall_timeout_seconds": timeout_seconds,
                "network_policy": "no_network_code_path",
                "job_error": "" if memory_enforced else job.error,
            },
        }
    except Exception as exc:
        return {
            "success": False,
            "return_code": None,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "timed_out": False,
            "output_truncated": False,
            "isolation": {
                "process_tree": "failed",
                "memory_limit_mb": None,
                "wall_timeout_seconds": timeout_seconds,
                "network_policy": "no_network_code_path",
                "job_error": job.error,
            },
        }
    finally:
        job.close()
