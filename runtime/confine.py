# kiro-classification: public
"""Child process confinement: UID switch + capability drop.

Provides ``confine_child_process`` for use as a ``preexec_fn``. The ctypes
handles are resolved lazily by ``init()`` — called once by PID 1 during the
``/run`` hook. The ``preexec_fn`` then uses only pre-resolved objects.

User code runs as **uid 1000 (sandbox)** with reduced capabilities. This
prevents overwriting root-owned system binaries, which closes the confinement
bypass where an attacker replaces binaries that PID 1 later executes.
"""
from __future__ import annotations

import os

_libc = None
_ready = False
_CapHeader = None
_CapData = None

_SANDBOX_UID = 1000
_SANDBOX_GID = 1000

_PR_SET_NO_NEW_PRIVS = 38

# Caps to DROP from user code (word 0: bits 0-31)
_SYS_ADMIN = 1 << 21
_MKNOD = 1 << 27
_SYS_PTRACE = 1 << 19
_SETUID = 1 << 7
_SETGID = 1 << 6
_NET_RAW = 1 << 13

# Caps to DROP from user code (word 1: bits 32-63)
_BPF = 1 << (39 - 32)
_PERFMON = 1 << (38 - 32)


def init() -> None:
    """Resolve ctypes objects. Call once from PID 1 before user code runs.

    PCSR Finding 6: raises on failure — a sandbox that cannot confine must not execute.
    """
    global _libc, _ready, _CapHeader, _CapData  # noqa: PLW0603
    import ctypes
    import ctypes.util

    name = ctypes.util.find_library("c")
    if not name:
        raise RuntimeError("Cannot resolve libc — sandbox confinement unavailable")
    try:
        _libc = ctypes.CDLL(name)
    except OSError as exc:
        raise RuntimeError(f"Cannot load libc — sandbox confinement unavailable: {exc}") from exc

    class H(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class D(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    _CapHeader = H
    _CapData = D
    _ready = True


def confine_child_process() -> None:
    """preexec_fn: switch to sandbox user + drop dangerous capabilities.

    PCSR Finding 6: every failure is fatal — a child that cannot be confined must not run.

    Execution order (between fork and execve):
    1. Set supplementary groups, GID, UID (must happen before cap drop — setuid needs CAP_SETUID)
    2. Set PR_SET_NO_NEW_PRIVS (prevents execve from restoring caps)
    3. Drop dangerous caps via capset

    After this, the child process:
    - Runs as uid 1000 (cannot write root-owned system binaries)
    - Has NO_NEW_PRIVS (caps cannot be restored via execve)
    - Lacks CAP_SYS_ADMIN, CAP_MKNOD, CAP_SYS_PTRACE, CAP_SETUID, CAP_SETGID,
      CAP_NET_RAW, CAP_BPF, CAP_PERFMON (8 capabilities dropped)

    PID 1 is unaffected — this runs in the fork-child only.
    """
    import ctypes  # already loaded by init(); module lookup only

    if not _ready or _libc is None:
        raise RuntimeError("Confinement not initialized — refusing to execute unconfined")

    # Step 1: Switch to sandbox user (must happen BEFORE we drop CAP_SETUID/SETGID)
    try:
        os.setgroups([_SANDBOX_GID])
        os.setgid(_SANDBOX_GID)
        os.setuid(_SANDBOX_UID)
    except OSError as exc:
        raise RuntimeError(f"Failed to switch to sandbox user (uid {_SANDBOX_UID}): {exc}") from exc

    # Step 2: Set NNP — prevents execve from restoring dropped caps
    rc = _libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if rc != 0:
        raise RuntimeError(f"prctl(PR_SET_NO_NEW_PRIVS) failed with rc={rc}")

    # Step 3: Drop dangerous caps
    hdr = _CapHeader(0x20080522, 0)
    data = (_CapData * 2)()
    if _libc.capget(ctypes.byref(hdr), ctypes.byref(data)) != 0:
        raise RuntimeError("capget failed — cannot read current capabilities")

    _drop0 = _SYS_ADMIN | _MKNOD | _SYS_PTRACE | _SETUID | _SETGID | _NET_RAW
    data[0].effective &= ~_drop0
    data[0].permitted &= ~_drop0
    data[0].inheritable &= ~_drop0
    data[1].effective &= ~(_BPF | _PERFMON)
    data[1].permitted &= ~(_BPF | _PERFMON)
    data[1].inheritable &= ~(_BPF | _PERFMON)

    if _libc.capset(ctypes.byref(hdr), ctypes.byref(data)) != 0:
        raise RuntimeError("capset failed — cannot drop dangerous capabilities")
