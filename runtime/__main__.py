# kiro-classification: public
"""MicroVM entry point: ``python -m runtime`` starts the Sandbox_Runtime server.

The MicroVM image's CMD invokes this module. At image-build time, Lambda calls only ``/ready``
on port 8080 — none of the lifecycle hooks — so the actions wired here start as no-ops for the
four lifecycle methods that are not ``apply_configuration``. At runtime, ``/run`` is the first
hook called and delivers the real per-Session configuration; ``_RuntimeActions.apply_configuration``
registers the actual Sandbox operations (process, filesystem, terminal, ports) on the shared
``OperationRegistry`` so that the Sandbox_Protocol handler can route requests to them.

The bind address is ``0.0.0.0`` because the Lambda endpoint forwards traffic into the MicroVM
and that forwarding may not arrive on loopback. The port is 8080, matching the image hook
configuration. Both differ from the local-testing defaults in ``runtime.server`` and are set
explicitly here for that reason.
"""

from __future__ import annotations

import json
import os

from runtime.app import create_app
from runtime.filesystem import ConfinedRoot, FilesystemOperations
from runtime.operations import OperationRegistry
from runtime.ports import ExposedPorts
from runtime.process import ProcessManager, register_process_operations
from runtime.server import serve
from runtime.terminal import TerminalManager, register_terminal_operations

#: MicroVM network: the endpoint forwards to this address and port.
_HOST = "0.0.0.0"  # nosec B104
_PORT = 8080

#: The filesystem root every ``fs.*`` operation resolves against.
_SANDBOX_ROOT = "/tmp"  # nosec B108


def _inject_proxy_env(payload: bytes) -> None:
    """Extract ``egressEndpoint`` from the run-hook envelope and set proxy env vars.

    The MicroVM platform wraps our ``runHookPayload`` in an envelope::

        {"microvmId": "...", "runHookPayload": <our-config>}

    The orchestrator adds ``egressEndpoint`` alongside ``runHookPayload`` so we can
    set ``https_proxy`` / ``http_proxy`` without touching the configuration schema.
    If absent (e.g. older orchestrator), this is a no-op.
    """
    try:
        envelope = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(envelope, dict):
        return

    # Unwrap: platform sends {"microvmId":"...","runHookPayload":"<json-string>"}
    # Our params are inside the runHookPayload string.
    inner = envelope
    rhp = envelope.get("runHookPayload")
    if isinstance(rhp, str):
        try:
            inner = json.loads(rhp)
        except (json.JSONDecodeError, ValueError):
            pass
    elif isinstance(rhp, dict):
        inner = rhp

    endpoint = inner.get("egressEndpoint") if isinstance(inner, dict) else None

    if not endpoint or not isinstance(endpoint, str):
        return

    proxy_url = f"http://{endpoint}:443"
    os.environ["https_proxy"] = proxy_url
    os.environ["http_proxy"] = proxy_url
    os.environ["HTTPS_PROXY"] = proxy_url
    os.environ["HTTP_PROXY"] = proxy_url
    # Exclude IMDS, ECS credential endpoint, and localhost from the proxy.
    # Without this, boto3 tries to reach 169.254.169.254 through the proxy
    # and fails with NoCredentialsError.
    # Exclude IMDS, credential endpoints, localhost, and AWS service endpoints
    # that are reached via VPC interface endpoints (not the internet proxy).
    # Bedrock goes through the VPC endpoint where the proxy intercepts it as
    # an HTTP forward request and re-signs with SigV4 — routing it through
    # the CONNECT proxy would bypass the re-signing.
    no_proxy = ",".join([
        "169.254.169.254",         # IMDS
        "169.254.170.2",           # ECS credential endpoint
        "127.0.0.1",
        "localhost",
        ".amazonaws.com",          # All AWS service endpoints (VPC endpoints)
        ".api.aws",                # Newer AWS endpoint format
    ])
    os.environ["no_proxy"] = no_proxy
    os.environ["NO_PROXY"] = no_proxy
    # Also write to a file so scripts that source /etc/profile.d can pick it up
    try:
        with open("/etc/profile.d/egress-proxy.sh", "w") as f:  # nosemgrep: unspecified-open-encoding
            f.write(f"export https_proxy={proxy_url}\n")
            f.write(f"export http_proxy={proxy_url}\n")
            f.write(f"export HTTPS_PROXY={proxy_url}\n")
            f.write(f"export HTTP_PROXY={proxy_url}\n")
            f.write(f"export no_proxy={no_proxy}\n")
            f.write(f"export NO_PROXY={no_proxy}\n")
            f.write("# AWS services reached via VPC endpoints, not the internet proxy\n")
    except OSError:
        pass  # read-only filesystem at build time — that is fine


def _block_imds() -> None:
    """Block IMDS access so untrusted code cannot steal execution role credentials.

    S3 Files efs-proxy handles its own credential refresh internally (it has
    its own IMDS access before we block). boto3 in the runtime process cached
    credentials at import. After this, user-spawned processes cannot reach IMDS.

    Bedrock access goes through the egress proxy (Tier 1 SigV4 re-signing) —
    the sandbox doesn't need direct Bedrock credentials.
    """
    import subprocess  # nosec B404
    for ip in ("169.254.169.254", "169.254.170.2"):
        try:
            subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=5,
            )
        except FileNotFoundError:
            try:
                subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                    ["ip", "route", "add", "blackhole", f"{ip}/32"],
                    capture_output=True, text=True, timeout=5,
                )
            except Exception:
                pass  # nosec B110
        except Exception:
            pass  # nosec B110


def _drop_dangerous_caps() -> None:
    """Drop dangerous Linux capabilities from the bounding set.

    After S3 Files mount and iptables rules are installed, we drop capabilities
    that untrusted code should never have. The bounding set limits what child
    processes (user code) can obtain — PID 1 (the runtime) keeps its effective
    and permitted sets for resume re-mount.

    We keep CAP_SYS_ADMIN (21) because the runtime needs it to re-mount S3 Files
    on resume. Child processes inherit it but cannot exploit it meaningfully
    without IMDS credentials or network access.

    Capability reference: capabilities(7)
    """
    import ctypes
    import ctypes.util

    PR_CAPBSET_DROP = 24  # noqa: N806 — kernel constant

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return
    try:
        libc = ctypes.CDLL(libc_name)
    except OSError:
        return

    # Capabilities to drop from bounding set.
    # CAP_SYS_ADMIN (21) is intentionally kept — needed for resume re-mount.
    caps_to_drop = {
        8: "SETPCAP",       # modify other processes' capabilities
        12: "NET_ADMIN",    # iptables, routing, network config
        15: "SYS_RESOURCE", # override resource limits
        16: "SYS_MODULE",   # load/unload kernel modules
        17: "SYS_RAWIO",    # raw I/O port access
        19: "SYS_PTRACE",   # ptrace other processes
        22: "SYS_TIME",     # set system clock
        23: "SYS_BOOT",     # reboot
    }

    for cap_id in caps_to_drop:
        try:
            libc.prctl(PR_CAPBSET_DROP, cap_id, 0, 0, 0)
        except Exception:
            pass  # nosec B110 — best-effort hardening



def _lock_core_pattern() -> None:
    """Make /proc/sys/kernel/core_pattern read-only via bind mount.

    Idempotent: safe to call on both /run and /resume. If the bind mount
    survived the snapshot/restore cycle, we skip re-mounting. If it didn't
    (or was never applied), we create it fresh.
    """
    import subprocess  # nosec B404
    try:
        # Check if already read-only (survives suspend/resume in some cases)
        check = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
            ["test", "-w", "/proc/sys/kernel/core_pattern"],
            capture_output=True, text=True, timeout=3,
        )
        if check.returncode != 0:
            return  # Already locked — nothing to do

        # Not locked yet — apply bind mount
        subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
            ["mount", "--bind",
             "/proc/sys/kernel/core_pattern",
             "/proc/sys/kernel/core_pattern"],
            capture_output=True, text=True, timeout=5,
        )
        subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
            ["mount", "-o", "remount,ro,bind",
             "/proc/sys/kernel/core_pattern"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        pass  # nosec B110 — best-effort, Firecracker is the real boundary


# Confinement for child processes. The libc handle and ctypes structures are
# resolved lazily by _init_confine() — called once by PID 1 during the /run
# hook (in the MicroVM, not at module import on the build host). The preexec_fn
# then uses only pre-resolved objects: no find_library, no subprocess, no
# allocations that could deadlock in the fork-child.

_confine_libc = None     # set by _init_confine()
_confine_ready = False


def _init_confine() -> None:
    """Resolve ctypes objects for confine_child_process. Call once from PID 1."""
    global _confine_libc, _confine_ready, _CapHeader, _CapData  # noqa: PLW0603
    import ctypes
    import ctypes.util

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return
    try:
        _confine_libc = ctypes.CDLL(libc_name)
    except OSError:
        return

    class _CapHeaderCls(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class _CapDataCls(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    _CapHeader = _CapHeaderCls
    _CapData = _CapDataCls
    _confine_ready = True


_PR_SET_NO_NEW_PRIVS = 38
_CAP_SYS_ADMIN_BIT = 1 << 21
_CAP_MKNOD_BIT = 1 << 27
_CAP_BPF_BIT = 1 << (39 - 32)
_CAP_PERFMON_BIT = 1 << (38 - 32)


def confine_child_process() -> None:
    """Drop dangerous capabilities from the current process before execve.

    Called as ``preexec_fn`` in subprocess/asyncio spawn so that user code runs
    with reduced privileges. Uses ``PR_SET_NO_NEW_PRIVS`` + ``capset()`` to
    irrevocably strip CAP_SYS_ADMIN, CAP_BPF, CAP_MKNOD, and CAP_PERFMON.

    **preexec_fn safety**: ``_init_confine()`` was called by PID 1 during the
    ``/run`` hook, resolving all ctypes objects. This function only calls
    libc.prctl / libc.capget / libc.capset through pre-resolved handles.

    PID 1 is unaffected — this runs in the fork-child only.
    """
    import ctypes as _ctypes  # already loaded by _init_confine; this is a no-op lookup

    if not _confine_ready or _confine_libc is None:
        return

    _confine_libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    hdr = _CapHeader(0x20080522, 0)
    data = (_CapData * 2)()
    if _confine_libc.capget(_ctypes.byref(hdr), _ctypes.byref(data)) != 0:
        return

    data[0].effective &= ~(_CAP_SYS_ADMIN_BIT | _CAP_MKNOD_BIT)
    data[0].permitted &= ~(_CAP_SYS_ADMIN_BIT | _CAP_MKNOD_BIT)
    data[0].inheritable &= ~(_CAP_SYS_ADMIN_BIT | _CAP_MKNOD_BIT)
    data[1].effective &= ~(_CAP_BPF_BIT | _CAP_PERFMON_BIT)
    data[1].permitted &= ~(_CAP_BPF_BIT | _CAP_PERFMON_BIT)
    data[1].inheritable &= ~(_CAP_BPF_BIT | _CAP_PERFMON_BIT)

    _confine_libc.capset(_ctypes.byref(hdr), _ctypes.byref(data))


_RUNTIME_INJECTED_KEYS = frozenset({
    "egressEndpoint",
    "s3filesFileSystemId",
    "s3filesAccessPointId",
    "s3filesMountTargetIp",
    "s3filesRegion",
})


def _strip_runtime_keys(payload: bytes) -> bytes:
    """Remove orchestrator-injected keys that the config parser doesn't understand.

    The platform wraps our payload as {"microvmId":"...","runHookPayload":"<json>"}.
    The runtime keys are inside runHookPayload. We strip them from the inner JSON
    and re-serialize the envelope.
    """
    try:
        envelope = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return payload
    if not isinstance(envelope, dict):
        return payload

    rhp = envelope.get("runHookPayload")
    if isinstance(rhp, str):
        try:
            inner = json.loads(rhp)
            if isinstance(inner, dict):
                stripped = {k: v for k, v in inner.items() if k not in _RUNTIME_INJECTED_KEYS}
                envelope["runHookPayload"] = json.dumps(stripped, separators=(",", ":"))
                return json.dumps(envelope, separators=(",", ":")).encode()
        except (json.JSONDecodeError, ValueError):
            pass
    elif isinstance(rhp, dict):
        stripped = {k: v for k, v in rhp.items() if k not in _RUNTIME_INJECTED_KEYS}
        envelope["runHookPayload"] = stripped
        return json.dumps(envelope, separators=(",", ":")).encode()
    else:
        stripped = {k: v for k, v in envelope.items() if k not in _RUNTIME_INJECTED_KEYS}
        return json.dumps(stripped, separators=(",", ":")).encode()
    return payload


def _mount_s3files(payload: bytes) -> None:
    """Mount S3 Files workspace at /mnt/workspace if params are in the payload.

    The orchestrator includes ``s3filesFileSystemId``, ``s3filesAccessPointId``,
    ``s3filesMountTargetIp``, and ``s3filesRegion`` when ``persistence=true``.
    If absent, this is a no-op and the session uses ephemeral ``/tmp`` only.
    """
    import subprocess  # nosec B404
    import secrets
    import time
    from pathlib import Path

    try:
        envelope = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if not isinstance(envelope, dict):
        return

    # Unwrap: platform sends {"microvmId":"...","runHookPayload":"<json-string>"}
    inner = envelope
    rhp = envelope.get("runHookPayload")
    if isinstance(rhp, str):
        try:
            inner = json.loads(rhp)
        except (json.JSONDecodeError, ValueError):
            pass
    elif isinstance(rhp, dict):
        inner = rhp

    fs_id = inner.get("s3filesFileSystemId", "") if isinstance(inner, dict) else ""
    ap_id = inner.get("s3filesAccessPointId", "") if isinstance(inner, dict) else ""
    mt_ip = inner.get("s3filesMountTargetIp", "") if isinstance(inner, dict) else ""
    region = inner.get("s3filesRegion", "us-east-1") if isinstance(inner, dict) else "us-east-1"


    if not fs_id:
        return  # No S3 Files configured — ephemeral /tmp only

    mount_path = "/mnt/workspace"
    Path(mount_path).mkdir(parents=True, exist_ok=True)

    # Check if already mounted (e.g. after resume).
    # Use `mountpoint` not `findmnt -T`, because findmnt returns the parent FS
    # for any existing path (even if it's just a dir on the root FS).
    try:
        check = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
            ["mountpoint", "-q", mount_path],
            capture_output=True, timeout=5,
        )
        if check.returncode == 0:
            return  # Already a mountpoint — skip
    except Exception:  # nosec B110
        pass

    opts = ["tls", "iam"]
    if ap_id:
        opts.append(f"accesspoint={ap_id}")
    if mt_ip:
        opts.append(f"mounttargetip={mt_ip}")
    if region:
        opts.append(f"region={region}")

    cmd = ["mount", "-t", "s3files", "-o", ",".join(opts), f"{fs_id}:/", mount_path]

    # Debug: write the command
    try:
        with open("/tmp/_debug_mount.json", "r", encoding="utf-8") as _f:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
            _dbg = json.loads(_f.read())
        _dbg["mount_cmd"] = " ".join(cmd)
        with open("/tmp/_debug_mount.json", "w", encoding="utf-8") as _f:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
            _f.write(json.dumps(_dbg, indent=2))
    except Exception:  # nosec B110
        pass

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)  # nosemgrep: dangerous-subprocess-use-audit # nosec B603

        # Debug: write result
        try:
            with open("/tmp/_debug_mount.json", "r", encoding="utf-8") as _f:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
                _dbg = json.loads(_f.read())
            _dbg["mount_rc"] = result.returncode
            _dbg["mount_stdout"] = (result.stdout or "")[:200]
            _dbg["mount_stderr"] = (result.stderr or "")[:200]
            with open("/tmp/_debug_mount.json", "w", encoding="utf-8") as _f:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
                _f.write(json.dumps(_dbg, indent=2))
        except Exception:  # nosec B110
            pass

        if result.returncode != 0:
            print(json.dumps({
                "msg": "s3files_mount_failed",
                "rc": result.returncode,
                "err": (result.stderr or result.stdout or "").strip()[:200],
            }), flush=True)
            return

        # Wait for mount to be usable (efs-proxy TLS tunnel warmup)
        probe = f"{mount_path}/.readycheck-{secrets.token_hex(4)}"
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                p = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                    ["sh", "-c", f'echo ok > "{probe}" && cat "{probe}" >/dev/null && rm -f "{probe}"'],
                    capture_output=True, text=True, timeout=3,
                )
                if p.returncode == 0:
                    # Save params for re-mount on resume
                    try:
                        with open("/tmp/_s3files_params.json", "w", encoding="utf-8") as _pf:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
                            _pf.write(json.dumps({"fs_id": fs_id, "ap_id": ap_id, "mt_ip": mt_ip, "region": region}))
                    except Exception:  # nosec B110
                        pass
                    print(json.dumps({"msg": "s3files_mounted", "path": mount_path, "fs": fs_id}), flush=True)
                    return
            except Exception:  # nosec B110
                pass
            time.sleep(1)  # nosemgrep: arbitrary-sleep

        print(json.dumps({"msg": "s3files_mount_not_usable", "path": mount_path}), flush=True)
    except Exception as e:
        print(json.dumps({"msg": "s3files_mount_error", "err": str(e)[:200]}), flush=True)


def _mount_s3files_from_params(params: dict) -> None:
    """Re-mount S3 Files from saved params (used on /resume).

    On resume, the NFS mount entry may survive in the kernel mount table but
    the underlying TCP connection to the mount target is dead (torn down during
    suspend). We detect this by probing the mount with a short-timeout I/O.
    If the mount is stale, we lazy-unmount it and re-mount fresh.
    """
    import subprocess  # nosec B404
    import secrets
    import time
    from pathlib import Path

    fs_id = params.get("fs_id", "")
    ap_id = params.get("ap_id", "")
    mt_ip = params.get("mt_ip", "")
    region = params.get("region", "us-east-1")
    mount_path = "/mnt/workspace"

    if not fs_id:
        return

    Path(mount_path).mkdir(parents=True, exist_ok=True)

    # Check if mounted AND usable. A stale NFS mount looks "mounted" but I/O hangs.
    try:
        check = subprocess.run(["mountpoint", "-q", mount_path], capture_output=True, timeout=5)  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
        if check.returncode == 0:
            # Mount entry exists — probe if it's actually usable
            probe = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                ["stat", mount_path],
                capture_output=True, text=True, timeout=5,
            )
            if probe.returncode == 0:
                return  # Mount is live and usable — nothing to do

            # Mount exists but I/O failed/timed out — stale NFS connection
            print(json.dumps({"msg": "s3files_stale_mount", "path": mount_path}), flush=True)
            subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                ["umount", "-l", mount_path],  # lazy unmount — detaches immediately
                capture_output=True, text=True, timeout=10,
            )
            time.sleep(1)  # let the lazy unmount settle  # nosemgrep: arbitrary-sleep
    except subprocess.TimeoutExpired:
        # mountpoint or stat timed out — definitely stale
        print(json.dumps({"msg": "s3files_mount_timeout", "path": mount_path}), flush=True)
        try:
            subprocess.run(["umount", "-l", mount_path], capture_output=True, text=True, timeout=10)  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
            time.sleep(1)  # nosemgrep: arbitrary-sleep
        except Exception:  # nosec B110
            pass
    except Exception:  # nosec B110
        pass

    # (Re-)mount fresh
    opts = ["tls", "iam"]
    if ap_id:
        opts.append(f"accesspoint={ap_id}")
    if mt_ip:
        opts.append(f"mounttargetip={mt_ip}")
    if region:
        opts.append(f"region={region}")

    cmd = ["mount", "-t", "s3files", "-o", ",".join(opts), f"{fs_id}:/", mount_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
        if result.returncode != 0:
            print(json.dumps({"msg": "s3files_remount_failed", "rc": result.returncode,
                              "err": (result.stderr or "")[:200]}), flush=True)
            return

        # Wait for mount to be usable (TLS tunnel warmup)
        probe = f"{mount_path}/.readycheck-{secrets.token_hex(4)}"
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                p = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                    ["sh", "-c", f'echo ok > "{probe}" && cat "{probe}" >/dev/null && rm -f "{probe}"'],
                    capture_output=True, text=True, timeout=5)
                if p.returncode == 0:
                    print(json.dumps({"msg": "s3files_resumed", "path": mount_path}), flush=True)
                    return
            except Exception:  # nosec B110
                pass
            time.sleep(1)  # nosemgrep: arbitrary-sleep

        print(json.dumps({"msg": "s3files_resume_not_usable", "path": mount_path}), flush=True)
    except subprocess.TimeoutExpired:
        print(json.dumps({"msg": "s3files_remount_timeout"}), flush=True)
    except Exception as e:
        print(json.dumps({"msg": "s3files_remount_error", "err": str(e)[:200]}), flush=True)


class _RuntimeActions:
    """Wire real operations when ``/run`` delivers the per-Session configuration.

    At image-build time Lambda calls ``/ready`` and none of the lifecycle hooks, so the four
    non-configuration methods are no-ops. When ``/run`` fires, ``apply_configuration`` registers
    the process, filesystem, terminal and port operations on the ``OperationRegistry`` the app
    already holds, so the Sandbox_Protocol handler begins routing requests to them.

    The ``OperationRegistry`` is created before the app and shared between this class and
    ``create_app``, so registration here is visible to the handler immediately.
    """

    def __init__(self, registry: OperationRegistry) -> None:
        self._registry = registry
        self._process_manager: ProcessManager | None = None
        self._terminal_manager: TerminalManager | None = None

    async def apply_configuration(self, payload: bytes) -> None:
        """Register the real operations on ``/run``.

        Before wiring the operations, extract the egress proxy endpoint from the
        run-hook payload envelope and set ``https_proxy`` / ``http_proxy`` so that
        child processes (``dnf install``, ``pip install``, ``curl``, …) route
        through the governed egress proxy rather than attempting a direct connection
        that the zero-route connector subnet will silently drop.
        """
        # DEBUG: dump payload structure to a file readable from the session
        try:
            with open("/tmp/_debug_payload.json", "w", encoding="utf-8") as _dbg:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
                try:
                    _decoded = json.loads(payload)
                    _dbg.write(json.dumps({
                        "payload_keys": list(_decoded.keys()) if isinstance(_decoded, dict) else str(type(_decoded)),
                        "payload_size": len(payload),
                        "payload_sample": payload.decode("utf-8", errors="replace")[:500],
                    }, indent=2))
                except Exception as _e:
                    _dbg.write(json.dumps({"error": str(_e), "raw_bytes": len(payload)}))
        except Exception:  # nosec B110
            pass

        _inject_proxy_env(payload)
        _mount_s3files(payload)
        # IMDS blocking removed: iptables approach breaks efs-proxy credential
        # refresh on resume (confirmed: xt_cgroup not available in kernel to
        # selectively allow efs-proxy). IMDS creds are mitigated by:
        # - DenyBedrockDirect IAM policy
        # - DenyEgressSecrets/DenyEgressKey/DenyProxyRole IAM policies
        # - Tenant-scoped S3 prefix (AllowSessionArtifactAccess)
        # - aws:SourceVpce condition (when S3 Gateway Endpoint is configured)
        _drop_dangerous_caps()
        _lock_core_pattern()
        import runtime.confine; runtime.confine.init()
        # Ensure /tmp and /mnt/workspace are writable by sandbox user (uid 1000).
        # For NFS mounts (S3 Files), chown may be rejected by root_squash —
        # use chmod 1777 (sticky + world-writable) as fallback, same as /tmp.
        import os as _os
        for _p in ("/tmp", "/mnt/workspace"):  # nosec B108
            try:
                _os.makedirs(_p, exist_ok=True)
                _os.chown(_p, 1000, 1000)
            except OSError:
                pass
            try:
                _os.chmod(_p, 0o1777)  # nosec B103 # nosemgrep: insecure-file-permissions — sticky + world-writable like /tmp; required for uid 1000 on NFS
            except OSError:
                pass
        # Strip runtime-injected keys before the config parser sees the payload.
        # The orchestrator adds egressEndpoint, s3files* alongside the config document;
        # parse_configuration rejects unknown keys, so we must remove them.
        payload = _strip_runtime_keys(payload)
        registry = self._registry

        # Process operations: exec.request, proc.start, proc.status.
        self._process_manager = register_process_operations(registry)

        # Filesystem operations: fs.read, fs.write, fs.list, fs.delete.
        root = ConfinedRoot(_SANDBOX_ROOT)
        fs = FilesystemOperations(root, catalogue=registry.catalogue)
        fs.register(registry)

        # Terminal operations: pty.open, pty.data, pty.resize, pty.close.
        self._terminal_manager = register_terminal_operations(registry)

        # Port operations: port.expose.
        ports = ExposedPorts(catalogue=registry.catalogue)
        ports.register(registry)

    async def quiesce_and_flush(self) -> None:
        """Nothing to flush at build time."""

    async def refresh_egress_identity(self) -> None:
        """Re-mount S3 Files on resume (non-blocking).

        NFS connections are torn down on suspend. The mount needs a fresh TCP
        connection which can take several seconds. We run it in a thread so it
        doesn't block the async event loop — the runtime can start accepting
        requests while the mount reconnects in the background.

        iptables rules and the core_pattern bind mount survive the
        snapshot/restore cycle (kernel state is preserved). No need to re-apply.
        """
        import asyncio

        async def _background_remount():
            try:
                with open("/tmp/_s3files_params.json", "r", encoding="utf-8") as f:  # nosemgrep: hardcoded-tmp-path unspecified-open-encoding # nosec B108
                    params = json.loads(f.read())
                if params.get("fs_id"):
                    await asyncio.get_event_loop().run_in_executor(
                        None, _mount_s3files_from_params, params
                    )
            except FileNotFoundError:
                pass  # No persistence — nothing to re-mount
            except Exception:  # nosec B110
                pass  # Best effort

        # Fire-and-forget: don't block the resume hook
        asyncio.ensure_future(_background_remount())

    async def persist_artifacts(self) -> None:
        """No artifacts to persist at build time."""


registry = OperationRegistry()
actions = _RuntimeActions(registry)
app = create_app(actions=actions, operations=registry)
serve(app, host=_HOST, port=_PORT)
