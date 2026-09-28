"""Minimal S3 Files mount test for Lambda MicroVMs.
Single port 8080 for both app and hooks (matching our runtime pattern).
"""
import json
import os
import secrets
import subprocess  # nosec B404
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

MOUNT_PATH = os.environ.get("S3FILES_MOUNT_PATH", "/mnt/workspace")
HOOK_PATH = "/aws/lambda-microvms/runtime/v1"

MOUNT = {
    "file_system_id": None, "access_point_id": None,
    "mount_target_ip": None, "region": None,
    "bucket": None, "prefix": None, "last_error": None,
}
STATE = {"boot_time": datetime.now(timezone.utc).isoformat(), "events": [], "ready": False}


def log(msg, **kw):
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "msg": msg, **kw}), flush=True)


def _is_mounted():
    try:
        out = subprocess.run(["findmnt", "-T", MOUNT_PATH, "-n"],  # nosec B603 B607
                             capture_output=True, text=True, timeout=5)
        return out.returncode == 0 and bool(out.stdout.strip())
    except Exception:
        return False


def mount_s3files():
    fsid = MOUNT["file_system_id"]
    if not fsid:
        MOUNT["last_error"] = "no file_system_id"
        return False
    if _is_mounted():
        return True
    Path(MOUNT_PATH).mkdir(parents=True, exist_ok=True)
    opts = ["tls", "iam"]
    if MOUNT.get("access_point_id"):
        opts.append("accesspoint=%s" % MOUNT["access_point_id"])
    if MOUNT.get("mount_target_ip"):
        opts.append("mounttargetip=%s" % MOUNT["mount_target_ip"])
    if MOUNT.get("region"):
        opts.append("region=%s" % MOUNT["region"])
    cmd = ["mount", "-t", "s3files", "-o", ",".join(opts), "%s:/" % fsid, MOUNT_PATH]
    log("mount_attempt", cmd=" ".join(cmd))
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=35)  # nosemgrep  # nosec B603
        if res.returncode != 0 or not _is_mounted():
            MOUNT["last_error"] = (res.stderr or res.stdout or "mount failed").strip()
            log("mount_failed", rc=res.returncode, err=MOUNT["last_error"])
            return False
        probe = "%s/.readycheck-%s" % (MOUNT_PATH, secrets.token_hex(4))
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            try:
                res2 = subprocess.run(  # nosemgrep: dangerous-subprocess-use-audit # nosec B603 B607
                    ["sh", "-c", 'echo ready > "%s" && cat "%s" >/dev/null && rm -f "%s"' % (probe, probe, probe)],  # nosemgrep: dangerous-subprocess-use-tainted-env-args
                    capture_output=True, text=True, timeout=3)
                if res2.returncode == 0:
                    MOUNT["last_error"] = None
                    log("mount_ok", path=MOUNT_PATH)
                    return True
            except Exception:  # nosec B110
                pass
            time.sleep(1)  # nosemgrep: arbitrary-sleep
        MOUNT["last_error"] = "mount registered but not usable"
        return False
    except Exception as e:
        MOUNT["last_error"] = str(e)
        return False


def _apply_payload(raw):
    if not raw:
        return
    try:
        env = json.loads(raw)
    except Exception:
        return
    inner = env
    if isinstance(env, dict):
        for k in ("runHookPayload", "runPayload"):
            if k in env:
                val = env[k]
                if isinstance(val, dict):
                    inner = val
                elif isinstance(val, str):
                    try:
                        inner = json.loads(val)
                    except Exception:  # nosec B110
                        pass
                break
    if not isinstance(inner, dict):
        return
    for k_src, k_dst in (
        ("fileSystemId", "file_system_id"),
        ("accessPointId", "access_point_id"),
        ("mountTargetIp", "mount_target_ip"),
        ("region", "region"),
        ("bucket", "bucket"),
        ("prefix", "prefix"),
    ):
        if inner.get(k_src):
            MOUNT[k_dst] = inner[k_src]


app = Flask("mount-test")

# --- App routes ---
@app.get("/")
def index():
    return jsonify({
        "service": "s3files-mount-test",
        "mounted": _is_mounted(),
        "mount_path": MOUNT_PATH,
        "file_system_id": MOUNT["file_system_id"],
        "last_error": MOUNT["last_error"],
        "python": sys.version.split()[0],
    })

@app.get("/files")
@app.get("/files/<path:rel>")
def files(rel=""):
    if not _is_mounted():
        return jsonify({"error": "not mounted", "last_error": MOUNT["last_error"]}), 503
    base = Path(MOUNT_PATH).resolve()
    target = (base / rel.lstrip("/")).resolve()
    # Prevent path traversal — ensure target stays within base directory
    if not str(target).startswith(str(base) + "/") and target != base:
        return jsonify({"error": "forbidden — path traversal detected"}), 403
    if target.is_dir():
        entries = [{"name": c.name, "type": "dir" if c.is_dir() else "file"}
                   for c in sorted(target.iterdir())]
        return jsonify({"path": "/" + rel, "entries": entries})
    if target.is_file():
        return target.read_text(), 200, {"Content-Type": "text/plain"}
    return jsonify({"error": "not found"}), 404

@app.get("/lifecycle")
def lifecycle():
    return jsonify({"mount": dict(MOUNT, mounted=_is_mounted()), "events": STATE["events"]})


# --- Lifecycle hooks (same port 8080) ---
@app.post(HOOK_PATH + "/ready")
def hook_ready():
    if STATE["ready"]:
        STATE["events"].append({"event": "ready", "at": datetime.now(timezone.utc).isoformat()})
        return jsonify({"status": "ready"}), 200
    return jsonify({"status": "warming_up"}), 503

@app.post(HOOK_PATH + "/validate")
def hook_validate():
    STATE["events"].append({"event": "validate", "at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"status": "valid"}), 200

@app.post(HOOK_PATH + "/run")
def hook_run():
    raw = request.get_data(as_text=True) or ""
    _apply_payload(raw)
    mounted = mount_s3files()
    STATE["events"].append({"event": "run", "at": datetime.now(timezone.utc).isoformat(),
                            "mounted": mounted, "fs": MOUNT["file_system_id"]})
    return jsonify({"status": "ok", "mounted": mounted}), 200

@app.post(HOOK_PATH + "/resume")
def hook_resume():
    mounted = mount_s3files()
    STATE["events"].append({"event": "resume", "at": datetime.now(timezone.utc).isoformat(), "mounted": mounted})
    return jsonify({"status": "ok", "mounted": mounted}), 200

@app.post(HOOK_PATH + "/suspend")
def hook_suspend():
    STATE["events"].append({"event": "suspend", "at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"status": "ok"}), 200

@app.post(HOOK_PATH + "/terminate")
def hook_terminate():
    STATE["events"].append({"event": "terminate", "at": datetime.now(timezone.utc).isoformat()})
    return jsonify({"status": "ok"}), 200


def _warmup():
    time.sleep(1.5)  # nosemgrep: arbitrary-sleep
    STATE["ready"] = True
    log("warmup_complete")


if __name__ == "__main__":
    log("startup", pid=os.getpid())
    threading.Thread(target=_warmup, daemon=True).start()
    app.run(host="0.0.0.0", port=8080, threaded=True, use_reloader=False)  # nosemgrep: avoid_app_run_with_bad_host # nosec B104
