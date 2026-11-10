# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Keeps a self-built Profile Lock Firefox on Windows current with Nightly.

Meant to run once a day from Task Scheduler (see register-task.ps1). Each run:

- asks Mozilla's update server which Nightly it is currently shipping, so a
  Nightly that Mozilla paused for severe problems is never picked up;
- rebuilds when a week has passed since the last build and that Nightly has
  been out for a day, or straight away when the Nightly fixes a security bug
  (one hidden in Bugzilla, or tagged sec-critical/sec-high);
- builds it with the Profile Lock patch applied, in a dedicated git worktree,
  smoke-tests it, backs up the protected profiles and swaps the program
  folder, keeping the previous one for rollback.

Profiles are never modified. If anything fails, the installed build is kept.
See README.md for setup and rollback.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
APPDATA = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))

CONFIG = {
    # The clone of the Profile Lock repository this script lives in.
    "source_dir": str(Path(__file__).resolve().parents[3]),
    # Separate worktree the updater builds in, so your own checkout is never
    # touched. Keep the path short: Windows builds dislike long paths.
    "work_dir": "C:/ffpl-auto",
    "install_dir": str(LOCALAPPDATA / "FirefoxProfileLock"),
    "state_dir": str(LOCALAPPDATA / "FirefoxProfileLock-updater"),
    "profiles_dir": str(APPDATA / "Mozilla/Firefox"),
    "mozillabuild": "C:/mozilla-build",
    "patch_repo": "https://github.com/pfinnpyro/firefox",
    "patch_branch": "claude/sleepy-pascal-41u91n",
    "upstream_repo": "https://github.com/mozilla-firefox/firefox",
    "rebuild_every_days": 7,
    "soak_hours": 24,
    "min_security_interval_days": 2,
    "keep_backups": 2,
}

BALROG = (
    "https://aus5.mozilla.org/update/6/Firefox/{version}/{build_id}/"
    "WINNT_x86_64-msvc-x64/en-US/nightly/"
    "Windows_NT%2010.0.0.0.22631.4602%20(x64)/ISET:SSE4_2,MEM:32768/default/default/"
    "update.xml"
)
HG2GIT = "https://lando.moz.tools/api/hg2git/firefox/{rev}"
PUSHLOG = "https://hg.mozilla.org/mozilla-central/json-pushes"
BUGZILLA = "https://bugzilla.mozilla.org/rest/bug"
SEVERE_SECURITY_KEYWORDS = {"sec-critical", "sec-high"}
BUG_RE = re.compile(r"\bbug\s*(\d{5,8})\b", re.IGNORECASE)


class UpdateError(Exception):
    pass


# --- Logging and notifications ---------------------------------------------


def log(message):
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    line = f"{stamp} {message}"
    print(line, flush=True)
    log_file = Path(CONFIG["state_dir"]) / "updater.log"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def notify(title, body):
    """Best-effort Windows toast; the log is the record either way."""
    if os.name != "nt":
        return
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, "
        "Windows.UI.Notifications, ContentType = WindowsRuntime] > $null;"
        "$t = [Windows.UI.Notifications.ToastNotificationManager]::"
        "GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::"
        "ToastText02);"
        "$x = $t.GetElementsByTagName('text');"
        f"$x.Item(0).AppendChild($t.CreateTextNode({ps_quote(title)})) > $null;"
        f"$x.Item(1).AppendChild($t.CreateTextNode({ps_quote(body)})) > $null;"
        "$id = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\"
        "WindowsPowerShell\\v1.0\\powershell.exe';"
        "[Windows.UI.Notifications.ToastNotificationManager]::"
        "CreateToastNotifier($id).Show("
        "[Windows.UI.Notifications.ToastNotification]::new($t))"
    )
    subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        check=False,
        capture_output=True,
    )


def ps_quote(text):
    return "'" + text.replace("'", "''") + "'"


# --- State ------------------------------------------------------------------


def state_path():
    return Path(CONFIG["state_dir"]) / "state.json"


def load_state():
    try:
        return json.loads(state_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_state(state):
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


# --- Upstream: what to build, and whether it is urgent ----------------------


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "profilelock-updater"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def fetch_json(url):
    return json.loads(fetch(url))


def offered_nightly(version, current_build_id=None):
    """The Nightly Mozilla's update server currently ships to Windows x64.

    A Nightly with severe problems is not offered: release management pauses
    Nightly updates when one is found. The server only answers builds it
    still updates, so ask as the installed build, or one from two weeks ago.
    """
    if not current_build_id:
        two_weeks_ago = datetime.datetime.now() - datetime.timedelta(days=14)
        current_build_id = two_weeks_ago.strftime("%Y%m%d%H%M%S")
    xml = fetch(BALROG.format(version=version, build_id=current_build_id)).decode()
    build_id = re.search(r'buildID="(\d{14})"', xml)
    mar_url = re.search(r'URL="([^"]+\.complete\.mar)"', xml)
    if not build_id or not mar_url:
        raise UpdateError("The update server offered no Nightly (updates paused?)")
    info = fetch_json(mar_url.group(1).replace(".complete.mar", ".json"))
    hg_rev = info["moz_source_stamp"]
    git_rev = fetch_json(HG2GIT.format(rev=hg_rev))["git_hash"]
    built = datetime.datetime.strptime(build_id.group(1), "%Y%m%d%H%M%S")
    return {
        "build_id": build_id.group(1),
        "built": built.replace(tzinfo=datetime.timezone.utc).isoformat(),
        "hg": hg_rev,
        "git": git_rev,
        "version": info.get("moz_app_version") or version,
    }


def bug_ids_between(from_hg, to_hg):
    query = urllib.parse.urlencode({
        "fromchange": from_hg,
        "tochange": to_hg,
        "full": 1,
        "version": 2,
    })
    pushes = fetch_json(f"{PUSHLOG}?{query}")["pushes"]
    ids = set()
    for push in pushes.values():
        for changeset in push["changesets"]:
            ids.update(int(m) for m in BUG_RE.findall(changeset["desc"]))
    return sorted(ids)


def is_hidden_bug(bug_id):
    """Bugzilla answers "not authorized" (code 102) for a bug that exists but
    is hidden, and "does not exist" (code 101) for a bad number."""
    req = urllib.request.Request(
        f"{BUGZILLA}/{bug_id}?include_fields=id",
        headers={"User-Agent": "profilelock-updater"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60):
            return False
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read()).get("code") == 102
        except ValueError:
            return False


def security_bugs(bug_ids):
    """Bugs that are security fixes: hidden from the public, which Mozilla
    does for every security bug until the fix ships, or keyed sec-critical /
    sec-high."""
    found = []
    for start in range(0, len(bug_ids), 100):
        chunk = bug_ids[start : start + 100]
        query = urllib.parse.urlencode({
            "id": ",".join(map(str, chunk)),
            "include_fields": "id,keywords",
            "permissive": 1,
        })
        result = fetch_json(f"{BUGZILLA}?{query}")
        visible = {}
        for bug in result.get("bugs", []):
            visible[bug["id"]] = set(bug.get("keywords", []))
        for bug_id in chunk:
            keywords = visible.get(bug_id)
            if keywords is None:
                if is_hidden_bug(bug_id):
                    found.append((bug_id, "hidden"))
            elif keywords & SEVERE_SECURITY_KEYWORDS:
                found.append((
                    bug_id,
                    ",".join(sorted(keywords & SEVERE_SECURITY_KEYWORDS)),
                ))
    return found


def decide(state, offered, security, now):
    """Pick what to build now, if anything.

    Returns (build, reason) where build is the Nightly to build or None. May
    record a candidate in state, which the caller saves.

    - Security fixes: build the offered Nightly straight away, but not more
      than once every min_security_interval_days, since Nightly takes security
      fixes almost daily.
    - Weekly: when a rebuild is due, remember the offered Nightly as the
      candidate, and build it once it has been out for soak_hours and Mozilla
      has shipped a newer Nightly since, which it would not have done had it
      paused updates over a severe problem in the candidate.
    """
    if state.get("built_hg") == offered["hg"]:
        return None, "already on the Nightly Mozilla is shipping"

    last = state.get("built_at")
    since_last = now - datetime.datetime.fromisoformat(last) if last else None

    if security:
        interval = datetime.timedelta(days=CONFIG["min_security_interval_days"])
        if since_last is None or since_last >= interval:
            return offered, "security fixes: " + ", ".join(
                f"bug {bug_id} ({why})" for bug_id, why in security[:10]
            ) + (f" and {len(security) - 10} more" if len(security) > 10 else "")

    if since_last is not None and since_last < datetime.timedelta(
        days=CONFIG["rebuild_every_days"]
    ):
        if security:
            return None, "security fixes pending; rebuilt too recently"
        return None, "weekly rebuild not due and no security fixes"

    candidate = state.get("candidate")
    if not candidate:
        state["candidate"] = dict(offered, seen=now.isoformat())
        return None, f"weekly rebuild due; soaking Nightly {offered['build_id']}"

    soaked = now - datetime.datetime.fromisoformat(candidate["seen"])
    if soaked < datetime.timedelta(hours=CONFIG["soak_hours"]):
        return None, f"soaking Nightly {candidate['build_id']}"
    if offered["build_id"] <= candidate["build_id"]:
        return None, (
            f"Mozilla has shipped nothing newer than Nightly "
            f"{candidate['build_id']}; updates may be paused, waiting"
        )
    return candidate, f"weekly rebuild of Nightly {candidate['build_id']}, soaked"


# --- Building ---------------------------------------------------------------


def run(cmd, cwd=None, env=None, check=True):
    log("$ " + " ".join(str(c) for c in cmd))
    result = subprocess.run(cmd, cwd=cwd, env=env, check=False)
    if check and result.returncode:
        raise UpdateError(f"Command failed ({result.returncode}): {cmd[0]}")
    return result.returncode


def git(*args, cwd=None, capture=False):
    cmd = ["git", *args]
    if capture:
        return subprocess.run(
            cmd, cwd=cwd, check=True, capture_output=True, text=True
        ).stdout.strip()
    return run(cmd, cwd=cwd)


def posix_path(path):
    path = Path(path).resolve()
    drive = path.drive.rstrip(":").lower()
    return f"/{drive}" + path.as_posix()[len(path.drive) :]


def mach(work_dir, *args):
    mozillabuild = Path(CONFIG["mozillabuild"])
    env = dict(os.environ, MOZILLABUILD=str(mozillabuild) + os.sep)
    bash = mozillabuild / "msys2/usr/bin/bash.exe"
    command = f"cd {posix_path(work_dir)!r} && ./mach {' '.join(args)}"
    run([bash, "--login", "-c", command], env=env)


def prepare_source(target):
    src = Path(CONFIG["source_dir"])
    work = Path(CONFIG["work_dir"])
    branch_ref = "refs/profilelock/patch-tip"
    git(
        "fetch",
        "--depth=50",
        CONFIG["patch_repo"],
        f"+{CONFIG['patch_branch']}:{branch_ref}",
        cwd=src,
    )
    base = git(
        "show",
        f"{branch_ref}:tools/profilelock/autoupdate/upstream-base.txt",
        cwd=src,
        capture=True,
    )
    git("fetch", "--depth=1", CONFIG["upstream_repo"], base, cwd=src)
    git("fetch", "--depth=1", CONFIG["upstream_repo"], target["git"], cwd=src)

    patch = Path(CONFIG["state_dir"]) / "profilelock.patch"
    diff = subprocess.run(
        ["git", "diff", "--binary", base, branch_ref],
        cwd=src,
        check=True,
        capture_output=True,
    ).stdout
    patch.write_bytes(diff)

    if not work.exists():
        git("worktree", "add", "--detach", str(work), target["git"], cwd=src)
    git("checkout", "--detach", "--force", target["git"], cwd=work)
    git("clean", "-fd", "-e", "obj-*", "-e", "mozconfig", cwd=work)
    if run(["git", "apply", "--3way", str(patch)], cwd=work, check=False):
        raise UpdateError(
            "The Profile Lock patch no longer applies to this Nightly; it needs "
            "a manual rebase. Keeping the installed build."
        )

    mozconfig = work / "mozconfig"
    if not mozconfig.exists():
        mozconfig.write_text(
            "ac_add_options --enable-application=browser\n"
            "ac_add_options --enable-optimize\n"
            "ac_add_options --disable-debug\n"
            "ac_add_options --enable-release\n"
            "ac_add_options --disable-tests\n"
        )
    return work


def build_package(work):
    mach(work, "build")
    mach(work, "package")
    packages = sorted(
        work.glob("obj-*/dist/firefox-*.win64.zip"), key=lambda p: p.stat().st_mtime
    )
    if not packages:
        raise UpdateError("mach package produced no zip")
    return packages[-1]


def smoke_test(staging):
    firefox = staging / "firefox" / "firefox.exe"
    with tempfile.TemporaryDirectory() as tmp:
        shot = Path(tmp) / "shot.png"
        profile = Path(tmp) / "profile"
        profile.mkdir()
        subprocess.run(
            [
                firefox,
                "--headless",
                "--no-remote",
                "--profile",
                profile,
                "--screenshot",
                shot,
                "about:blank",
            ],
            check=False,
            timeout=180,
        )
        if not shot.exists():
            raise UpdateError("The new build failed to start (smoke test)")


def stage(package, target, state):
    staging = Path(CONFIG["state_dir"]) / "staged"
    shutil.rmtree(staging, ignore_errors=True)
    with zipfile.ZipFile(package) as z:
        z.extractall(staging)
    smoke_test(staging)
    state["staged"] = target
    save_state(state)


# --- Installing -------------------------------------------------------------


def firefox_running_from(install_dir):
    if os.name != "nt":
        return False
    script = (
        "Get-Process firefox -ErrorAction SilentlyContinue | ForEach-Object { $_.Path }"
    )
    out = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    prefix = str(Path(install_dir).resolve()).lower()
    return any(line.strip().lower().startswith(prefix) for line in out.splitlines())


def backup_protected_profiles():
    """Copy every profile protected by Profile Lock. The copies stay
    encrypted, like the originals."""
    root = Path(CONFIG["profiles_dir"])
    backups = Path(CONFIG["state_dir"]) / "backups"
    dest = backups / datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    count = 0
    for marker in root.glob("**/protection.ini"):
        profile = marker.parent
        shutil.copytree(
            profile,
            dest / profile.name,
            ignore=shutil.ignore_patterns("lock", "parent.lock", ".parentlock"),
        )
        count += 1
    for old in sorted(backups.glob("*"))[: -CONFIG["keep_backups"]]:
        shutil.rmtree(old, ignore_errors=True)
    log(f"Backed up {count} protected profile(s) to {dest}")


def install_staged(state):
    staged = state.get("staged")
    staging = Path(CONFIG["state_dir"]) / "staged" / "firefox"
    if not staged or not staging.exists():
        return False
    install = Path(CONFIG["install_dir"])
    if firefox_running_from(install):
        log("Firefox is running; the new build stays staged until it is closed")
        notify(
            "Profile Lock Firefox update ready",
            "It installs the next time the updater runs with Firefox closed.",
        )
        return False
    backup_protected_profiles()
    previous = install.with_name(install.name + ".previous")
    shutil.rmtree(previous, ignore_errors=True)
    if install.exists():
        install.rename(previous)
    install.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(staging), str(install))
    state.update(
        built_hg=staged["hg"],
        built_git=staged["git"],
        built_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        installed_build_id=staged["build_id"],
        version=staged["version"],
        staged=None,
    )
    save_state(state)
    log(f"Installed Nightly {staged['build_id']} ({staged['git'][:12]}) in {install}")
    notify(
        "Profile Lock Firefox updated",
        f"Now on Nightly {staged['build_id']}. Previous build kept for rollback.",
    )
    return True


# --- Main -------------------------------------------------------------------


def update(force=False, check_only=False):
    state = load_state()
    if install_staged(state):
        return 0

    version = state.get("version") or "162.0a1"
    target = offered_nightly(version, state.get("installed_build_id"))
    log(f"Mozilla is shipping Nightly {target['build_id']} ({target['git'][:12]})")

    security = []
    if state.get("built_hg") and state["built_hg"] != target["hg"]:
        security = security_bugs(bug_ids_between(state["built_hg"], target["hg"]))
    now = datetime.datetime.now(datetime.timezone.utc)
    build, reason = decide(state, target, security, now)
    if force and state.get("built_hg") != target["hg"]:
        build, reason = target, "forced"
    log(("Building: " if build else "Not building: ") + reason)
    if check_only:
        return 0
    save_state(state)
    if not build:
        return 0

    work = prepare_source(build)
    package = build_package(work)
    state["candidate"] = None
    stage(package, build, state)
    install_staged(state)
    return 0


def ensure_tools_on_path():
    """Task Scheduler runs with the plain system PATH; fall back to the git
    that MozillaBuild ships."""
    if shutil.which("git"):
        return
    msys = Path(CONFIG["mozillabuild"]) / "msys2/usr/bin"
    os.environ["PATH"] = str(msys) + os.pathsep + os.environ.get("PATH", "")
    if not shutil.which("git"):
        raise UpdateError("git not found; install Git for Windows or MozillaBuild")


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--force", action="store_true", help="build the offered Nightly even if not due"
    )
    parser.add_argument(
        "--check", action="store_true", help="only report what would happen"
    )
    args = parser.parse_args()

    lock = Path(CONFIG["state_dir"]) / "updater.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        if time.time() - lock.stat().st_mtime < 12 * 3600:
            log("Another update is running; exiting")
            return 0
        lock.unlink()
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    os.close(fd)
    try:
        ensure_tools_on_path()
        return update(force=args.force, check_only=args.check)
    except Exception as e:
        log(f"Update failed, keeping the installed build: {e}")
        notify("Profile Lock Firefox update failed", str(e)[:200])
        return 1
    finally:
        lock.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
