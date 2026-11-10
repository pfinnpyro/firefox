# Profile Lock Firefox auto-updater (Windows)

Keeps a self-built Profile Lock Firefox current with Mozilla's Nightly. It
rebuilds weekly, or sooner for security fixes, and never touches your
profiles.

## What it does

Task Scheduler runs `profilelock_updater.py` once a day. Each run:

1. Installs a build left staged by an earlier run, if Firefox is closed.
2. Asks Mozilla's update server which Nightly it is shipping. A Nightly that
   Mozilla paused over severe problems is never offered, so it is never
   built.
3. Lists the bugs fixed since the installed build and asks Bugzilla which are
   security fixes: hidden bugs (Mozilla hides every security bug until the
   fix ships) and bugs keyed `sec-critical` / `sec-high`.
4. Decides:
   - **Security fixes:** build the offered Nightly now, at most once every
     2 days. Nightly takes security fixes almost daily, so this is usually
     every other day.
   - **Weekly:** once 7 days have passed, pick the offered Nightly as a
     candidate and build it a day later, provided Mozilla has shipped a newer
     Nightly since. A Nightly with severe problems makes Mozilla pause
     updates, and then the candidate is not built.
5. Applies the Profile Lock patch to that Nightly in a separate worktree
   (`C:\ffpl-auto`), builds and packages it. If the patch no longer applies
   or the build fails, it stops and keeps the installed build.
6. Starts the new build headless to check that it runs.
7. If Firefox is running, leaves the new build staged for the next run.
   Otherwise:
   - copies every protected profile (they stay encrypted) to the backups
     folder, keeping the last 2;
   - moves the installed build to `FirefoxProfileLock.previous`;
   - puts the new build in `%LOCALAPPDATA%\FirefoxProfileLock`.
8. Shows a Windows notification, and logs to
   `%LOCALAPPDATA%\FirefoxProfileLock-updater\updater.log`.

## Setup

In the MozillaBuild shell, with this repository cloned and built once:

```
python3 tools/profilelock/autoupdate/profilelock_updater.py --check
```

That only reports what it would do. Then register the daily task and the
Start menu shortcut from PowerShell:

```
powershell -ExecutionPolicy Bypass -File tools\profilelock\autoupdate\register-task.ps1
```

To get the first build without waiting for the soak, run the updater once
with `--force`. It builds the offered Nightly right away (35–60 minutes).

Settings, such as the worktree path, the cadence and the branch carrying the
patch, are in `CONFIG` at the top of `profilelock_updater.py`.

## Rolling back

1. Close Firefox.
2. Rename `%LOCALAPPDATA%\FirefoxProfileLock` to `FirefoxProfileLock.bad`.
3. Rename `FirefoxProfileLock.previous` to `FirefoxProfileLock`.
4. Start it once with `--allow-downgrade`; Firefox otherwise refuses a
   profile last used by a newer build.

If a profile itself was damaged, copy it back from
`%LOCALAPPDATA%\FirefoxProfileLock-updater\backups` over the profile folder.

## Caveats

- You are running Nightly, Mozilla's development build, with Profile Lock on
  top. It gets fixes first, and also new bugs.
- Profile Lock depends on at-rest encryption that is still work in progress
  upstream. A change to its on-disk format could make a new build refuse
  your profile; roll back as above if that happens.
- When upstream changes the code Profile Lock touches, the patch stops
  applying. The updater then keeps the installed build and notifies you; the
  patch branch needs rebasing, after which updates resume.
