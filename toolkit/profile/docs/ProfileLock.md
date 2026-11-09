# Profile Lock

Profile Lock turns a profile into a vault. A protected profile:

1. keeps everything it stores encrypted at rest, under keys that only its
   password can unwrap;
2. cannot be opened without explicitly choosing it at startup and entering
   that password. While any profile is protected, the profile manager is shown
   at every startup that doesn't name a profile, so with a single protected
   profile the browser is unusable until it is unlocked;
3. closes itself (locks) after a configurable idle time, when the OS screen is
   locked and when the computer sleeps, optionally emptying the profile first;
4. can be restricted to private browsing only.

The design assumes the browser runs on a computer that other people can use
or reach, and that the profile handles data that must not leak to them. Each
profile is treated as an untrusted environment until its owner proves
otherwise, again at every start ("zero trust" towards the local machine
state).

```{contents}
:local:
```

## Threat model

### Protected against

- **Someone reading the disk** while the browser is closed or locked: a
  colleague browsing the user's home directory, a copied backup, a stolen
  laptop without full-disk encryption, a repaired or recycled disk. Every
  store listed as covered in [the data inventory](#data-inventory) is
  ciphertext, and its keys are wrapped by a key derived from the password.
- **Someone at the keyboard of an unattended session.** The profile closes
  itself on idle, screen lock and sleep. Reopening it requires the profile
  password, even if the OS session is unlocked.
- **Someone starting the browser.** The browser does not open any protected
  profile on its own: the user must choose the profile and then unlock it.
  Command line options that skip the profile manager (`-P`, `--profile`) still
  require the password.
- **Offline guessing of the password**, up to the cost of 600,000 rounds of
  PBKDF2-HMAC-SHA256 per guess, for both the lockstore key and the NSS
  primary password.

### Not protected against

These are out of reach for any application and must be handled by the OS or
by policy:

- Code running as the same OS user while the profile is unlocked (malware, a
  keylogger, a debugger attached to the process, a modified Firefox binary or
  `user.js`). Anyone who can write to the user's files can capture the
  password the next time it is typed.
- Memory of the running process, which holds decrypted data and keys while
  unlocked, and the copies the OS may make of it: swap, hibernation files,
  crash dumps. Use encrypted swap and full-disk encryption.
- Data that leaves the profile on purpose: downloaded files, files opened
  with external applications, printed documents, the clipboard, screenshots,
  data sent to websites, and Sync.
- Denial of service: anyone who can write the profile can destroy it.
  Protection is about confidentiality, not availability. Keep backups.

## Building blocks that already exist

Profile Lock is a coordinator. It ties together several at-rest encryption
efforts that already exist in the tree, each of them off by default:

| Component | Source | What it does |
| --- | --- | --- |
| lockstore | `security/lockstore` | Key store (`lockstore.keys.sqlite`). Data encryption keys (DEKs) are wrapped by key encryption keys (KEKs) of three kinds: `local` (no secret), `password` (PBKDF2, 600,000 rounds) and `pkcs11` (token-backed). |
| Profile KEK | `security/lockstore/ProfileKek.cpp` | Startup step, run just before `profile-do-change`, that unlocks the `password:profile` KEK with the primary password, or aborts startup. |
| obfsvfs | `storage/ObfuscatingVFS.cpp`, `storage/SQLiteEncryption.cpp` | Page-level ChaCha20-Poly1305 encryption of SQLite databases (`security.storage.encryption.sqlite.enabled`). |
| QuotaManager encryption | `dom/quota` | Encrypts IndexedDB, Cache API, LocalStorage and other origin storage (`dom.quotaManager.encryption.enabled`). |
| Cache encryption | `netwerk/cache2/CacheCrypto.cpp` | Encrypts the HTTP cache (`browser.cache.disk.encryption.enabled`). |
| IOUtils encryption | `xpcom/ioutils` | `encrypt` / `decrypt` read and write options, used by session store (`browser.sessionstore.encryption.enabled`). |
| Primary password | NSS `key4.db` | Protects saved logins and private keys. |

Taken separately, these leave a gap: every consumer wrapped its DEKs under its
own `local` KEK (`local:sqlite`, `local:sessionstore`, a random one for
QuotaManager), and a local KEK sits unprotected next to the data it protects.
They also all switch on build-wide, through a pref read before the profile's
own prefs. Profile Lock closes both gaps.

## Architecture

```
            profiles.ini                <profile>/protection.ini
   [ProfileN] RequiresUnlock=1        [Protection] Enabled=1, PrivateOnly=0|1
              │                                     │
              ▼                                     ▼
 ┌─────────────────────────────┐   ┌──────────────────────────────────────┐
 │ 1. Profile selection        │──▶│ 2. ProfileProtection (toolkit/xre)   │
 │    forced profile manager   │   │    per-profile encryption gate,      │
 │    (nsAppRunner)            │   │    forced locked prefs               │
 └─────────────────────────────┘   └──────────────────┬───────────────────┘
                                                       ▼
                         ┌───────────────────────────────────────────────┐
                         │ 3. ProfileKek (security/lockstore)            │
                         │    set up / unlock the password KEK, fail     │
                         │    closed, move every DEK under it            │
                         └──────────────────┬────────────────────────────┘
                                            ▼  profile-do-change
       ┌──────────────┬──────────────┬──────┴───────┬───────────────────┐
       ▼              ▼              ▼              ▼                   ▼
   SQLite DBs    QuotaManager    HTTP cache    session store      logins / keys
   (obfsvfs)     origins         (cache2)      (IOUtils)          (key4.db)
       └──────────────┴──────────────┴──────────────┘
            DEKs wrapped under lockstore::kek::password:profile
                                            │
                                            ▼
                         ┌───────────────────────────────────────────────┐
                         │ 4. ProfileLock.sys.mjs (browser)              │
                         │    idle / screen lock / sleep / "Lock now"    │
                         │    → optional empty → force quit              │
                         └───────────────────────────────────────────────┘
```

### Key hierarchy

```
password ──PBKDF2-HMAC-SHA256 (600k, per-KEK salt)──▶ wrapping key
                                                         │ AES-256-GCM
                                                         ▼
                              KEK  lockstore::kek::password:profile
                                                         │ AES-256-GCM
                ┌───────────────┬───────────────┬────────┴──────┬───────────┐
                ▼               ▼               ▼               ▼           ▼
          DEK per SQLite   DEK per origin   cache DEK    session store   (future
          database         and client                    DEKs            consumers)

password ──PBKDF2 (600k for passwords set under Profile Lock)──▶ key4.db
                                                                 (logins, certs' keys)
```

The same secret is both the lockstore password and the NSS primary password,
so the user has one password per profile and the existing primary password
UI keeps working. NSS is the authority on whether a password is right: the
unlock prompt checks it against the token before it touches lockstore.

Rotating the password re-wraps the KEK (`changeKekPassword`); no data is
re-encrypted. Removing the password is refused while the profile is
protected, because it would move every DEK back to a local KEK.

### Configuration and where it lives

| Setting | Where | Why there |
| --- | --- | --- |
| Profile is protected | `<profile>/protection.ini` `Enabled` | Needed before any profile data is read, and travels with the profile. Plaintext on purpose: it can only switch protections on. A file that exists but cannot be parsed counts as protected. |
| Private browsing only | `<profile>/protection.ini` `PrivateOnly` | Must be applied before the first window opens. |
| Force the profile manager | `profiles.ini` `RequiresUnlock` | Must be known before a profile is chosen. Only a hint: removing it skips the picker but not the password prompt. |
| Auto-lock delay, lock on screen lock, lock on sleep, empty on lock | prefs `browser.profileLock.*` | Only used after unlock. Lockable by enterprise policy. |

Tampering with any of these requires write access to the user's files, which
is out of scope (see the threat model). The worst outcome of editing them
without the password is a profile that refuses to open, or one that skips a
lock trigger the next time it is unlocked by its owner.

## Startup sequence

1. **Profile selection** (`XREMain::XRE_mainStartup`). If the startup was not
   given a profile explicitly (command line or environment) and any profile
   has `RequiresUnlock=1`, or the default profile's `protection.ini` enables
   protection, the profile manager is shown, whatever "use the selected
   profile without asking" says. Profile reset is refused for a protected
   profile: it would copy data into an unprotected one.
2. **Encryption gate.** `ReadProfileProtection` reads the chosen profile's
   `protection.ini`. A protected profile counts as encryption-on for the
   existing check that refuses to open plaintext databases with encryption on,
   or the reverse. So a profile that already holds plaintext data cannot be
   turned into a protected one by writing the file. It is refused with the
   "migration required" message rather than corrupted.
3. **Forced prefs** (`ApplyProfileProtectionPrefs`, start of
   `nsXREDirProvider::DoStartup`). After the default and user prefs are loaded
   and before `profile-do-change`, every encryption pref is forced on as a
   locked default: SQLite, QuotaManager, HTTP cache, session store and the
   lockstore unlock link. Page thumbnails and automatic crash report
   submission are forced off. `browser.privatebrowsing.autostart` is forced on
   for private-only profiles. `NSS_MIN_MP_PBE_ITERATION_COUNT` is raised to
   600,000.
4. **Unlock** (`SyncProfileKekAtStartup`). For a protected profile nothing is
   skippable. Cancelling, or failing to reach the key store, quits.
   - No password anywhere (a new protected profile): ask for a new password
     twice, set it as the primary password, create the password KEK.
   - A primary password but no KEK: ask for it, create the KEK from it, and
     re-encode the primary password with the raised iteration count.
   - A password KEK: ask for the password until it is right, with an
     increasing delay after the third wrong attempt.
5. **Sweep.** Every DEK still wrapped by any `local:*` KEK is switched to the
   password KEK, and the emptied local KEKs are deleted. This covers DEKs
   minted before the password existed and any a consumer created under a local
   KEK. A failure is retried at the next startup.
6. `profile-do-change`. Consumers start opening stores. Each of them now asks
   `LockstoreService::DoResolveWrappingKek` (SQLite reads the key store
   directly, with the same logic), which returns the password KEK whenever it
   exists, so new DEKs are never created under a local KEK.

## Locking

Locking a profile means quitting the browser. Keys are cached in the key
store and inside every open database connection, and decrypted data sits in
caches all over the process. Only process exit guarantees that all of it is
gone. Reopening goes through the profile manager and password prompt again.

`ProfileLock.sys.mjs` (`browser/components/profilelock`) triggers a lock on:

| Trigger | Signal | Default |
| --- | --- | --- |
| No input for N minutes | `nsIUserIdleService` idle observer | 15 minutes (`browser.profileLock.autoLockMinutes`, 0 = off) |
| OS screen lock | `os-session-locked` observer topic | on (`browser.profileLock.lockOnOSLock`) |
| Sleep | `sleep_notification` | on (`browser.profileLock.lockOnSleep`) |
| User | File ▸ Lock Profile, Ctrl/Cmd+Shift+L, or the Lock now button in settings | always available |

The `os-session-locked` / `os-session-unlocked` topics are new and come from:

- Windows: `WM_WTSSESSION_CHANGE` (`WTS_SESSION_LOCK`) for the current
  session, in `widget/windows/WinEventObserver.cpp`.
- Linux: logind `org.freedesktop.login1.Session` `Lock` / `Unlock` on the
  process's own session, plus `ActiveChanged` from `org.freedesktop.ScreenSaver`
  and `org.gnome.ScreenSaver` on the session bus, in `widget/gtk/nsAppShell.cpp`.
  Screen savers also report blanking without a lock, which also locks the
  profile; erring on that side is intended.
- macOS: the `com.apple.screenIsLocked` / `com.apple.screenIsUnlocked`
  distributed notifications, in `widget/cocoa/nsToolkit.mm`.

With **Empty the profile when locking** (`browser.profileLock.clearOnLock`),
the session is first replaced by a single blank tab and the Sanitizer clears
browsing and download history, cookies and site data, the cache, form data and
active logins. Saved passwords, bookmarks and settings are kept: they stay
encrypted and only an unlock reaches them. Emptying is bounded to 15 seconds
so a lock cannot hang. Shutdown is a forced quit: pages cannot delay it with
`beforeunload`.

## Private browsing only

`PrivateOnly=1` forces `browser.privatebrowsing.autostart` (permanent private
browsing) on as a locked pref for that profile. Private browsing keeps
history, cookies and site data in memory. Combined with Profile Lock, what
remains on disk is the profile's settings, bookmarks, saved passwords and
extensions, all of which are encrypted where covered below. The setting is in
the new-profile wizard and in Settings ▸ General ▸ Profile Lock. A change takes
effect the next time the profile opens.

## Data inventory

What a protected profile stores, and whether it is encrypted. "Covered" means
the store is encrypted by one of the mechanisms above with its DEK under the
password KEK. Several of these mechanisms are upstream work in progress and
are behind prefs that are marked internal. Profile Lock only switches them on.

| Store | Location | Status |
| --- | --- | --- |
| History, bookmarks (`places.sqlite`), favicons, cookies, permissions, form history, content prefs, `storage.sqlite`, other mozStorage SQLite DBs | profile | Covered (obfsvfs) |
| IndexedDB, Cache API, LocalStorage, OPFS and other origin storage | `storage/` | Covered for origins created while protected (QuotaManager) |
| HTTP cache | local profile dir (`cache2/`) | Covered (CacheCrypto) |
| Session restore (`sessionstore.jsonlz4`, `sessionstore-backups/`) | profile | Covered (IOUtils encryption) |
| Saved logins (`logins.json`) | profile | Covered: encrypted with a key in `key4.db`, under the primary password |
| Private keys, login encryption key (`key4.db`) | profile | Covered by the primary password, not by obfsvfs |
| Certificates and trust (`cert9.db`) | profile | Not encrypted (low sensitivity; reveals installed client certificates and roots) |
| Key store (`lockstore.keys.sqlite`) | profile | Holds only wrapped keys; plaintext metadata (DEK names reveal database file names and origins) |
| Page thumbnails | local profile dir | Disabled for protected profiles |
| Prefs (`prefs.js`, `user.js`), `xulstore.json`, `containers.json`, `handlers.json`, `search.json.mozlz4`, `times.json`, `compatibility.ini` | profile | **Not encrypted.** Read before unlock; may reveal settings, search engines, container names, the last download folder |
| HSTS and other site security state (`SiteSecurityServiceState.bin`) | profile | **Not encrypted.** Reveals HTTPS sites visited that sent HSTS |
| Extensions (`extensions/`, `extensions.json`, `addonStartup.json.lz4`) and their `browser.storage.local` | profile | Code and manifests not encrypted; extension storage is IndexedDB (covered) |
| Startup cache, shader cache | local profile dir | Not encrypted (code and GPU shaders, no browsing data) |
| Telemetry archive and pending pings | profile (`datareporting/`, `saved-telemetry-pings/`) | **Not encrypted.** Disable data collection by policy |
| Crash reports and minidumps | profile (`minidumps/`), `Crash Reports/` | **Not encrypted, contain process memory.** Auto-submission forced off; disable the crash reporter by policy for strict use |
| Downloads | user's download folder | Out of scope (leaves the profile by design) |
| Files opened with other applications, PDFs and media written to temp | OS temp dir | Out of scope; clear the OS temp directory regularly |

## Failure handling

The rule is: when Profile Lock cannot tell whether a store is protected, it
refuses to run rather than run unprotected.

| Situation | Behaviour |
| --- | --- |
| `protection.ini` present but unreadable | Treated as protected |
| Password prompt cancelled, headless start, no prompt service | Quit |
| Key store unreachable | Quit |
| Something tries to create encrypted data before the password KEK exists (for example quit observers running while startup refuses the profile) | Refused: no DEK is ever created under a LocalKey in a protected profile |
| Encrypted profile opened by a build or a session with encryption off | Refused by the existing encryption gate |
| Protected profile already holding plaintext databases | Refused ("migration required") |
| Sweep of local KEKs fails | Startup continues, data stays readable, retried at next startup |
| Removing or resetting the primary password | Refused in the UI and in `ProfileKekPassword` |
| Forgotten password | Data is unrecoverable by design; delete the profile |

## Using it

1. Open the profile manager (`firefox -P`), choose **Create Profile…**, check
   **Protect this profile with a password** and optionally **Only allow
   private browsing in this profile**.
2. Start the new profile. Choose its password when asked.
3. Bring data over from an old profile by exporting bookmarks (HTML) and
   logins (CSV) and importing them in the protected profile. Copying files is
   refused by the encryption gate, and Firefox Backup is disabled while
   encryption is on.
4. Delete the old, unprotected profile, including its files.
5. Recommended alongside: OS full-disk encryption, encrypted swap, a screen
   lock on the OS session, telemetry and the crash reporter disabled by
   enterprise policy (`DisableTelemetry`, `DisableCrashReporter`), and the
   `browser.profileLock.*` prefs locked through the `Preferences` policy.

## Roadmap

Profile Lock as built here is a first phase. Further work, roughly in order
of value:

1. **Migrate existing profiles in place.** Re-encrypt plaintext SQLite
   databases through mozStorage's online backup API into obfsvfs connections,
   re-encrypt QuotaManager origins and the session store, then write
   `protection.ini`. This needs an exclusive, restartable migration step at
   startup.
2. **Encrypt the remaining plaintext stores.** Split prefs into a minimal
   pre-unlock file and an encrypted one loaded after unlock. Move JSON stores
   (`xulstore.json`, `containers.json`, `handlers.json`, search settings) to
   IOUtils encryption. Make site security state in-memory or encrypted for
   protected profiles. Keep telemetry and crash data out of protected
   profiles.
3. **Lock without quitting.** Close every encrypted store, drop cached keys
   (`nsILockstore.lock()`), discard content processes and show an unlock
   screen, instead of exiting. This needs every consumer to support closing
   and reopening its store at runtime.
4. **Stronger KDF and hardware keys.** Argon2id for password KEKs. Offer an OS
   or hardware-backed KEK (Windows Hello / TPM, macOS Keychain / Secure
   Enclave, PKCS#11 smart cards, already supported by lockstore) as a second
   factor next to the password.
5. **Profile manager integration.** Unlock in the profile manager itself
   instead of a prompt after it, show lock state in the new profile selector
   (`about:profilemanager`) for selectable profiles, and an enterprise policy
   that requires every profile to be protected.
6. **Telemetry-free audit trail.** Record unlock failures and lock events in
   the encrypted profile for the owner to review.

## Testing

- `security/lockstore/gtest/TestProfileKek.cpp`: startup decisions, including
  the `Setup` path and the rule that nothing can be skipped for a protected
  profile.
- `toolkit/profile/test/xpcshell/test_requires_unlock.js`: `RequiresUnlock`
  round-trips through `profiles.ini`, including section renumbering.
- `browser/components/profilelock/test/unit/`: lock triggers (idle, screen
  lock, sleep, prefs) and the `protection.ini` reader and writer.
- End to end, under Xvfb on Linux: a new protected profile asks for a new
  password twice, opens, and Ctrl+Shift+L closes it. Afterwards every DEK in
  the key store is wrapped only by `password:profile`, every SQLite database
  (places, cookies, favicons, IndexedDB…) is in the obfsvfs format with no
  plaintext schema, and `sessionstore.jsonlz4` starts with the `mozEnc0`
  marker. The next start rejects a wrong password and opens with the right
  one. A headless start of a protected profile quits without creating any
  database or key.
- Manual: create a protected profile, set a password, confirm that the data
  files under the profile are ciphertext (no SQLite header magic), that
  startup asks for the profile and the password every time, and that each
  trigger closes the browser.
