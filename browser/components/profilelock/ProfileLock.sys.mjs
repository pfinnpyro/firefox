/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const lazy = {};

ChromeUtils.defineESModuleGetters(lazy, {
  E10SUtils: "resource://gre/modules/E10SUtils.sys.mjs",
  Sanitizer: "resource:///modules/Sanitizer.sys.mjs",
  SessionStore:
    "moz-src:///browser/components/sessionstore/SessionStore.sys.mjs",
  clearTimeout: "resource://gre/modules/Timer.sys.mjs",
  setTimeout: "resource://gre/modules/Timer.sys.mjs",
});

const PREF_ACTIVE = "browser.profileLock.active";
const PREF_AUTO_LOCK_MINUTES = "browser.profileLock.autoLockMinutes";
const PREF_LOCK_ON_OS_LOCK = "browser.profileLock.lockOnOSLock";
const PREF_LOCK_ON_SLEEP = "browser.profileLock.lockOnSleep";
const PREF_CLEAR_ON_LOCK = "browser.profileLock.clearOnLock";

const TOPIC_OS_LOCKED = "os-session-locked";
const TOPIC_SLEEP = "sleep_notification";

// What "empty on lock" removes. Saved passwords, bookmarks and settings are
// kept: they are encrypted at rest and only reachable after an unlock.
const ITEMS_TO_CLEAR = [
  "browsingHistoryAndDownloads",
  "cookiesAndStorage",
  "cache",
  "formdata",
  "sessions",
];

// Locking must not hang on a slow sanitizer: the profile is closed either way.
const CLEAR_TIMEOUT_MS = 15000;

/**
 * Runtime half of Profile Lock (see toolkit/profile/docs/ProfileLock.md).
 * Startup already refused to open the profile without its password; this
 * closes the profile again when the user steps away, so that its decrypted
 * state does not outlive an unattended session.
 *
 * "Locking" is closing the browser: only a fresh start, which goes through the
 * profile picker and password prompt, can reopen the profile. Every key and
 * all decrypted data held by the process go away with it.
 */
export const ProfileLock = {
  _initialized: false,
  _idleSeconds: 0,
  _lockPromise: null,
  // What triggered the lock in progress, if any.
  lockReason: null,

  /**
   * The quit entry point. Tests replace it so they do not shut down.
   */
  _quit() {
    Services.startup.quit(Ci.nsIAppStartup.eForceQuit);
  },

  get idleService() {
    return Cc["@mozilla.org/widget/useridleservice;1"].getService(
      Ci.nsIUserIdleService
    );
  },

  get isActive() {
    return Services.prefs.getBoolPref(PREF_ACTIVE, false);
  },

  get isLocking() {
    return !!this._lockPromise;
  },

  init() {
    if (this._initialized || !this.isActive) {
      return;
    }
    this._initialized = true;

    Services.obs.addObserver(this, TOPIC_OS_LOCKED);
    Services.obs.addObserver(this, TOPIC_SLEEP);
    Services.prefs.addObserver(PREF_AUTO_LOCK_MINUTES, this);
    this._updateIdleObserver();
  },

  uninit() {
    if (!this._initialized) {
      return;
    }
    this._initialized = false;

    Services.obs.removeObserver(this, TOPIC_OS_LOCKED);
    Services.obs.removeObserver(this, TOPIC_SLEEP);
    Services.prefs.removeObserver(PREF_AUTO_LOCK_MINUTES, this);
    this._removeIdleObserver();
  },

  /**
   * Called for every new browser window, from the
   * browser-window-delayed-startup category.
   *
   * @param {Window} win
   */
  onWindowDelayedStartup(win) {
    if (!this.isActive) {
      return;
    }
    win.document.getElementById("cmd_lockProfile")?.removeAttribute("disabled");
    let menuitem = win.document.getElementById("menu_FileLockProfile");
    if (menuitem) {
      menuitem.hidden = false;
    }
  },

  _removeIdleObserver() {
    if (this._idleSeconds) {
      this.idleService.removeIdleObserver(this, this._idleSeconds);
      this._idleSeconds = 0;
    }
  },

  _updateIdleObserver() {
    this._removeIdleObserver();
    let minutes = Services.prefs.getIntPref(PREF_AUTO_LOCK_MINUTES, 0);
    if (minutes > 0) {
      this._idleSeconds = minutes * 60;
      this.idleService.addIdleObserver(this, this._idleSeconds);
    }
  },

  observe(subject, topic, data) {
    switch (topic) {
      case "idle":
        this.lock("idle");
        break;
      case TOPIC_OS_LOCKED:
        if (Services.prefs.getBoolPref(PREF_LOCK_ON_OS_LOCK, true)) {
          this.lock("os-lock");
        }
        break;
      case TOPIC_SLEEP:
        if (Services.prefs.getBoolPref(PREF_LOCK_ON_SLEEP, true)) {
          this.lock("sleep");
        }
        break;
      case "nsPref:changed":
        if (data == PREF_AUTO_LOCK_MINUTES) {
          this._updateIdleObserver();
        }
        break;
    }
  },

  /**
   * Close the profile now, first emptying it if the user asked for that.
   *
   * @param {string} reason
   *   What triggered the lock: "user", "idle", "os-lock" or "sleep".
   * @returns {Promise<void>}
   *   Resolves once shutdown has been requested.
   */
  lock(reason = "user") {
    if (!this.isActive) {
      return Promise.resolve();
    }
    if (!this._lockPromise) {
      this.lockReason = reason;
      this._lockPromise = this._lock();
    }
    return this._lockPromise;
  },

  async _lock() {
    if (Services.prefs.getBoolPref(PREF_CLEAR_ON_LOCK, false)) {
      try {
        await this._withTimeout(this._empty(), CLEAR_TIMEOUT_MS);
      } catch (e) {
        console.error("Profile Lock: failed to empty the profile", e);
      }
    }
    this._quit();
  },

  async _empty() {
    // Replace every open window with a single blank tab so that the session
    // written on the way out holds nothing to restore.
    lazy.SessionStore.setBrowserState(
      JSON.stringify({
        windows: [
          {
            tabs: [
              {
                entries: [
                  {
                    url: "about:blank",
                    triggeringPrincipal_base64:
                      lazy.E10SUtils.SERIALIZED_SYSTEMPRINCIPAL,
                  },
                ],
              },
            ],
          },
        ],
      })
    );
    await lazy.Sanitizer.sanitize(ITEMS_TO_CLEAR, { ignoreTimespan: true });
  },

  _withTimeout(promise, ms) {
    let timer;
    let timeout = new Promise((_, reject) => {
      timer = lazy.setTimeout(() => reject(new Error("Timed out")), ms);
    });
    return Promise.race([promise, timeout]).finally(() =>
      lazy.clearTimeout(timer)
    );
  },

  QueryInterface: ChromeUtils.generateQI(["nsIObserver"]),
};
