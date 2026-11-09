/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { ProfileLock } = ChromeUtils.importESModule(
  "moz-src:///browser/components/profilelock/ProfileLock.sys.mjs"
);

const PREF_ACTIVE = "browser.profileLock.active";
const PREF_MINUTES = "browser.profileLock.autoLockMinutes";
const PREF_OS_LOCK = "browser.profileLock.lockOnOSLock";
const PREF_SLEEP = "browser.profileLock.lockOnSleep";

let gQuits = 0;
let gIdleObservers = new Map();

function fakeIdleService() {
  return {
    addIdleObserver(observer, seconds) {
      gIdleObservers.set(seconds, observer);
    },
    removeIdleObserver(observer, seconds) {
      Assert.equal(gIdleObservers.get(seconds), observer);
      gIdleObservers.delete(seconds);
    },
  };
}

function reset() {
  ProfileLock.uninit();
  ProfileLock._lockPromise = null;
  ProfileLock.lockReason = null;
  gQuits = 0;
}

add_setup(() => {
  ProfileLock._quit = () => gQuits++;
  Object.defineProperty(ProfileLock, "idleService", {
    get: fakeIdleService,
    configurable: true,
  });
  registerCleanupFunction(() => {
    ProfileLock.uninit();
    for (let pref of [PREF_ACTIVE, PREF_MINUTES, PREF_OS_LOCK, PREF_SLEEP]) {
      Services.prefs.clearUserPref(pref);
    }
  });
});

add_task(async function test_inactive_profile_never_locks() {
  reset();
  Services.prefs.setBoolPref(PREF_ACTIVE, false);
  ProfileLock.init();
  Services.obs.notifyObservers(null, "os-session-locked");
  await ProfileLock.lock("user");
  Assert.equal(gQuits, 0, "An unprotected profile is never closed");
  Assert.equal(gIdleObservers.size, 0, "No idle observer is registered");
});

add_task(async function test_lock_now_closes_once() {
  reset();
  Services.prefs.setBoolPref(PREF_ACTIVE, true);
  ProfileLock.init();
  await Promise.all([ProfileLock.lock("user"), ProfileLock.lock("user")]);
  Assert.equal(gQuits, 1, "Concurrent locks close the profile once");
});

add_task(async function test_os_lock_and_sleep() {
  reset();
  Services.prefs.setBoolPref(PREF_ACTIVE, true);
  Services.prefs.setBoolPref(PREF_OS_LOCK, false);
  Services.prefs.setBoolPref(PREF_SLEEP, false);
  ProfileLock.init();

  Services.obs.notifyObservers(null, "os-session-locked");
  Services.obs.notifyObservers(null, "sleep_notification");
  Assert.ok(!ProfileLock.isLocking, "Ignored while turned off");

  Services.prefs.setBoolPref(PREF_OS_LOCK, true);
  Services.obs.notifyObservers(null, "os-session-locked");
  Assert.ok(ProfileLock.isLocking, "Screen lock locks the profile");
  Assert.equal(ProfileLock.lockReason, "os-lock");
  await ProfileLock.lock();
  Assert.equal(gQuits, 1);

  reset();
  Services.prefs.setBoolPref(PREF_SLEEP, true);
  ProfileLock.init();
  Services.obs.notifyObservers(null, "sleep_notification");
  await ProfileLock.lock();
  Assert.equal(gQuits, 1, "Sleep locks the profile");
});

add_task(async function test_idle_timeout() {
  reset();
  Services.prefs.setBoolPref(PREF_ACTIVE, true);
  Services.prefs.setIntPref(PREF_MINUTES, 5);
  ProfileLock.init();
  Assert.deepEqual([...gIdleObservers.keys()], [300], "Observes 5 minutes");

  Services.prefs.setIntPref(PREF_MINUTES, 30);
  Assert.deepEqual([...gIdleObservers.keys()], [1800], "Follows the pref");

  Services.prefs.setIntPref(PREF_MINUTES, 0);
  Assert.equal(gIdleObservers.size, 0, "0 turns auto-lock off");

  Services.prefs.setIntPref(PREF_MINUTES, 15);
  gIdleObservers.get(900).observe(null, "idle", "900");
  await ProfileLock.lock();
  Assert.equal(gQuits, 1, "Going idle locks the profile");

  ProfileLock.uninit();
  Assert.equal(gIdleObservers.size, 0, "uninit removes the idle observer");
});
