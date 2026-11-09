/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/security/lockstore/ProfileKek.h"

#include <algorithm>

#include "LockstoreService.h"
#include "ScopedNSSTypes.h"
#include "mozilla/Components.h"
#include "mozilla/Preferences.h"
#include "mozilla/ProfileProtection.h"
#include "mozilla/RefPtr.h"
#include "mozilla/StaticPrefs_security.h"
#include "nsCOMPtr.h"
#include "nsComponentManagerUtils.h"
#include "nsEmbedCID.h"
#include "nsIPKCS11Token.h"
#include "nsIPromptService.h"
#include "nsISecretDecoderRing.h"
#include "nsIStringBundle.h"
#include "nsServiceManagerUtils.h"
#include "nsString.h"
#include "nsTArray.h"
#include "nsThreadUtils.h"
#include "pk11pub.h"
#include "prenv.h"
#include "prinrval.h"
#include "prthread.h"

#ifdef XP_MACOSX
#  include "MacApplicationDelegate.h"
#endif

namespace mozilla::security::lockstore {

Maybe<PrimaryPasswordSync> ChoosePrimaryPasswordSync(
    bool aKekExists, bool aKekUnlocked, FunctionRef<bool()> aTokenHasPassword,
    bool aPasswordRequired) {
  if (aKekExists) {
    // If the KEK exists and is already unlocked, another component is managing
    // it. This happens in enterprise, where the profile KEK is secured by the
    // felt secret.
    if (aKekUnlocked) {
      return Nothing();
    }
    return Some(PrimaryPasswordSync::Unlock);
  }
  // No password KEK yet: only a primary password the user has already set
  // gives us anything to adopt.
  if (aTokenHasPassword()) {
    return Some(PrimaryPasswordSync::Adopt);
  }
  if (aPasswordRequired) {
    return Some(PrimaryPasswordSync::Setup);
  }
  return Nothing();
}

bool SyncIsSkippable(PrimaryPasswordSync aSync, bool aPasswordRequired) {
  return !aPasswordRequired && aSync == PrimaryPasswordSync::Adopt;
}

bool IsLocalKekRef(const nsACString& aKekRef) {
  return StringBeginsWith(aKekRef, "lockstore::kek::local:"_ns);
}

// The KEK has to stay unlocked for the rest of the session. lockstore clamps
// the window to its own maximum, so ask for everything.
constexpr uint64_t kCacheForSession = UINT64_MAX;

// The lockstore helpers here reach the FFI, which is synchronous and hits
// SQLite, so callers dispatch them to a background queue.

static bool KekExists(LockstoreService* aLockstore, const nsACString& aKekRef) {
  auto exists = aLockstore->DoKekExists(aKekRef);
  return exists.isOk() && exists.unwrap();
}

// Requires the password KEK to be unlocked.
static nsresult MoveProfileDeksToLocalKey(LockstoreService* aLockstore) {
  auto created = aLockstore->DoCreateKek("local"_ns, kProfileKekId, ""_ns,
                                         /* cache_timeout_ms */ 0);
  if (created.isErr()) {
    return created.unwrapErr();
  }
  nsresult rv =
      aLockstore->DoMigrateDeks(kProfilePasswordKek, created.unwrap());
  NS_ENSURE_SUCCESS(rv, rv);
  // The migrated-from KEK now wraps nothing, but its record alone is what
  // later startups read as "the profile uses a password KEK", so drop it.
  return aLockstore->DoDeleteKek(kProfilePasswordKek);
}

// Profile Lock: re-wrap every DEK still under a LocalKey -- whichever
// consumer minted it -- under the password KEK, then drop the LocalKeys. A
// LocalKey unwraps without a secret, so a DEK left under one would be readable
// by anyone who can read the profile. Requires the password KEK to be unlocked.
// Best effort per DEK: whatever fails stays readable this session and is
// retried at the next startup.
static nsresult WrapAllDeksUnderPasswordKek(LockstoreService* aLockstore) {
  auto deks = aLockstore->DoListDeks();
  if (deks.isErr()) {
    return deks.unwrapErr();
  }

  nsresult result = NS_OK;
  nsTArray<nsCString> localKeks;
  for (const nsCString& dek : deks.inspect()) {
    auto keks = aLockstore->DoListKeks(dek);
    if (keks.isErr()) {
      result = keks.unwrapErr();
      continue;
    }
    bool underPassword = keks.inspect().Contains(kProfilePasswordKek);
    for (const nsCString& kek : keks.inspect()) {
      if (!IsLocalKekRef(kek)) {
        continue;
      }
      if (!localKeks.Contains(kek)) {
        localKeks.AppendElement(kek);
      }
      nsresult rv = underPassword ? aLockstore->DoRemoveKek(dek, kek)
                                  : aLockstore->DoSwitchKek(
                                        dek, kek, kProfilePasswordKek);
      if (NS_FAILED(rv)) {
        result = rv;
        continue;
      }
      underPassword = true;
    }
  }

  // Refused while a DEK still wraps under the KEK, which only happens when the
  // loop above failed for it.
  for (const nsCString& kek : localKeks) {
    (void)aLockstore->DoDeleteKek(kek);
  }
  return result;
}

// Set aPassword as the internal key token's primary password, which must not
// have one yet. Off the main thread: NSS runs the password-based KDF.
static nsresult SetInitialPrimaryPassword(const nsACString& aPassword) {
  UniquePK11SlotInfo slot(PK11_GetInternalKeySlot());
  if (!slot) {
    return NS_ERROR_FAILURE;
  }
  const nsPromiseFlatCString& password = PromiseFlatCString(aPassword);
  SECStatus srv = PK11_NeedUserInit(slot.get())
                      ? PK11_InitPin(slot.get(), "", password.get())
                      : PK11_ChangePW(slot.get(), "", password.get());
  return srv == SECSuccess ? NS_OK : NS_ERROR_FAILURE;
}

// Re-encode a primary password that was set before Profile Lock, so that NSS
// stretches it with the iteration count ApplyProfileProtectionPrefs raised.
// Best effort: the old encoding still works, it is only cheaper to attack.
static void StrengthenPrimaryPassword(const nsACString& aPassword) {
  UniquePK11SlotInfo slot(PK11_GetInternalKeySlot());
  if (!slot) {
    return;
  }
  const nsPromiseFlatCString& password = PromiseFlatCString(aPassword);
  if (PK11_ChangePW(slot.get(), password.get(), password.get()) != SECSuccess) {
    NS_WARNING("Failed to re-encode the primary password");
  }
}

// Slow down repeated wrong guesses at the unlock prompt. Offline guessing is
// bounded by the KDF instead; this only blunts someone at the keyboard.
static void BackOffAfterFailure(uint32_t aFailures) {
  constexpr uint32_t kFreeAttempts = 3;
  constexpr uint32_t kMaxDelaySeconds = 30;
  if (aFailures < kFreeAttempts) {
    return;
  }
  uint32_t delay = std::min<uint32_t>(
      1u << std::min<uint32_t>(aFailures - kFreeAttempts, 5u),
      kMaxDelaySeconds);
  PR_Sleep(PR_SecondsToInterval(delay));
}

// Move the profile DEKs off the password KEK once the link is
// disabled, while that KEK is still unlocked. Nothing re-unlocks it once the
// link is off, so DEKs left under it stop being readable for the rest of the
// session, which breaks every consumer of an encrypted database.
// Best-effort: this runs on a background task shutdown can outrun, and the
// migration itself can fail. Whatever is left behind stays under the password
// KEK until the link is enabled again, when the startup sync unlocks it.
static void OnLockstoreUnlockPrefChanged(const char* /* aPref */,
                                         void* /* aData */) {
  // Read the pref rather than its StaticPrefs mirror, whose own callback is
  // not ordered against this one.
  if (Preferences::GetBool("security.lockstore.unlock.enabled", false)) {
    return;
  }
  RefPtr<LockstoreService> lockstore = LockstoreService::GetSingleton();
  if (!lockstore) {
    return;
  }
  NS_DispatchBackgroundTask(
      NS_NewRunnableFunction(
          "LockstoreMigrateToLocal",
          [lockstore] {
            if (KekExists(lockstore, kProfilePasswordKek) &&
                NS_FAILED(MoveProfileDeksToLocalKey(lockstore))) {
              NS_WARNING("Failed to migrate the profile DEKs to a LocalKey");
            }
          }),
      NS_DISPATCH_EVENT_MAY_BLOCK);
}

// Create the password KEK from a primary password the token has just accepted,
// and move over every DEK minted under the LocalKey before it existed.
static nsresult AdoptPrimaryPassword(LockstoreService* aLockstore,
                                     const nsACString& aSecret) {
  auto created = aLockstore->DoCreateKek("password"_ns, kProfileKekId, aSecret,
                                         kCacheForSession);
  if (created.isErr()) {
    return created.unwrapErr();
  }
  if (!KekExists(aLockstore, kProfileLocalKek)) {
    return NS_OK;
  }
  // The LocalKey unlocks without a secret, so a DEK left under it stays
  // readable without the primary password.
  nsresult rv =
      aLockstore->DoMigrateDeks(kProfileLocalKek, kProfilePasswordKek);
  if (NS_SUCCEEDED(rv)) {
    return aLockstore->DoDeleteKek(kProfileLocalKek);
  }
  // A password KEK wrapping nothing protects nothing; drop it so the next
  // startup retries the adoption.
  (void)aLockstore->DoDeleteKek(kProfilePasswordKek);
  return rv;
}

static nsString GetString(nsIStringBundle* aBundle, const char* aName) {
  nsString result;
  if (aBundle) {
    (void)aBundle->GetStringFromName(aName, result);
  }
  return result;
}

// Prompt for a password, returning false if the user cancelled. aError, when
// not empty, is shown above aText to explain why we are asking again.
static bool PromptForPassword(nsIPromptService* aPs, const nsString& aTitle,
                              const nsString& aText, const nsAString& aError,
                              nsACString& aOut) {
  nsAutoString text;
  if (!aError.IsEmpty()) {
    text.Append(aError);
    text.AppendLiteral("\n\n");
  }
  text.Append(aText);

  char16_t* rawPassword = nullptr;
  bool ok = false;
  aPs->PromptPassword(nullptr, aTitle.IsEmpty() ? nullptr : aTitle.get(),
                      text.get(), &rawPassword, &ok);
  nsString password;
  password.Adopt(rawPassword);
  if (!ok) {
    return false;
  }
  CopyUTF16toUTF8(password, aOut);
  return true;
}

// Synchronise the lockstore profile KEK with the primary password: unlock it,
// or adopt a primary password it does not know about yet. For a profile
// protected by Profile Lock, also create the password when there is none, and
// gather every DEK under it. Returns false when startup cannot continue, which
// covers every state this cannot rule out: an unreachable keystore answers
// nothing about the profile's DEKs.
static bool SyncLockstoreWithPrimaryPassword() {
  // Profile Lock forces security.lockstore.unlock.enabled on, but check both
  // so that a protected profile fails closed whatever happened to the pref.
  const bool passwordRequired = mozilla::GetStartupProfileProtection().mEnabled;

  // Without the link there is nothing to sync, and the keystore must not be
  // touched: opening it creates it in every profile, and the profile KEK may
  // belong to a component other than the primary password.
  if (!StaticPrefs::security_lockstore_unlock_enabled() && !passwordRequired) {
    return true;
  }

  // LockstoreService::Init ensures NSS itself, so a singleton means NSS is up.
  RefPtr<LockstoreService> lockstore = LockstoreService::GetSingleton();
  nsCOMPtr<nsISerialEventTarget> unlockQueue;
  if (!lockstore || NS_FAILED(NS_CreateBackgroundTaskQueue(
                        "LockstoreUnlock", getter_AddRefs(unlockQueue)))) {
    // Out of reach of the keystore, whether this profile keeps its DEKs under
    // a password KEK cannot be answered, and carrying on regardless hands the
    // session to consumers whose databases may be unreadable.
    NS_WARNING("No lockstore to sync the profile KEK with");
    return false;
  }

  // Once the password KEK is unlocked, a protected profile must not keep any
  // DEK under a LocalKey. Failing that is not fatal: the DEKs stay readable,
  // and the next startup tries again.
  auto finish = [&]() {
    if (!passwordRequired) {
      return true;
    }
    nsresult sweepRv = NS_OK;
    nsresult dispatchRv = NS_DispatchAndSpinEventLoopUntilComplete(
        "LockstoreUnlock"_ns, unlockQueue,
        NS_NewRunnableFunction("LockstoreSweepLocalKeks", [&] {
          sweepRv = WrapAllDeksUnderPasswordKek(lockstore);
        }));
    if (NS_FAILED(dispatchRv) || NS_FAILED(sweepRv)) {
      NS_WARNING("Failed to wrap every DEK under the profile password KEK");
    }
    return true;
  };

  bool kekExists = false;
  bool kekUnlocked = false;

  nsresult dispatchRv = NS_DispatchAndSpinEventLoopUntilComplete(
      "LockstoreUnlock"_ns, unlockQueue,
      NS_NewRunnableFunction("LockstoreUnlock", [&] {
        kekExists = KekExists(lockstore, kProfilePasswordKek);
        bool unlocked = false;
        kekUnlocked = kekExists &&
                      NS_SUCCEEDED(lockstore->IsKekUnlocked(kProfilePasswordKek,
                                                            &unlocked)) &&
                      unlocked;
      }));
  if (NS_WARN_IF(NS_FAILED(dispatchRv))) {
    // As above: an unanswered probe is no better than an unreachable keystore.
    return false;
  }

  Maybe<PrimaryPasswordSync> sync = ChoosePrimaryPasswordSync(
      kekExists, kekUnlocked,
      [] {
        nsCOMPtr<nsIPKCS11Token> token(
            do_CreateInstance("@mozilla.org/security/internalkeytoken;1"));
        bool hasPassword = false;
        return token && NS_SUCCEEDED(token->GetHasPassword(&hasPassword)) &&
               hasPassword;
      },
      passwordRequired);
  if (sync.isNothing()) {
    // For a protected profile this only happens when the KEK is already
    // unlocked by its owner.
    return finish();
  }

  const bool syncIsSkippable = SyncIsSkippable(*sync, passwordRequired);

  // Nothing can answer a prompt in headless mode, and a protected profile must
  // not wait on one forever.
  if (passwordRequired && PR_GetEnv("MOZ_HEADLESS")) {
    NS_WARNING("A protected profile cannot be unlocked in headless mode");
    return false;
  }

  // Every sync from here on asks the user for the primary password.
  nsCOMPtr<nsIPromptService> ps(do_GetService(NS_PROMPTSERVICE_CONTRACTID));
  if (!ps) {
    // A locked KEK left behind holds every DEK under it hostage for the
    // session; only adoption, which no DEK depends on yet, can wait.
    NS_WARNING("No prompt service to ask for the primary password with");
    return syncIsSkippable;
  }

  nsCOMPtr<nsISecretDecoderRing> sdr(
      do_GetService("@mozilla.org/security/sdr;1"));
  if (!sdr) {
    // Adopting a password nothing has checked would key the KEK to a password
    // the token may never accept, so the sync cannot go ahead here; only
    // adoption can be left to another startup.
    NS_WARNING("No secret decoder ring to check the primary password with");
    return syncIsSkippable;
  }

  nsCOMPtr<nsIStringBundleService> sbs =
      mozilla::components::StringBundle::Service();
  nsCOMPtr<nsIStringBundle> pipnssBundle;
  nsCOMPtr<nsIStringBundle> profileBundle;
  if (sbs) {
    (void)sbs->CreateBundle("chrome://pipnss/locale/pipnss.properties",
                            getter_AddRefs(pipnssBundle));
    if (passwordRequired) {
      (void)sbs->CreateBundle(
          "chrome://mozapps/locale/profile/profileSelection.properties",
          getter_AddRefs(profileBundle));
    }
  }

  // Unless the profile is locked, use the wording NSS itself prompts the
  // primary password with, so the dialog reads the same whichever sync
  // brought us here.
  nsString promptTitle;
  nsString promptText;
  nsString wrongPasswordText;
  if (passwordRequired) {
    promptTitle = GetString(profileBundle, "profileLockUnlockTitle");
    promptText = GetString(profileBundle, "profileLockUnlockText");
    wrongPasswordText = GetString(profileBundle, "profileLockWrongPassword");
  } else {
    promptText = GetString(pipnssBundle, "CertPasswordPromptDefault");
  }
  if (promptText.IsEmpty()) {
    NS_WARNING("Failed to load the primary password prompt string");
    return syncIsSkippable;
  }

#ifdef XP_MACOSX
  // This runs before XRE_mainRun initializes the Cocoa app for the first
  // window. Calling InitializeMacApp more than once does nothing.
  InitializeMacApp();
#endif

  if (*sync == PrimaryPasswordSync::Setup) {
    nsString setupTitle = GetString(profileBundle, "profileLockSetupTitle");
    nsString setupText = GetString(profileBundle, "profileLockSetupText");
    nsString confirmText = GetString(profileBundle, "profileLockConfirmText");
    nsString mismatchText = GetString(profileBundle, "profileLockMismatch");
    nsString emptyText = GetString(profileBundle, "profileLockEmpty");
    if (setupText.IsEmpty() || confirmText.IsEmpty()) {
      NS_WARNING("Failed to load the Profile Lock setup strings");
      return false;
    }

    const nsString noError;
    nsAutoString error;
    while (true) {
      nsAutoCString secret;
      if (!PromptForPassword(ps, setupTitle, setupText, error, secret)) {
        return false;
      }
      if (secret.IsEmpty()) {
        error = emptyText;
        continue;
      }
      nsAutoCString confirmation;
      if (!PromptForPassword(ps, setupTitle, confirmText, noError,
                             confirmation)) {
        return false;
      }
      if (!secret.Equals(confirmation)) {
        error = mismatchText;
        continue;
      }

      nsresult rv = NS_ERROR_FAILURE;
      dispatchRv = NS_DispatchAndSpinEventLoopUntilComplete(
          "LockstoreUnlock"_ns, unlockQueue,
          NS_NewRunnableFunction("LockstoreSetup", [&] {
            rv = SetInitialPrimaryPassword(secret);
            if (NS_SUCCEEDED(rv)) {
              rv = AdoptPrimaryPassword(lockstore, secret);
            }
          }));
      if (NS_FAILED(dispatchRv) || NS_FAILED(rv)) {
        NS_WARNING("Failed to set up the Profile Lock password");
        return false;
      }
      return finish();
    }
  }

  const nsString noUnlockError;
  uint32_t failures = 0;
  while (true) {
    nsAutoCString secret;
    if (!PromptForPassword(ps, promptTitle, promptText,
                           failures ? wrongPasswordText : noUnlockError,
                           secret)) {
      return syncIsSkippable;
    }

    // The token is the ground truth for the password, so check it before
    // lockstore: a typo must not be reported as a lockstore failure.
    bool loggedIn = false;
    if (NS_FAILED(sdr->Login(secret, &loggedIn))) {
      NS_WARNING("Failed to log into the internal token at startup");
      return syncIsSkippable;
    }
    if (!loggedIn) {
      BackOffAfterFailure(++failures);
      continue;
    }

    nsresult rv = NS_ERROR_FAILURE;
    dispatchRv = NS_DispatchAndSpinEventLoopUntilComplete(
        "LockstoreUnlock"_ns, unlockQueue,
        NS_NewRunnableFunction("LockstoreUnlock", [&] {
          if (*sync == PrimaryPasswordSync::Adopt) {
            rv = AdoptPrimaryPassword(lockstore, secret);
            if (NS_SUCCEEDED(rv) && passwordRequired) {
              StrengthenPrimaryPassword(secret);
            }
            return;
          }

          rv = lockstore->DoUnlockKek(kProfilePasswordKek, secret,
                                      kCacheForSession);
        }));
    if (NS_WARN_IF(NS_FAILED(dispatchRv))) {
      return syncIsSkippable;
    }
    if (NS_SUCCEEDED(rv)) {
      return finish();
    }
    NS_WARNING("Failed to sync the lockstore KEK with the primary password");
    return syncIsSkippable;
  }
}

bool SyncProfileKekAtStartup() {
  MOZ_ASSERT(NS_IsMainThread());
  const bool canContinue = SyncLockstoreWithPrimaryPassword();
  Preferences::RegisterCallback(&OnLockstoreUnlockPrefChanged,
                                "security.lockstore.unlock.enabled"_ns);
  return canContinue;
}

}  // namespace mozilla::security::lockstore
