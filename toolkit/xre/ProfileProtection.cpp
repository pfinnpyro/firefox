/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "mozilla/ProfileProtection.h"

#include "mozilla/Preferences.h"
#include "nsCOMPtr.h"
#include "nsIFile.h"
#include "nsINIParser.h"
#include "nsPrintfCString.h"
#include "nsString.h"
#include "nsThreadUtils.h"
#include "prenv.h"

#include <stdlib.h>

namespace mozilla {

static constexpr auto kProtectionFile = "protection.ini"_ns;
static constexpr const char* kProtectionSection = "Protection";

static ProfileProtection sStartupProtection;

static bool ReadFlag(nsINIParser& aParser, const char* aKey, bool aDefault) {
  nsAutoCString value;
  if (NS_FAILED(aParser.GetString(kProtectionSection, aKey, value))) {
    return aDefault;
  }
  return !value.EqualsLiteral("0");
}

ProfileProtection ReadProfileProtection(nsIFile* aProfileDir) {
  ProfileProtection result;
  if (!aProfileDir) {
    return result;
  }

  nsCOMPtr<nsIFile> file;
  if (NS_FAILED(aProfileDir->Clone(getter_AddRefs(file))) ||
      NS_FAILED(file->Append(NS_ConvertUTF8toUTF16(kProtectionFile)))) {
    return result;
  }

  bool exists = false;
  if (NS_FAILED(file->Exists(&exists)) || !exists) {
    return result;
  }

  nsINIParser parser;
  if (NS_FAILED(parser.Init(file))) {
    NS_WARNING("protection.ini is unreadable, treating profile as protected");
    result.mEnabled = true;
    return result;
  }

  result.mEnabled = ReadFlag(parser, "Enabled", true);
  result.mPrivateOnly =
      result.mEnabled && ReadFlag(parser, "PrivateOnly", false);
  return result;
}

void SetStartupProfileProtection(const ProfileProtection& aProtection) {
  sStartupProtection = aProtection;
}

const ProfileProtection& GetStartupProfileProtection() {
  return sStartupProtection;
}

static void ForceBoolPref(const char* aName, bool aValue) {
  // Locked prefs ignore new defaults, so unlock around the write. Enterprise
  // policies override locked prefs the same way.
  if (Preferences::IsLocked(aName)) {
    (void)Preferences::Unlock(aName);
  }
  if (NS_FAILED(Preferences::SetBool(aName, aValue, PrefValueKind::Default))) {
    NS_WARNING(nsPrintfCString("Failed to force %s", aName).get());
  }
  (void)Preferences::Lock(aName);
}

void ApplyProfileProtectionPrefs() {
  MOZ_ASSERT(NS_IsMainThread());
  if (!sStartupProtection.mEnabled) {
    return;
  }

  static const struct {
    const char* mName;
    bool mValue;
  } kForcedPrefs[] = {
      // Encrypt every store that supports it, under the profile password.
      {"security.lockstore.unlock.enabled", true},
      {"security.storage.encryption.sqlite.enabled", true},
      {"dom.quotaManager.encryption.enabled", true},
      {"browser.cache.disk.encryption.enabled", true},
      {"browser.sessionstore.encryption.available", true},
      {"browser.sessionstore.encryption.enabled", true},
      // Page thumbnails are plaintext images of visited pages.
      {"browser.pagethumbnails.capturing_disabled", true},
      // Crash reports carry process memory, decrypted data and keys included.
      {"browser.crashReports.unsubmittedCheck.autoSubmit2", false},
      {"browser.tabs.crashReporting.sendReport", false},
      {"browser.profileLock.active", true},
  };
  for (const auto& pref : kForcedPrefs) {
    ForceBoolPref(pref.mName, pref.mValue);
  }

  if (sStartupProtection.mPrivateOnly) {
    ForceBoolPref("browser.privatebrowsing.autostart", true);
  }

  // NSS stretches the primary password with only 10,000 PBKDF2 rounds by
  // default, which would make key4.db the cheapest place to guess the Profile
  // Lock password offline. Match lockstore's 600,000 for every password set or
  // changed in this session. NSS reads this whenever it encodes a password.
  static constexpr int kMinIterations = 600000;
  const char* current = PR_GetEnv("NSS_MIN_MP_PBE_ITERATION_COUNT");
  if (!current || atoi(current) < kMinIterations) {
    static const char kIterationEnv[] = "NSS_MIN_MP_PBE_ITERATION_COUNT=600000";
    PR_SetEnv(kIterationEnv);
  }
}

}  // namespace mozilla
