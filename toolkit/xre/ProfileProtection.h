/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef mozilla_ProfileProtection_h
#define mozilla_ProfileProtection_h

class nsIFile;

namespace mozilla {

// Profile Lock settings that must be known before any profile data is read.
// They live in <profile>/protection.ini, which is deliberately plaintext: it
// only switches protections on, so tampering with it can at worst make the
// profile refuse to open. See toolkit/profile/docs/ProfileLock.md.
struct ProfileProtection {
  // Encrypt every supported store at rest and require the profile password
  // before startup reaches profile-do-change.
  bool mEnabled = false;
  // Force permanent private browsing for this profile.
  bool mPrivateOnly = false;
};

// Reads <aProfileDir>/protection.ini. A missing file means unprotected. A file
// that exists but cannot be parsed is treated as protected so that damage to
// it fails closed.
ProfileProtection ReadProfileProtection(nsIFile* aProfileDir);

// The protection of the profile this process started with. Set by
// XREMain::XRE_mainStartup once the profile is final.
void SetStartupProfileProtection(const ProfileProtection& aProtection);
const ProfileProtection& GetStartupProfileProtection();

// Force the at-rest encryption and unlock prefs on, as locked defaults, for a
// protected startup profile. Must run after the default prefs are loaded and
// before profile-do-change. Main thread only.
void ApplyProfileProtectionPrefs();

}  // namespace mozilla

#endif  // mozilla_ProfileProtection_h
