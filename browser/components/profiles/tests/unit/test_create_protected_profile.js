/* Any copyright is dedicated to the Public Domain.
https://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { readProfileProtection } = ChromeUtils.importESModule(
  "moz-src:///toolkit/profile/ProfileProtectionFile.sys.mjs"
);

add_setup(() => {
  Services.prefs.setBoolPref("browser.profiles.enabled", true);

  let mockSource = L10nFileSource.createMock(
    "test",
    "app",
    Services.locale.packagedLocales,
    "/localization/",
    [
      {
        path: `/localization/browser/profiles.ftl`,
        source: `
default-profile-name = Profile number: { $number }
original-profile-name = Original profile name
`,
      },
    ]
  );
  let registry = L10nRegistry.getInstance();
  registry.clearSources();
  registry.registerSources([mockSource]);
});

add_task(async function test_create_protected_profile() {
  startProfileService();

  const SelectableProfileService = getSelectableProfileService();
  await getProfilesDatastoreService().init();
  await SelectableProfileService.init();
  await SelectableProfileService.maybeSetupDataStore();

  Assert.ok(
    !SelectableProfileService.newProfilesProtected,
    "An unprotected group creates unprotected profiles by default"
  );

  let plain = await SelectableProfileService.createNewProfile(
    false,
    null,
    "test"
  );
  Assert.ok(
    !(await SelectableProfileService.isProfileProtected(plain)),
    "A plain new profile is not protected"
  );
  Assert.ok(
    !SelectableProfileService.groupToolkitProfile.requiresUnlock,
    "The group does not require unlock yet"
  );

  let locked = await SelectableProfileService.createNewProfile(
    false,
    null,
    "test",
    { protect: true, privateOnly: true }
  );
  Assert.deepEqual(
    readProfileProtection(await locked.rootDir),
    { enabled: true, privateOnly: true },
    "protection.ini was written before the profile first starts"
  );
  Assert.ok(await SelectableProfileService.isProfileProtected(locked));
  Assert.ok(
    SelectableProfileService.groupToolkitProfile.requiresUnlock,
    "A protected profile makes the group require a profile choice"
  );
  Assert.ok(
    SelectableProfileService.newProfilesProtected,
    "Once the group is protected, new profiles are protected by default"
  );

  let inherited = await SelectableProfileService.createNewProfile(
    false,
    null,
    "test"
  );
  Assert.ok(
    await SelectableProfileService.isProfileProtected(inherited),
    "New profiles of a protected group are protected"
  );

  let optedOut = await SelectableProfileService.createNewProfile(
    false,
    null,
    "test",
    { protect: false }
  );
  Assert.ok(
    !(await SelectableProfileService.isProfileProtected(optedOut)),
    "protect: false opts out, as a backup restore must"
  );
});
