/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

/*
 * Tests that the Profile Lock RequiresUnlock flag round-trips through
 * profiles.ini via nsIToolkitProfile.requiresUnlock.
 */

function readRequiresUnlock(section) {
  let target = gDataHome.clone();
  target.append("profiles.ini");
  let ini = Cc["@mozilla.org/xpcom/ini-parser-factory;1"]
    .getService(Ci.nsIINIParserFactory)
    .createINIParser(target);
  return safeGet(ini, section, "RequiresUnlock");
}

add_task(async () => {
  let first = makeRandomProfileDir("first");
  let second = makeRandomProfileDir("second");
  writeProfilesIni({
    profiles: [
      { name: "first", path: first.leafName, default: true },
      { name: "second", path: second.leafName },
    ],
  });

  // Mark the second profile by hand, as an older session would have.
  let target = gDataHome.clone();
  target.append("profiles.ini");
  let writer = Cc["@mozilla.org/xpcom/ini-parser-factory;1"]
    .getService(Ci.nsIINIParserFactory)
    .createINIParser(target)
    .QueryInterface(Ci.nsIINIParserWriter);
  writer.setString("Profile1", "RequiresUnlock", "1");
  writer.writeFile(target);

  let service = getProfileService();
  let byName = name =>
    Array.from(service.profiles.entries(Ci.nsIToolkitProfile)).find(
      profile => profile.name == name
    );

  Assert.ok(!byName("first").requiresUnlock, "First profile is unprotected");
  Assert.ok(byName("second").requiresUnlock, "Second profile is protected");

  byName("first").requiresUnlock = true;
  byName("second").requiresUnlock = false;
  service.flush();

  Assert.equal(readRequiresUnlock("Profile0"), "1", "Flag was written");
  Assert.equal(readRequiresUnlock("Profile1"), null, "Flag was removed");

  // Removing a profile renumbers the sections; the flag must follow.
  byName("first").requiresUnlock = false;
  byName("second").requiresUnlock = true;
  service.flush();
  byName("first").remove(false);
  service.flush();
  Assert.equal(
    readRequiresUnlock("Profile0"),
    "1",
    "Flag survived renumbering"
  );
  Assert.ok(byName("second").requiresUnlock, "Profile is still protected");
});
