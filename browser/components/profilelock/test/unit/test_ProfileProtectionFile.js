/* Any copyright is dedicated to the Public Domain.
   http://creativecommons.org/publicdomain/zero/1.0/ */

"use strict";

const { AppConstants } = ChromeUtils.importESModule(
  "resource://gre/modules/AppConstants.sys.mjs"
);

const { readProfileProtection, writeProfileProtection, PROTECTION_FILE_NAME } =
  ChromeUtils.importESModule(
    "moz-src:///toolkit/profile/ProfileProtectionFile.sys.mjs"
  );

function makeDir() {
  let dir = do_get_tempdir();
  dir.append("protection-test");
  dir.createUnique(Ci.nsIFile.DIRECTORY_TYPE, 0o700);
  return dir;
}

add_task(async function test_missing_file_is_unprotected() {
  Assert.deepEqual(readProfileProtection(makeDir()), {
    enabled: false,
    privateOnly: false,
  });
});

add_task(async function test_round_trip() {
  let dir = makeDir();
  writeProfileProtection(dir, { privateOnly: true });
  Assert.deepEqual(readProfileProtection(dir), {
    enabled: true,
    privateOnly: true,
  });

  writeProfileProtection(dir, { privateOnly: false });
  Assert.deepEqual(readProfileProtection(dir), {
    enabled: true,
    privateOnly: false,
  });

  let file = dir.clone();
  file.append(PROTECTION_FILE_NAME);
  if (AppConstants.platform != "win") {
    Assert.equal(file.permissions & 0o077, 0, "Only the owner can access it");
  }
});

add_task(async function test_damaged_file_fails_closed() {
  let dir = makeDir();
  let file = dir.clone();
  file.append(PROTECTION_FILE_NAME);
  await IOUtils.writeUTF8(file.path, "[Protection]\n");
  Assert.ok(
    readProfileProtection(dir).enabled,
    "A file without Enabled still means protected"
  );
});
