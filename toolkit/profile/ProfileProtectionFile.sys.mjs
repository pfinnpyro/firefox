/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/**
 * Reads and writes protection.ini, the per-profile Profile Lock settings that
 * startup reads before any other profile data (see toolkit/xre/ProfileProtection.h
 * and toolkit/profile/docs/ProfileLock.md).
 *
 * Writes are synchronous because the profile manager may launch the profile
 * as soon as its dialog closes.
 */

export const PROTECTION_FILE_NAME = "protection.ini";

function protectionFile(profileDir) {
  let file = profileDir.clone();
  file.append(PROTECTION_FILE_NAME);
  return file;
}

/**
 * @param {nsIFile} profileDir
 * @returns {{enabled: boolean, privateOnly: boolean}}
 */
export function readProfileProtection(profileDir) {
  let file = protectionFile(profileDir);
  if (!file.exists()) {
    return { enabled: false, privateOnly: false };
  }
  try {
    let parser = Cc["@mozilla.org/xpcom/ini-parser-factory;1"]
      .getService(Ci.nsIINIParserFactory)
      .createINIParser(file);
    let read = (key, fallback) => {
      try {
        return parser.getString("Protection", key) != "0";
      } catch (e) {
        return fallback;
      }
    };
    let enabled = read("Enabled", true);
    return { enabled, privateOnly: enabled && read("PrivateOnly", false) };
  } catch (e) {
    // Startup treats an unreadable file as protected; match it.
    return { enabled: true, privateOnly: false };
  }
}

/**
 * Mark a profile as protected by Profile Lock. Only meaningful for a profile
 * with no data yet: startup refuses to open a protected profile that still
 * holds unencrypted databases.
 *
 * @param {nsIFile} profileDir
 * @param {object} options
 * @param {boolean} options.privateOnly
 *   Force permanent private browsing in this profile.
 */
export function writeProfileProtection(profileDir, { privateOnly = false }) {
  let data = `[Protection]\nEnabled=1\nPrivateOnly=${privateOnly ? 1 : 0}\n`;
  let stream = Cc[
    "@mozilla.org/network/safe-file-output-stream;1"
  ].createInstance(Ci.nsIFileOutputStream);
  // PR_WRONLY | PR_CREATE_FILE | PR_TRUNCATE, owner-only.
  stream.init(protectionFile(profileDir), 0x02 | 0x08 | 0x20, 0o600, 0);
  try {
    stream.write(data, data.length);
    stream.QueryInterface(Ci.nsISafeOutputStream).finish();
  } catch (e) {
    stream.close();
    throw e;
  }
}
