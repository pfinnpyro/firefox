# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Tests for the update decisions. Run with: python3 test_profilelock_updater.py"""

import datetime
import unittest

import profilelock_updater as u

NOW = datetime.datetime(2026, 11, 10, 12, tzinfo=datetime.timezone.utc)


def nightly(build_id, hg=None):
    return {"build_id": build_id, "hg": hg or f"hg{build_id}", "git": "g"}


def days_ago(days):
    return (NOW - datetime.timedelta(days=days)).isoformat()


class DecideTest(unittest.TestCase):
    def test_already_current(self):
        state = {"built_hg": "hgA"}
        build, _ = u.decide(state, nightly("20261110", "hgA"), [(1, "hidden")], NOW)
        self.assertIsNone(build)

    def test_security_builds_offered_nightly(self):
        state = {"built_hg": "old", "built_at": days_ago(3)}
        offered = nightly("20261110")
        build, reason = u.decide(state, offered, [(1, "hidden")], NOW)
        self.assertEqual(build, offered)
        self.assertIn("security", reason)

    def test_security_rate_limited(self):
        state = {"built_hg": "old", "built_at": days_ago(1)}
        build, reason = u.decide(state, nightly("20261110"), [(1, "hidden")], NOW)
        self.assertIsNone(build)
        self.assertIn("too recently", reason)

    def test_no_security_not_due(self):
        state = {"built_hg": "old", "built_at": days_ago(3)}
        build, _ = u.decide(state, nightly("20261110"), [], NOW)
        self.assertIsNone(build)
        self.assertNotIn("candidate", state)

    def test_weekly_soaks_then_builds_candidate(self):
        state = {"built_hg": "old", "built_at": days_ago(8)}
        first = nightly("20261110090000")
        build, _ = u.decide(state, first, [], NOW)
        self.assertIsNone(build)
        self.assertEqual(state["candidate"]["build_id"], first["build_id"])

        later = NOW + datetime.timedelta(hours=12)
        build, _ = u.decide(state, nightly("20261110210000"), [], later)
        self.assertIsNone(build, "not soaked yet")

        later = NOW + datetime.timedelta(hours=25)
        build, _ = u.decide(state, nightly("20261111090000"), [], later)
        self.assertEqual(build["build_id"], first["build_id"])

    def test_weekly_waits_while_updates_paused(self):
        state = {
            "built_hg": "old",
            "built_at": days_ago(8),
            "candidate": dict(nightly("20261110090000"), seen=days_ago(2)),
        }
        build, reason = u.decide(state, nightly("20261110090000"), [], NOW)
        self.assertIsNone(build)
        self.assertIn("paused", reason)

    def test_first_run_soaks(self):
        state = {}
        build, _ = u.decide(state, nightly("20261110"), [], NOW)
        self.assertIsNone(build)
        self.assertIn("candidate", state)


class BugIdTest(unittest.TestCase):
    def test_bug_ids(self):
        text = "Bug 2090801 - Fix. r=me\nBackout bug 1234567 and Bug1999999"
        self.assertEqual(
            sorted(int(m) for m in u.BUG_RE.findall(text)),
            [1234567, 1999999, 2090801],
        )


if __name__ == "__main__":
    unittest.main()
