/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "mozilla/security/lockstore/ProfileKek.h"

using mozilla::Maybe;
using mozilla::Nothing;
using mozilla::Some;
using mozilla::security::lockstore::ChoosePrimaryPasswordSync;
using mozilla::security::lockstore::PrimaryPasswordSync;
using mozilla::security::lockstore::SyncIsSkippable;

namespace {

// Fails the test if the decision reaches for the internal key token when it
// had no business doing so.
bool TokenMustNotBeProbed() {
  ADD_FAILURE() << "the internal key token was probed unnecessarily";
  return false;
}

Maybe<PrimaryPasswordSync> Choose(bool aKekExists, bool aKekUnlocked,
                                  bool aTokenHasPassword) {
  return ChoosePrimaryPasswordSync(aKekExists, aKekUnlocked,
                                   [&] { return aTokenHasPassword; });
}

}  // namespace

TEST(ProfileKek, UnlockWhenKekExistsAndLocked)
{
  EXPECT_EQ(
      ChoosePrimaryPasswordSync(/* kekExists */ true,
                                /* kekUnlocked */ false, TokenMustNotBeProbed),
      Some(PrimaryPasswordSync::Unlock));
}

// An unlocked KEK was unlocked by someone other than this sync, which runs
// before anything here touches it.
TEST(ProfileKek, NothingToDoWhenKekAlreadyUnlocked)
{
  EXPECT_EQ(
      ChoosePrimaryPasswordSync(/* kekExists */ true,
                                /* kekUnlocked */ true, TokenMustNotBeProbed),
      Nothing());
}

TEST(ProfileKek, AdoptAnUnknownPrimaryPassword)
{
  EXPECT_EQ(Choose(/* kekExists */ false, /* kekUnlocked */ false,
                   /* tokenHasPassword */ true),
            Some(PrimaryPasswordSync::Adopt));
}

TEST(ProfileKek, NothingToAdoptWithoutAPrimaryPassword)
{
  EXPECT_EQ(Choose(/* kekExists */ false, /* kekUnlocked */ false,
                   /* tokenHasPassword */ false),
            Nothing());
}

TEST(ProfileKek, TokenProbedOnlyWhenAdoptionIsPossible)
{
  uint32_t probes = 0;
  auto probe = [&] {
    ++probes;
    return true;
  };

  ChoosePrimaryPasswordSync(/* kekExists */ false, /* kekUnlocked */ false,
                            probe);
  EXPECT_EQ(probes, 1u);
}

// Only adoption may be abandoned: giving up on an unlock leaves DEKs wrapped
// under a KEK this session cannot unlock.
TEST(ProfileKek, OnlyAdoptionIsSkippable)
{
  EXPECT_TRUE(SyncIsSkippable(PrimaryPasswordSync::Adopt));
  EXPECT_FALSE(SyncIsSkippable(PrimaryPasswordSync::Unlock));
}

// Profile Lock: with no password anywhere, a protected profile must create
// one rather than carry on under a LocalKey.
TEST(ProfileKek, SetupWhenPasswordRequiredAndNoneExists)
{
  EXPECT_EQ(
      ChoosePrimaryPasswordSync(/* kekExists */
                                false,
                                /* kekUnlocked */ false, [] { return false; },
                                /* passwordRequired */ true),
      Some(PrimaryPasswordSync::Setup));
}

TEST(ProfileKek, AdoptExistingPrimaryPasswordWhenPasswordRequired)
{
  EXPECT_EQ(
      ChoosePrimaryPasswordSync(/* kekExists */
                                false,
                                /* kekUnlocked */ false, [] { return true; },
                                /* passwordRequired */ true),
      Some(PrimaryPasswordSync::Adopt));
}

TEST(ProfileKek, UnlockWhenPasswordRequired)
{
  EXPECT_EQ(
      ChoosePrimaryPasswordSync(/* kekExists */ true,
                                /* kekUnlocked */ false, TokenMustNotBeProbed,
                                /* passwordRequired */ true),
      Some(PrimaryPasswordSync::Unlock));
}

TEST(ProfileKek, NothingIsSkippableWhenPasswordRequired)
{
  EXPECT_FALSE(SyncIsSkippable(PrimaryPasswordSync::Adopt,
                               /* passwordRequired */ true));
  EXPECT_FALSE(SyncIsSkippable(PrimaryPasswordSync::Unlock,
                               /* passwordRequired */ true));
  EXPECT_FALSE(SyncIsSkippable(PrimaryPasswordSync::Setup,
                               /* passwordRequired */ true));
}

TEST(ProfileKek, RecognizesLocalKekRefs)
{
  using mozilla::security::lockstore::IsLocalKekRef;
  using mozilla::security::lockstore::kProfileLocalKek;
  using mozilla::security::lockstore::kProfilePasswordKek;
  EXPECT_TRUE(IsLocalKekRef(kProfileLocalKek));
  EXPECT_TRUE(IsLocalKekRef("lockstore::kek::local:sqlite"_ns));
  EXPECT_FALSE(IsLocalKekRef(kProfilePasswordKek));
  EXPECT_FALSE(IsLocalKekRef("lockstore::kek::pkcs11:abc"_ns));
}
