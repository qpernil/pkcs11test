#include "wrapping-profiles.h"

namespace pkcs11 {
namespace test {

// This executable exercises discovery decisions without loading a token module.
CK_FUNCTION_LIST_PTR g_fns = NULL_PTR;
CK_SLOT_ID g_slot_id = 0;
const char* g_wrap_mechanism = "auto";

TEST(WrappingProfiles, RequiresGenerationAndRequestedOperations) {
  WrappingCapabilities capabilities;
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP).empty());
  capabilities[CKM_AES_KEY_WRAP] = {16, 32, CKF_WRAP | CKF_UNWRAP};
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP).empty());
  capabilities[CKM_AES_KEY_GEN] = {16, 32, 0};
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP).empty());
  capabilities[CKM_AES_KEY_GEN].flags = CKF_GENERATE;
  EXPECT_EQ(1U, SelectWrappingProfiles(capabilities, CKF_WRAP | CKF_UNWRAP).size());
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP | CKF_DECRYPT).empty());
  capabilities[CKM_AES_KEY_WRAP].flags = CKF_WRAP;
  EXPECT_EQ(1U, SelectWrappingProfiles(capabilities, CKF_WRAP).size());
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP | CKF_UNWRAP).empty());
}

TEST(WrappingProfiles, SelectsEveryCompatibleProfile) {
  WrappingCapabilities capabilities = {
    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_AES_KEY_WRAP, {16, 32, CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_KEY_WRAP_KWP, {16, 32, CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_DES3_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_DES3_ECB, {0, 0, CKF_WRAP | CKF_UNWRAP}},
  };
  auto profiles = SelectWrappingProfiles(capabilities, CKF_WRAP | CKF_UNWRAP);
  ASSERT_EQ(3U, profiles.size());
  EXPECT_EQ(CKM_AES_KEY_WRAP, profiles[0].mechanism);
  EXPECT_EQ(CKM_AES_KEY_WRAP_KWP, profiles[1].mechanism);
  EXPECT_EQ(CKM_DES3_ECB, profiles[2].mechanism);
  EXPECT_EQ(-1, profiles[2].key_length);
  profiles = SelectWrappingProfiles(capabilities, CKF_WRAP, "AES-KWP");
  ASSERT_EQ(1U, profiles.size());
  EXPECT_EQ(CKM_AES_KEY_WRAP_KWP, profiles[0].mechanism);
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP, "AES-ECB").empty());
}

TEST(WrappingProfiles, IntersectsAesSizesAndRespectsBlockAlignment) {
  WrappingCapabilities capabilities = {
    {CKM_AES_KEY_GEN, {24, 32, CKF_GENERATE}},
    {CKM_AES_KEY_WRAP, {16, 24, CKF_WRAP}},
    {CKM_AES_ECB, {24, 24, CKF_WRAP}},
    {CKM_AES_CBC_PAD, {24, 24, CKF_WRAP}},
  };
  auto profiles = SelectWrappingProfiles(capabilities, CKF_WRAP);
  ASSERT_EQ(2U, profiles.size());
  EXPECT_EQ(24, profiles[0].key_length);
  EXPECT_EQ(CKM_AES_CBC_PAD, profiles[1].mechanism);
  EXPECT_EQ(24, profiles[1].key_length);
  capabilities[CKM_AES_KEY_GEN].ulMinKeySize = 32;
  EXPECT_TRUE(SelectWrappingProfiles(capabilities, CKF_WRAP).empty());
  capabilities[CKM_AES_KEY_WRAP].ulMaxKeySize = 32;
  profiles = SelectWrappingProfiles(capabilities, CKF_WRAP);
  ASSERT_EQ(1U, profiles.size());
  EXPECT_EQ(32, profiles[0].key_length);
}

TEST(WrappingProfiles, SuppliesOnlyRequiredIvParameters) {
  CK_BYTE iv[16] = {};
  for (const auto& profile : WrappingCandidates()) {
    std::memset(iv, 0x7f, sizeof(iv));
    CK_MECHANISM mechanism = profile.parameters(iv);
    EXPECT_EQ(profile.mechanism, mechanism.mechanism);
    EXPECT_EQ(profile.iv_length, mechanism.ulParameterLen);
    for (CK_ULONG i = 0; i < profile.iv_length; ++i) EXPECT_EQ(0, iv[i]);
    EXPECT_EQ(profile.iv_length ? iv : NULL_PTR, mechanism.pParameter);
    if (profile.key_type == CKK_AES && profile.iv_length) EXPECT_EQ(16UL, profile.iv_length);
    if (profile.key_type != CKK_AES && profile.iv_length) EXPECT_EQ(8UL, profile.iv_length);
  }
}

namespace {
WrappingCapabilities fake_capabilities;
CK_RV fake_error;
CK_RV FakeGetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info) {
  if (fake_error != CKR_OK) return fake_error;
  auto found = fake_capabilities.find(mechanism);
  if (found == fake_capabilities.end()) return CKR_MECHANISM_INVALID;
  *info = found->second;
  return CKR_OK;
}
class WrappingDiscovery : public ::testing::Test {
  void SetUp() override {
    fake_capabilities.clear();
    fake_error = CKR_OK;
    functions_ = {};
    functions_.C_GetMechanismInfo = FakeGetMechanismInfo;
    g_fns = &functions_;
  }
  void TearDown() override { g_fns = NULL_PTR; }
  CK_FUNCTION_LIST functions_;
};
}

TEST_F(WrappingDiscovery, MissingMechanismsYieldNoProfiles) {
  std::vector<WrappingProfile> profiles = WrappingCandidates();
  EXPECT_EQ(CKR_OK, LoadWrappingProfiles(CKF_WRAP, &profiles));
  EXPECT_TRUE(profiles.empty());
}

TEST_F(WrappingDiscovery, DiscoveryErrorsAreNotUnsupportedAlgorithms) {
  fake_error = CKR_DEVICE_ERROR;
  std::vector<WrappingProfile> profiles = WrappingCandidates();
  EXPECT_EQ(CKR_DEVICE_ERROR, LoadWrappingProfiles(CKF_WRAP, &profiles));
  EXPECT_TRUE(profiles.empty());
}

TEST_F(WrappingDiscovery, LoadsAdvertisedCapabilities) {
  fake_capabilities = {
    {CKM_DES_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_DES_CBC, {0, 0, CKF_WRAP | CKF_DECRYPT}},
  };
  std::vector<WrappingProfile> profiles;
  ASSERT_EQ(CKR_OK, LoadWrappingProfiles(CKF_WRAP | CKF_DECRYPT, &profiles));
  ASSERT_EQ(1U, profiles.size());
  EXPECT_EQ(CKM_DES_CBC, profiles[0].mechanism);
}

}  // namespace test
}  // namespace pkcs11

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
