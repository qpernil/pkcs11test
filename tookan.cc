// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Test cases analogous to those described by the Tookan project:
//   http://secgroup.dais.unive.it/projects/tookan/
#include "pkcs11test.h"
#include "wrapping-profiles.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadOnlySessionTest, TookanAttackA1) {
  LOAD_WRAPPING_PROFILES(profiles, CKF_WRAP | CKF_DECRYPT);
  for (const WrappingProfile& profile : profiles) {
    SCOPED_TRACE(profile.name);
    cout << "Wrapping profile: " << profile.name << endl;
    ObjectAttributes target_attrs;
    target_attrs.push_back({CKA_SENSITIVE, &g_ck_true, sizeof(g_ck_true)});
    target_attrs.push_back({CKA_EXTRACTABLE, &g_ck_false, sizeof(g_ck_false)});
    SecretKey target(session_, target_attrs, profile.generation, profile.key_length);
    ObjectAttributes wrapping_attrs;
    wrapping_attrs.push_back(CKA_WRAP);
    wrapping_attrs.push_back(CKA_DECRYPT);
    SecretKey wrapping(session_, wrapping_attrs, profile.generation, profile.key_length);
    ASSERT_TRUE(target.valid());
    ASSERT_TRUE(wrapping.valid());
    CK_BYTE iv[16] = {};
    CK_MECHANISM mechanism = profile.parameters(iv);
    CK_BYTE data[4096];
    CK_ULONG data_len = sizeof(data);
    // Establish that this wrapper can export the same kind of extractable key.
    ObjectAttributes control_attrs;
    SecretKey control(session_, control_attrs, profile.generation, profile.key_length);
    ASSERT_TRUE(control.valid());
    ASSERT_CKR_OK(g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), control.handle(), data, &data_len));
    data_len = sizeof(data);
    mechanism = profile.parameters(iv);
    CK_RV rv = g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), target.handle(), data, &data_len);
    // Export must fail before an attacker could decrypt the wrapped key.
    // An advertised operation returning FUNCTION_NOT_SUPPORTED is a failure.
    EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE || rv == CKR_KEY_UNEXTRACTABLE) << CK_RV_(rv);
  }
}

TEST_F(ROEitherSessionTest, TookanAttackA2) {
  REQUIRE_MECHANISM(CKM_AES_KEY_GEN, CKF_GENERATE);
  REQUIRE_MECHANISM(CKM_RSA_PKCS_KEY_PAIR_GEN, CKF_GENERATE_KEY_PAIR);
  REQUIRE_MECHANISM(CKM_RSA_PKCS, CKF_WRAP | CKF_DECRYPT);
  // First, create a sensitive key k1.
  ObjectAttributes k1_attrs;
  k1_attrs.push_back({CKA_SENSITIVE, &g_ck_true, sizeof(g_ck_true)});
  k1_attrs.push_back({CKA_EXTRACTABLE, &g_ck_false, sizeof(g_ck_false)});
  SecretKey k1(session_, k1_attrs, CKM_AES_KEY_GEN, 16);

  // Second, create a keypair k2 with wrap (public) & decrypt (private)
  vector<CK_ATTRIBUTE_TYPE> k2_public_attrs = {CKA_WRAP};
  vector<CK_ATTRIBUTE_TYPE> k2_private_attrs = {CKA_DECRYPT};
  KeyPair k2(session_, k2_public_attrs, k2_private_attrs);
  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv;
  rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.public_handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE ||
              rv == CKR_KEY_UNEXTRACTABLE) << " rv=" << CK_RV_(rv);

  if (rv == CKR_OK) {
    // Use k2 to decrypt the result, giving contents of k1.
    EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.private_handle()));
    CK_ULONG key_out_len = sizeof(data);
    rv = g_fns->C_Decrypt(session_, data, data_len, data, &key_out_len);
    if (rv == CKR_OK) {
      cerr << "Secret key is: " << hex_data(data, key_out_len) << endl;
    }
  }
}

TEST_F(ReadOnlySessionTest, TookanAttackA3) {
  REQUIRE_MECHANISM(CKM_AES_KEY_GEN, CKF_GENERATE);
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs, CKM_AES_KEY_GEN, 16);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
}

TEST_F(ReadOnlySessionTest, TookanAttackA4) {
  REQUIRE_MECHANISM(CKM_AES_KEY_GEN, CKF_GENERATE);
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs, CKM_AES_KEY_GEN, 16);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  // A non-extractable secret must not disclose its value, even when it is
  // non-sensitive. Verify both confidentiality and the unchanged policy.
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
  CK_BBOOL extractable = CK_TRUE;
  CK_ATTRIBUTE policy = {CKA_EXTRACTABLE, &extractable, sizeof(extractable)};
  ASSERT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &policy, 1));
  EXPECT_EQ(CK_FALSE, extractable);
}

TEST_F(ReadOnlySessionTest, TookanAttackA5a) {
  REQUIRE_MECHANISM(CKM_AES_KEY_GEN, CKF_GENERATE);
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs, CKM_AES_KEY_GEN, 16);

  // Try to change it to be non-sensitive
  CK_ATTRIBUTE attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_SENSITIVE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_TRUE, (CK_BBOOL)data[0]);
}

TEST_F(ReadOnlySessionTest, TookanAttackA5b) {
  REQUIRE_MECHANISM(CKM_AES_KEY_GEN, CKF_GENERATE);
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs, CKM_AES_KEY_GEN, 16);

  // Try to change it to be extractable
  CK_ATTRIBUTE attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_EXTRACTABLE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_FALSE, (CK_BBOOL)data[0]);
}

}  // namespace test
}  // namespace pkcs11
