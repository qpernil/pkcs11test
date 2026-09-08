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
//
// PKCS#11 s11.14: Key management functions
//   C_GenerateKey
//   C_GenerateKeyPair
//   C_WrapKey
//   C_UnwrapKey
//   C_DeriveKey
#include "pkcs11test.h"
#include "wrapping-profiles.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadOnlySessionTest, GenerateKeyInvalid) {
  CK_MECHANISM mechanism = {CKM_DES_KEY_GEN, NULL_PTR, 0};
  CK_ATTRIBUTE attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE key;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_GenerateKey(INVALID_SESSION_HANDLE, &mechanism, attrs, 3, &key));
  CK_RV rv = g_fns->C_GenerateKey(session_, NULL_PTR, attrs, 3, &key);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKey(session_, &mechanism, NULL_PTR, 3, &key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKey(session_, &mechanism, attrs, 3, NULL_PTR));

}

TEST_F(ReadOnlySessionTest, GenerateKeyPairInvalid) {
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_ULONG modulus_bits = 1024;
  CK_BYTE public_exponent_value[] = {0x1, 0x0, 0x1}; // 65537=0x010001
  CK_ATTRIBUTE public_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
    {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_ATTRIBUTE private_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE public_key;
  CK_OBJECT_HANDLE private_key;

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
    g_fns->C_GenerateKeyPair(INVALID_SESSION_HANDLE, &mechanism,
                             public_attrs, 4,
                             private_attrs, 2,
                             &public_key, &private_key));
  CK_RV rv = g_fns->C_GenerateKeyPair(session_, NULL_PTR,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      &public_key, &private_key);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      NULL_PTR, 4,
                                      private_attrs, 2,
                                      &public_key, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      NULL_PTR, 2,
                                      &public_key, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      NULL_PTR, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      &public_key, NULL_PTR));
}


namespace {

// Ensure the unwrapped session object is cleaned up after fatal assertions too.
struct UnwrappedObject {
  explicit UnwrappedObject(CK_SESSION_HANDLE s) : session(s), handle(0) {}
  ~UnwrappedObject() {
    if (handle) EXPECT_CKR_OK(g_fns->C_DestroyObject(session, handle));
  }
  CK_SESSION_HANDLE session;
  CK_OBJECT_HANDLE handle;
};

ObjectAttributes UnwrapAttributes(CK_KEY_TYPE* type) {
  ObjectAttributes attrs;
  static CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  attrs.push_back({CKA_CLASS, &key_class, sizeof(key_class)});
  attrs.push_back({CKA_KEY_TYPE, type, sizeof(*type)});
  attrs.push_back({CKA_TOKEN, &g_ck_false, sizeof(g_ck_false)});
  attrs.push_back({CKA_PRIVATE, &g_ck_false, sizeof(g_ck_false)});
  attrs.push_back({CKA_SENSITIVE, &g_ck_false, sizeof(g_ck_false)});
  attrs.push_back({CKA_EXTRACTABLE, &g_ck_true, sizeof(g_ck_true)});
  return attrs;
}

}  // namespace

TEST_F(ReadOnlySessionTest, WrapUnwrap) {
  LOAD_WRAPPING_PROFILES(profiles, CKF_WRAP | CKF_UNWRAP);
  for (const WrappingProfile& profile : profiles) {
    SCOPED_TRACE(profile.name);
    cout << "Wrapping profile: " << profile.name << endl;
    ObjectAttributes target_attrs;
    SecretKey target(session_, target_attrs, profile.generation, profile.key_length);
    ObjectAttributes wrapping_attrs;
    wrapping_attrs.push_back(CKA_WRAP);
    wrapping_attrs.push_back(CKA_UNWRAP);
    if (profile.flags & CKF_DECRYPT) wrapping_attrs.push_back(CKA_DECRYPT);
    SecretKey wrapping(session_, wrapping_attrs, profile.generation, profile.key_length);
    ASSERT_TRUE(target.valid());
    ASSERT_TRUE(wrapping.valid());

    CK_BYTE iv[16] = {};
    CK_MECHANISM mechanism = profile.parameters(iv);
    CK_BYTE wrapped[4096];
    CK_ULONG wrapped_len = sizeof(wrapped);
    ASSERT_CKR_OK(g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(),
                                  target.handle(), wrapped, &wrapped_len));
    CK_BYTE original[2048];
    CK_ATTRIBUTE original_attr = {CKA_VALUE, original, sizeof(original)};
    ASSERT_CKR_OK(g_fns->C_GetAttributeValue(session_, target.handle(), &original_attr, 1));
    ASSERT_LE(original_attr.ulValueLen, sizeof(original));

    if (profile.flags & CKF_DECRYPT) {
      // Cross-check wrapping against decryption when both are advertised.
      CK_BYTE clear[4096];
      CK_ULONG clear_len = sizeof(clear);
      mechanism = profile.parameters(iv);
      ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism, wrapping.handle()));
      ASSERT_CKR_OK(g_fns->C_Decrypt(session_, wrapped, wrapped_len, clear, &clear_len));
      ASSERT_EQ(original_attr.ulValueLen, clear_len);
      EXPECT_EQ(0, memcmp(original, clear, clear_len));
    }

    CK_KEY_TYPE key_type = profile.key_type;
    ObjectAttributes attrs = UnwrapAttributes(&key_type);
    UnwrappedObject unwrapped(session_);
    mechanism = profile.parameters(iv);
    ASSERT_CKR_OK(g_fns->C_UnwrapKey(session_, &mechanism, wrapping.handle(), wrapped,
                                    wrapped_len, attrs.data(), attrs.size(), &unwrapped.handle));
    CK_BYTE recovered[2048];
    CK_ATTRIBUTE recovered_attr = {CKA_VALUE, recovered, sizeof(recovered)};
    ASSERT_CKR_OK(g_fns->C_GetAttributeValue(session_, unwrapped.handle, &recovered_attr, 1));
    ASSERT_EQ(original_attr.ulValueLen, recovered_attr.ulValueLen);
    EXPECT_EQ(0, memcmp(original, recovered, recovered_attr.ulValueLen));
  }
}

TEST_F(ReadOnlySessionTest, WrapInvalid) {
  LOAD_WRAPPING_PROFILES(profiles, CKF_WRAP);
  for (const WrappingProfile& profile : profiles) {
    SCOPED_TRACE(profile.name);
    cout << "Wrapping profile: " << profile.name << endl;
    ObjectAttributes target_attrs;
    SecretKey target(session_, target_attrs, profile.generation, profile.key_length);
    ObjectAttributes wrapping_attrs;
    wrapping_attrs.push_back(CKA_WRAP);
    SecretKey wrapping(session_, wrapping_attrs, profile.generation, profile.key_length);
    ASSERT_TRUE(target.valid());
    ASSERT_TRUE(wrapping.valid());
    CK_BYTE iv[16] = {};
    CK_MECHANISM mechanism = profile.parameters(iv);
    CK_BYTE data[4096];
    CK_ULONG data_len = sizeof(data);
    ASSERT_CKR_OK(g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(),
                                  target.handle(), data, &data_len));
    data_len = sizeof(data);
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
               g_fns->C_WrapKey(INVALID_SESSION_HANDLE, &mechanism, wrapping.handle(), target.handle(), data, &data_len));
    CK_RV rv = g_fns->C_WrapKey(session_, NULL_PTR, wrapping.handle(), target.handle(), data, &data_len);
    EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << CK_RV_(rv);
    EXPECT_CKR(CKR_WRAPPING_KEY_HANDLE_INVALID,
               g_fns->C_WrapKey(session_, &mechanism, INVALID_OBJECT_HANDLE, target.handle(), data, &data_len));
    EXPECT_CKR(CKR_KEY_HANDLE_INVALID,
               g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), INVALID_OBJECT_HANDLE, data, &data_len));
    EXPECT_CKR(CKR_ARGUMENTS_BAD,
               g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), target.handle(), data, NULL_PTR));
    CK_ULONG required = 0;
    ASSERT_CKR_OK(g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), target.handle(), NULL_PTR, &required));
    ASSERT_GT(required, 1UL);
    data_len = 1;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL,
               g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(), target.handle(), data, &data_len));
  }
}

TEST_F(ReadOnlySessionTest, UnwrapInvalid) {
  LOAD_WRAPPING_PROFILES(profiles, CKF_WRAP | CKF_UNWRAP);
  for (const WrappingProfile& profile : profiles) {
    SCOPED_TRACE(profile.name);
    cout << "Wrapping profile: " << profile.name << endl;
    ObjectAttributes target_attrs;
    SecretKey target(session_, target_attrs, profile.generation, profile.key_length);
    ObjectAttributes wrapping_attrs;
    wrapping_attrs.push_back(CKA_WRAP);
    wrapping_attrs.push_back(CKA_UNWRAP);
    SecretKey wrapping(session_, wrapping_attrs, profile.generation, profile.key_length);
    ASSERT_TRUE(target.valid());
    ASSERT_TRUE(wrapping.valid());
    CK_BYTE iv[16] = {};
    CK_MECHANISM mechanism = profile.parameters(iv);
    CK_BYTE data[4096];
    CK_ULONG data_len = sizeof(data);
    ASSERT_CKR_OK(g_fns->C_WrapKey(session_, &mechanism, wrapping.handle(),
                                  target.handle(), data, &data_len));
    CK_KEY_TYPE key_type = profile.key_type;
    ObjectAttributes attrs = UnwrapAttributes(&key_type);
    UnwrappedObject result(session_);
    EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
               g_fns->C_UnwrapKey(INVALID_SESSION_HANDLE, &mechanism, wrapping.handle(), data, data_len, attrs.data(), attrs.size(), &result.handle));
    CK_RV rv = g_fns->C_UnwrapKey(session_, NULL_PTR, wrapping.handle(), data, data_len, attrs.data(), attrs.size(), &result.handle);
    EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << CK_RV_(rv);
    EXPECT_CKR(CKR_UNWRAPPING_KEY_HANDLE_INVALID,
               g_fns->C_UnwrapKey(session_, &mechanism, 0, data, data_len, attrs.data(), attrs.size(), &result.handle));
    EXPECT_CKR(CKR_ARGUMENTS_BAD,
               g_fns->C_UnwrapKey(session_, &mechanism, wrapping.handle(), NULL_PTR, data_len, attrs.data(), attrs.size(), &result.handle));
    EXPECT_CKR(CKR_ARGUMENTS_BAD,
               g_fns->C_UnwrapKey(session_, &mechanism, wrapping.handle(), data, data_len, NULL_PTR, attrs.size(), &result.handle));
    EXPECT_CKR(CKR_ARGUMENTS_BAD,
               g_fns->C_UnwrapKey(session_, &mechanism, wrapping.handle(), data, data_len, attrs.data(), attrs.size(), NULL_PTR));
    EXPECT_EQ(0UL, result.handle);
  }
}

}  // namespace test
}  // namespace pkcs11
