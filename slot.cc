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
// PKCS#11 s11.5: Slot and token management functions
//   C_GetSlotList
//   C_GetSlotInfo
//   C_GetTokenInfo
//   C_WaitForSlotEvent
//   C_GetMechanismList
//   C_GetMechanismInfo
//   C_InitToken
//   C_InitPIN
//   C_SetPIN

#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(PKCS11Test, EnumerateSlots) {
  // First determine how many slots.
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  EXPECT_LT(0, slot_count);
  unique_ptr<CK_SLOT_ID, freer> slot((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  // Retrieve slot list.
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, slot.get(), &slot_count));
  for (int ii = 0; ii < (int)slot_count; ii++) {
    CK_SLOT_INFO slot_info;
    memset(&slot_info, 0, sizeof(slot_info));
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(slot.get()[ii], &slot_info));
    if (g_verbose) cout << "slot[" << ii << "] = " << (unsigned int)slot.get()[ii] << " = " << slot_description(&slot_info) << endl;
    EXPECT_TRUE(IS_SPACE_PADDED(slot_info.slotDescription));
    EXPECT_TRUE(IS_SPACE_PADDED(slot_info.manufacturerID));
    CK_FLAGS all_slot_flags = (CKF_TOKEN_PRESENT|CKF_REMOVABLE_DEVICE|CKF_HW_SLOT);
    EXPECT_EQ(0, slot_info.flags & ~all_slot_flags);
    if (slot_info.flags & CKF_TOKEN_PRESENT) {
      CK_TOKEN_INFO token_info;
      memset(&token_info, 0, sizeof(token_info));
      EXPECT_CKR_OK(g_fns->C_GetTokenInfo(slot.get()[ii], &token_info));
      if (g_verbose) cout << "  " << token_description(&token_info) << endl;
      EXPECT_TRUE(IS_SPACE_PADDED(token_info.label));
      EXPECT_TRUE(IS_SPACE_PADDED(token_info.manufacturerID));
      EXPECT_TRUE(IS_SPACE_PADDED(token_info.model));
      EXPECT_TRUE(IS_SPACE_PADDED(token_info.serialNumber));
      CK_FLAGS all_token_flags = (CKF_RNG|CKF_WRITE_PROTECTED|CKF_LOGIN_REQUIRED|CKF_USER_PIN_INITIALIZED|
                                  CKF_RESTORE_KEY_NOT_NEEDED|CKF_CLOCK_ON_TOKEN|CKF_PROTECTED_AUTHENTICATION_PATH|
                                  CKF_DUAL_CRYPTO_OPERATIONS|CKF_TOKEN_INITIALIZED|CKF_SECONDARY_AUTHENTICATION|
                                  CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED|
                                  CKF_USER_PIN_TO_BE_CHANGED|CKF_SO_PIN_COUNT_LOW|CKF_SO_PIN_FINAL_TRY|
                                  CKF_SO_PIN_LOCKED|CKF_SO_PIN_TO_BE_CHANGED);
      EXPECT_EQ(0, token_info.flags & ~all_token_flags);
      if (g_token_flags & CKF_CLOCK_ON_TOKEN) {
        // Check for well-formed date
        // PKCS#11 s9.2: represented in the format YYYYMMDDhhmmssxx.
        int year = GetInteger(token_info.utcTime + 0, 4);
        EXPECT_LE(1900, year);
        EXPECT_GE(2100, year);
        int month = GetInteger(token_info.utcTime + 4, 2);
        EXPECT_LE(1, month);
        EXPECT_GE(12, month);
        int day = GetInteger(token_info.utcTime + 6, 2);
        EXPECT_LE(1, day);
        EXPECT_GE(31, day);
        int hour = GetInteger(token_info.utcTime + 8, 2);
        EXPECT_LE(0, hour);
        EXPECT_GE(23, hour);
        int min = GetInteger(token_info.utcTime + 10, 2);
        EXPECT_LE(0, min);
        EXPECT_GE(59, min);
        int sec = GetInteger(token_info.utcTime + 12, 2);
        EXPECT_LE(0, sec);
        EXPECT_GE(60, sec);  // Could be a leap second.
        int reserved = GetInteger(token_info.utcTime + 14, 2);
        EXPECT_EQ(0, reserved);
      }
    }
  }
}

TEST_F(PKCS11Test, EnumerateMechanisms) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE)));
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &mechanism_count));
  for (int ii = 0; ii < (int)mechanism_count; ii++) {
    const CK_MECHANISM_TYPE mechanism_type = mechanism.get()[ii];
    CK_MECHANISM_INFO mechanism_info;
    EXPECT_CKR_OK(g_fns->C_GetMechanismInfo(g_slot_id, mechanism_type, &mechanism_info));
    if (g_verbose) cout << "mechanism[" << ii << "]=" << mechanism_type_name(mechanism_type)
                        << " " << mechanism_info_description(&mechanism_info) << endl;

    EXPECT_LE(mechanism_info.ulMinKeySize, mechanism_info.ulMaxKeySize);
    // The mechanism tables in this old suite are not an exhaustive capability
    // registry. Validate defined flag bits, including newer standard APIs.
    CK_INFO library_info;
    ASSERT_CKR_OK(g_fns->C_GetInfo(&library_info));
    CK_FLAGS known = CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_DIGEST |
      CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER |
      CKF_GENERATE | CKF_GENERATE_KEY_PAIR | CKF_WRAP | CKF_UNWRAP | CKF_DERIVE |
      CKF_EC_F_P | CKF_EC_F_2M | CKF_EC_ECPARAMETERS | CKF_EC_NAMEDCURVE |
      CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS | CKF_EXTENSION;
    if (library_info.cryptokiVersion.major >= 3) {
      known |= 0x0000003eUL; // MESSAGE_* and MULTI_MESSAGE (PKCS #11 3.0).
      known |= 0x04000000UL; // EC_CURVENAME (PKCS #11 3.0).
    }
    if (library_info.cryptokiVersion.major > 3 ||
        (library_info.cryptokiVersion.major == 3 && library_info.cryptokiVersion.minor >= 2)) {
      known |= 0x30000000UL; // ENCAPSULATE and DECAPSULATE (PKCS #11 3.2).
    }
    EXPECT_EQ(0UL, mechanism_info.flags & ~known);
  }
}

TEST_F(PKCS11Test, GetSlotList) {
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  unique_ptr<CK_SLOT_ID, freer> all_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, all_slots.get(), &slot_count));
  set<CK_SLOT_ID> all_slots_set;
  for (int ii = 0; ii < (int)slot_count; ++ii) {
    CK_SLOT_ID slot_id = all_slots.get()[ii];
    all_slots_set.insert(slot_id);

    CK_RV rv = g_fns->C_GetSlotInfo(slot_id, nullptr);
    EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);

    CK_SLOT_INFO slot_info;
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(slot_id, &slot_info));

    if (!(slot_info.flags & CKF_TOKEN_PRESENT)) {
      CK_TOKEN_INFO token_info;
      EXPECT_CKR(CKR_TOKEN_NOT_PRESENT, g_fns->C_GetTokenInfo(slot_id, &token_info));
    }
  }
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count));
  unique_ptr<CK_SLOT_ID, freer> token_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_TRUE, token_slots.get(), &slot_count));

  // Every slot with a token should appear in the list of all slots.
  for (int ii = 0; ii < (int)slot_count; ++ii) {
    EXPECT_EQ(1, all_slots_set.count(token_slots.get()[ii]));
    CK_RV rv = g_fns->C_GetSlotInfo(token_slots.get()[ii], nullptr);
    EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << CK_RV_(rv);
    EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetTokenInfo(token_slots.get()[ii], nullptr));
  }
}

TEST_F(PKCS11Test, GetSlotListFailTooSmall) {
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  if (slot_count > 1) {
    unique_ptr<CK_SLOT_ID, freer> all_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
    CK_ULONG new_count = (slot_count - 1);
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, g_fns->C_GetSlotList(CK_FALSE, all_slots.get(), &new_count));
    EXPECT_EQ(slot_count, new_count);
  }
}

TEST_F(PKCS11Test, GetSlotListTooLarge) {
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  if (slot_count > 1) {
    // Over-allocate space.
    CK_ULONG new_count = slot_count + 3;
    unique_ptr<CK_SLOT_ID, freer> all_slots((CK_SLOT_ID*)malloc(new_count * sizeof(CK_SLOT_ID)));
    EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, all_slots.get(), &new_count));
    EXPECT_EQ(slot_count, new_count);
  }
}

TEST_F(PKCS11Test, GetSlotListFailArgumentsBad) {
  CK_RV rv = g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << CK_RV_(rv);
}

TEST_F(PKCS11Test, GetSlotInfoFail) {
  CK_SLOT_INFO slot_info;
  memset(&slot_info, 0, sizeof(slot_info));
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetSlotInfo(INVALID_SLOT_ID, &slot_info));
  CK_RV rv = g_fns->C_GetSlotInfo(g_slot_id, nullptr);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST_F(PKCS11Test, GetTokenInfoFail) {
  CK_TOKEN_INFO token_info;
  memset(&token_info, 0, sizeof(token_info));
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetTokenInfo(INVALID_SLOT_ID, &token_info));
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetTokenInfo(g_slot_id, nullptr));
}

TEST_F(PKCS11Test, WaitForSlotEvent) {
  CK_SLOT_ID slot_id = -1;
  // Ask twice without blocking, to clear any pending event.
  CK_RV rv = g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("WaitForSlotEvent not supported");
    return;
  }
  EXPECT_CKR(CKR_NO_EVENT, g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR));
}

TEST_F(PKCS11Test, GetMechanismListFailInvalid) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, NULL_PTR));
}

TEST_F(PKCS11Test, GetMechanismListFailInvalidSlot) {
  CK_ULONG mechanism_count;
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetMechanismList(INVALID_SLOT_ID, NULL_PTR, &mechanism_count));
}

TEST_F(PKCS11Test, GetMechanismListFailTooSmall) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  if (mechanism_count > 1) {
    unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE)));
    CK_ULONG new_count = mechanism_count - 1;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &new_count));
    EXPECT_EQ(mechanism_count, new_count);
  }
}

TEST_F(PKCS11Test, GetMechanismListTooLarge) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  if (mechanism_count > 1) {
    // Over-allocate space.
    CK_ULONG new_count = mechanism_count + 3;
    unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(new_count * sizeof(CK_MECHANISM_TYPE)));
    EXPECT_CKR(CKR_OK, g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &new_count));
    EXPECT_EQ(mechanism_count, new_count);
  }
}

TEST_F(PKCS11Test, GetMechanismInfoInvalid) {
  CK_MECHANISM_INFO mechanism_info;
  EXPECT_CKR(CKR_MECHANISM_INVALID, g_fns->C_GetMechanismInfo(g_slot_id, CKM_VENDOR_DEFINED + 1, &mechanism_info));
}

TEST_F(PKCS11Test, GetMechanismInfoInvalidSlot) {
  CK_MECHANISM_INFO mechanism_info;
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetMechanismInfo(INVALID_SLOT_ID, CKM_RSA_PKCS_KEY_PAIR_GEN, &mechanism_info));
}

TEST_F(PKCS11Test, GetMechanismInfoFail) {
  CK_RV rv = g_fns->C_GetMechanismInfo(g_slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST(Slot, NoInit) {
  // Check nothing works if C_Initialize has not been called.
  CK_ULONG slot_count;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  CK_SLOT_INFO slot_info;
  memset(&slot_info, 0, sizeof(slot_info));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetSlotInfo(g_slot_id, &slot_info));
  CK_TOKEN_INFO token_info;
  memset(&token_info, 0, sizeof(token_info));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetTokenInfo(g_slot_id, &token_info));
  CK_SLOT_ID slot_id = -1;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR));
  CK_ULONG mechanism_count;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  CK_MECHANISM_INFO mechanism_info;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetMechanismInfo(g_slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, &mechanism_info));
  const char* label_str = "PKCS#11 Unit Test";
  CK_UTF8CHAR label[32];
  memset(label, ' ', sizeof(label));
  memcpy(label, label_str, strlen(label_str));  // Not including null terminator.
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_InitToken(INVALID_SLOT_ID, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), label));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_InitPIN(INVALID_SESSION_HANDLE, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_SetPIN(INVALID_SESSION_HANDLE,
                                                           (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin),
                                                           (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(PKCS11Test, TokenInit) {
  if (!g_init_token) {
    TEST_SKIPPED("Destructive token re-initialization not performed");
    return;
  }
  if (g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
    if (g_verbose) cout << "Skipping token initialization due to protected authentication path" << endl;
  }
  // !!!WARNING!!! - The following line will destroy all content on the token.
  EXPECT_CKR_OK(g_fns->C_InitToken(g_slot_id, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));

  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    if (g_verbose) cout << "Skipping restoration of PINs" << endl;
    return;
  }

  // User PIN will have been reset, so need to set it. Use a new session (which also checks that the SO PIN is still OK).
  {
    RWSOSession session(g_so_pin);
    EXPECT_CKR_OK(g_fns->C_InitPIN(session.handle(), (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  }
  // Check the user PIN is as expected.
  {
    ROSession session;
    EXPECT_CKR_OK(g_fns->C_Login(session.handle(), CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
    g_fns->C_Logout(session.handle());
  }

}

TEST_F(PKCS11Test, TokenInitPinIncorrect) {
  if (!g_init_token) {
    TEST_SKIPPED("Destructive token re-initialization not performed");
    return;
  }
  // Keep the known-valid length and character family; test authentication,
  // not the token's minimum PIN length with a fixed five-byte string.
  string wrong_pin(g_so_pin);
  ASSERT_FALSE(wrong_pin.empty());
  char& first = wrong_pin[0];
  if (first >= '0' && first <= '9') first = first == '0' ? '1' : '0';
  else if (first >= 'a' && first <= 'z') first = first == 'a' ? 'b' : 'a';
  else if (first >= 'A' && first <= 'Z') first = first == 'A' ? 'B' : 'A';
  else { TEST_SKIPPED("Cannot construct a same-format wrong SO PIN"); return; }
  EXPECT_CKR(CKR_PIN_INCORRECT, g_fns->C_InitToken(g_slot_id,
      (CK_UTF8CHAR_PTR)wrong_pin.data(), wrong_pin.size(), g_token_label));
}

TEST_F(PKCS11Test, TokenInitInvalidSlot) {
  if (!g_init_token) {
    TEST_SKIPPED("Destructive token re-initialization not performed");
    return;
  }
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_InitToken(INVALID_SLOT_ID, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));
}

TEST_F(ReadOnlySessionTest, TokenInitWithSession) {
  if (!g_init_token) {
    TEST_SKIPPED("Destructive token re-initialization not performed");
    return;
  }
  EXPECT_CKR(CKR_SESSION_EXISTS, g_fns->C_InitToken(g_slot_id, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));
}

}  // namespace test
}  // namespace pkcs11
