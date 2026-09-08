// Symmetric wrapping fixtures shared by key-management and policy tests.
#ifndef WRAPPING_PROFILES_H
#define WRAPPING_PROFILES_H

#include "pkcs11test.h"
#include <cstring>
#include <map>
#include <set>

namespace pkcs11 {
namespace test {

// The bundled PKCS #11 headers predate these standard mechanism identifiers.
#ifndef CKM_AES_KEY_WRAP
#define CKM_AES_KEY_WRAP 0x00002109UL
#endif
#ifndef CKM_AES_KEY_WRAP_PAD
#define CKM_AES_KEY_WRAP_PAD 0x0000210aUL
#endif
#ifndef CKM_AES_KEY_WRAP_KWP
#define CKM_AES_KEY_WRAP_KWP 0x0000210bUL
#endif

struct WrappingProfile {
  const char* name;
  CK_MECHANISM_TYPE mechanism;
  CK_MECHANISM_TYPE generation;
  CK_KEY_TYPE key_type;
  int key_length;  // CKA_VALUE_LEN for AES; -1 for fixed-size DES/3DES.
  CK_ULONG iv_length;
  CK_FLAGS flags;

  CK_MECHANISM parameters(CK_BYTE* iv) const {
    // Give each operation a fresh test IV even if a provider modified it.
    if (iv_length) std::memset(iv, 0, iv_length);
    return {mechanism, iv_length ? iv : NULL_PTR, iv_length};
  }
};

inline const std::vector<WrappingProfile>& WrappingCandidates() {
  static const std::vector<WrappingProfile> profiles = {
    {"AES-KW", CKM_AES_KEY_WRAP, CKM_AES_KEY_GEN, CKK_AES, 16, 0, 0},
    {"AES-KW-PAD", CKM_AES_KEY_WRAP_PAD, CKM_AES_KEY_GEN, CKK_AES, 16, 0, 0},
    {"AES-KWP", CKM_AES_KEY_WRAP_KWP, CKM_AES_KEY_GEN, CKK_AES, 16, 0, 0},
    {"AES-ECB", CKM_AES_ECB, CKM_AES_KEY_GEN, CKK_AES, 16, 0, 0},
    {"AES-CBC", CKM_AES_CBC, CKM_AES_KEY_GEN, CKK_AES, 16, 16, 0},
    {"AES-CBC-PAD", CKM_AES_CBC_PAD, CKM_AES_KEY_GEN, CKK_AES, 16, 16, 0},
    {"3DES-ECB", CKM_DES3_ECB, CKM_DES3_KEY_GEN, CKK_DES3, -1, 0, 0},
    {"3DES-CBC", CKM_DES3_CBC, CKM_DES3_KEY_GEN, CKK_DES3, -1, 8, 0},
    {"3DES-CBC-PAD", CKM_DES3_CBC_PAD, CKM_DES3_KEY_GEN, CKK_DES3, -1, 8, 0},
    {"DES-ECB", CKM_DES_ECB, CKM_DES_KEY_GEN, CKK_DES, -1, 0, 0},
    {"DES-CBC", CKM_DES_CBC, CKM_DES_KEY_GEN, CKK_DES, -1, 8, 0},
    {"DES-CBC-PAD", CKM_DES_CBC_PAD, CKM_DES_KEY_GEN, CKK_DES, -1, 8, 0},
  };
  return profiles;
}

typedef std::map<CK_MECHANISM_TYPE, CK_MECHANISM_INFO> WrappingCapabilities;

inline std::vector<WrappingProfile> SelectWrappingProfiles(
    const WrappingCapabilities& capabilities, CK_FLAGS required_flags,
    const std::string& selected = "auto") {
  std::vector<WrappingProfile> result;
  for (WrappingProfile profile : WrappingCandidates()) {
    if (selected != "auto" && selected != profile.name) continue;
    auto generation = capabilities.find(profile.generation);
    auto wrapping = capabilities.find(profile.mechanism);
    if (generation == capabilities.end() || wrapping == capabilities.end() ||
        !(generation->second.flags & CKF_GENERATE) ||
        (wrapping->second.flags & required_flags) != required_flags) continue;
    if (profile.key_type == CKK_AES) {
      profile.key_length = 0;
      for (CK_ULONG size : {16UL, 24UL, 32UL}) {
        // The same key type/size is used as wrapping key and wrapped payload.
        // Unpadded AES profiles require a whole number of cipher blocks.
        if (size == 24 && (profile.mechanism == CKM_AES_ECB ||
                           profile.mechanism == CKM_AES_CBC)) continue;
        if (size >= generation->second.ulMinKeySize &&
            size <= generation->second.ulMaxKeySize &&
            size >= wrapping->second.ulMinKeySize &&
            size <= wrapping->second.ulMaxKeySize) {
          profile.key_length = size;
          break;
        }
      }
      if (!profile.key_length) continue;
    }
    // DES/3DES have fixed sizes; PKCS #11 does not use their min/max fields.
    profile.flags = wrapping->second.flags;
    result.push_back(profile);
  }
  return result;
}

inline CK_RV LoadWrappingProfiles(CK_FLAGS required_flags,
                                  std::vector<WrappingProfile>* result) {
  result->clear();
  std::set<CK_MECHANISM_TYPE> mechanisms;
  for (const WrappingProfile& profile : WrappingCandidates()) {
    mechanisms.insert(profile.mechanism);
    mechanisms.insert(profile.generation);
  }
  WrappingCapabilities capabilities;
  for (CK_MECHANISM_TYPE mechanism : mechanisms) {
    CK_MECHANISM_INFO info;
    CK_RV rv = g_fns->C_GetMechanismInfo(g_slot_id, mechanism, &info);
    if (rv == CKR_MECHANISM_INVALID) continue;
    if (rv != CKR_OK) return rv;
    capabilities[mechanism] = info;
  }
  *result = SelectWrappingProfiles(capabilities, required_flags, g_wrap_mechanism);
  return CKR_OK;
}

#define LOAD_WRAPPING_PROFILES(profiles, flags) \
  std::vector<WrappingProfile> profiles; \
  ASSERT_CKR_OK(LoadWrappingProfiles((flags), &profiles)); \
  if (profiles.empty()) { \
    TEST_SKIPPED("No compatible advertised symmetric wrapping mechanism"); \
    return; \
  }

}  // namespace test
}  // namespace pkcs11
#endif
