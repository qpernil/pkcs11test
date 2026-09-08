all: pkcs11test
SLOT_ID ?= 0
test_opencryptoki: pkcs11test
	./pkcs11test -m libopencryptoki.so -l /usr/lib/opencryptoki -s ${SLOT_ID}

# Run the specific tests that dump token contents
dump_opencryptoki: pkcs11test
	./pkcs11test -m libopencryptoki.so -l /usr/lib/opencryptoki --gtest_filter=*.Enumerate* -s ${SLOT_ID} -v

# Define STRICT_P11 somewhere to force 1-byte alignment on P11 structures
ifneq (, $(STRICT_P11))
    CXXFLAGS+=-DSTRICT_P11
endif
ifneq (, $(PKCS11_LONG_SIZE))
    CXXFLAGS+=-DPKCS11_LONG_SIZE=$(PKCS11_LONG_SIZE)
endif

GTEST_DIR=gtest-1.10.0/googletest
GTEST_INC=-isystem $(GTEST_DIR)/include
CXXFLAGS+=-Ithird_party/pkcs11  $(GTEST_INC) -g -std=c++0x -Wall
OBJECTS=pkcs11test.o pkcs11-describe.o describe.o globals.o init.o slot.o session.o object.o login.o rng.o tookan.o keypair.o cipher.o digest.o sign.o hmac.o key.o dual.o

key.o tookan.o pkcs11test.o: wrapping-profiles.h

$(OBJECTS): pkcs11-env.h globals.h $(GTEST_DIR)/include/gtest/gtest.h pkcs11test.h pkcs11-describe.h third_party/pkcs11/pkcs11.h third_party/pkcs11/pkcs11t.h third_party/pkcs11/pkcs11f.h

pkcs11test: $(OBJECTS) libgtest.a
	$(CXX) -g $(GTEST_INCS) -o $@ $(OBJECTS) -ldl libgtest.a -lpthread

gtest-all.o: $(GTEST_DIR)/src/gtest-all.cc
	$(CXX) $(CXXFLAGS) -I$(GTEST_DIR) -c $(GTEST_DIR)/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf pkcs11test wrapping-profiles-test wrapping-profiles-test.dSYM $(OBJECTS) gtest-all.o libgtest.a opencryptoki.out

.PHONY: check
check: wrapping-profiles-test
	./wrapping-profiles-test

wrapping-profiles-test: wrapping-profiles-test.cc wrapping-profiles.h pkcs11test.h globals.h libgtest.a
	$(CXX) $(CXXFLAGS) -o $@ wrapping-profiles-test.cc libgtest.a -lpthread
