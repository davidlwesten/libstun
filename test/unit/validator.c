#include <unity.h>

#include "runner.h"
#include "validator.h"

static stun_validator_t begin(stun_class_t message_class,
                              stun_method_t method) {
  stun_header_t const header = {.message_class = message_class,
                                .method = method};
  return stun_validator_begin(&header);
}

// an attribute of a type we know, as decoding leaves it
static bool add_known(stun_validator_t *validator, stun_attribute_type_t type) {
  stun_attribute_t const attribute = {.type = type};
  return stun_validator_add(validator, &attribute, true);
}

static bool add_unknown(stun_validator_t *validator, uint16_t type) {
  stun_attribute_t const attribute = {.type = (stun_attribute_type_t)type};
  return stun_validator_add(validator, &attribute, false);
}

static void test_validator_nothing_required() {
  auto validator = begin(STUN_CLASS_REQUEST, STUN_METHOD_BINDING);
  TEST_ASSERT_TRUE(stun_validator_end(&validator));

  validator = begin(STUN_CLASS_INDICATION, STUN_METHOD_BINDING);
  TEST_ASSERT_TRUE(stun_validator_end(&validator));

  // only Binding says what its success responses carry so far
  validator = begin(STUN_CLASS_SUCCESS, (stun_method_t)0x002);
  TEST_ASSERT_TRUE(stun_validator_end(&validator));
}

static void test_validator_unknown_attributes() {
  auto validator = begin(STUN_CLASS_REQUEST, STUN_METHOD_BINDING);

  // optional ones are skipped
  TEST_ASSERT_TRUE(add_unknown(&validator, 0x8000));
  TEST_ASSERT_TRUE(add_unknown(&validator, 0xFFFF));
  TEST_ASSERT_TRUE(stun_validator_end(&validator));

  // and comprehension-required ones reject the message
  TEST_ASSERT_FALSE(add_unknown(&validator, 0x0000));
  TEST_ASSERT_FALSE(add_unknown(&validator, 0x7FFF));
}

static void test_validator_error_response_needs_error_code() {
  auto validator = begin(STUN_CLASS_ERROR, STUN_METHOD_BINDING);
  TEST_ASSERT_TRUE(add_unknown(&validator, 0x8022));
  TEST_ASSERT_FALSE(stun_validator_end(&validator));
  TEST_ASSERT_TRUE(add_known(&validator, STUN_ATTRIBUTE_ERROR_CODE));
  TEST_ASSERT_TRUE(stun_validator_end(&validator));

  // whatever the method
  validator = begin(STUN_CLASS_ERROR, (stun_method_t)0x002);
  TEST_ASSERT_FALSE(stun_validator_end(&validator));
  TEST_ASSERT_TRUE(add_known(&validator, STUN_ATTRIBUTE_ERROR_CODE));
  TEST_ASSERT_TRUE(stun_validator_end(&validator));
}

static void test_validator_binding_success_needs_address() {
  auto validator = begin(STUN_CLASS_SUCCESS, STUN_METHOD_BINDING);
  TEST_ASSERT_FALSE(stun_validator_end(&validator));

  // another known attribute doesn't count
  TEST_ASSERT_TRUE(add_known(&validator, STUN_ATTRIBUTE_ERROR_CODE));
  TEST_ASSERT_FALSE(stun_validator_end(&validator));

  TEST_ASSERT_TRUE(add_known(&validator, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS));
  TEST_ASSERT_TRUE(stun_validator_end(&validator));

  // and more of it doesn't hurt
  TEST_ASSERT_TRUE(add_known(&validator, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS));
  TEST_ASSERT_TRUE(stun_validator_end(&validator));
}

void validator_tests() {
  RUN_TEST(test_validator_nothing_required);
  RUN_TEST(test_validator_unknown_attributes);
  RUN_TEST(test_validator_error_response_needs_error_code);
  RUN_TEST(test_validator_binding_success_needs_address);
}
