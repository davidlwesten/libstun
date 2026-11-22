#include <unity.h>

#include "message.h"
#include "runner.h"
#include "samples.h"

static stun_message_parse_result_t parse(size_t size, uint8_t const data[]) {
  return stun_message_parse((const_view_t){.size = size, .data = data});
}

#define COOKIE 0x21, 0x12, 0xA4, 0x42
#define NOT_COOKIE 0x21, 0x12, 0xA4, 0x43

// The header of a Binding success response with `length` bytes of attributes
#define SUCCESS(length) 0x01, 0x01, 0, length, COOKIE, TRANSACTION_ID

// The header of a Binding request with `length` bytes of attributes
#define REQUEST(length) 0x00, 0x01, 0, length, COOKIE, TRANSACTION_ID

static stun_transaction_id_t const transaction_id = {{TRANSACTION_ID}};

static void test_message_write() {
  uint8_t buffer[24] = {[20] = 0xAA};
  auto const size = stun_message_write(
      (view_t){.size = sizeof(buffer), .data = buffer}, STUN_CLASS_REQUEST,
      STUN_METHOD_BINDING, &transaction_id);

  // no attributes, and nothing past the header
  uint8_t const expected[] = {0x00, 0x01, 0, 0, COOKIE, TRANSACTION_ID, 0xAA};
  TEST_ASSERT_EQUAL_size_t(20, size);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, sizeof(expected));
}

static void test_message_write_interleaves_class_and_method() {
  uint8_t buffer[20];
  auto const dst = (view_t){.size = sizeof(buffer), .data = buffer};

  stun_message_write(dst, STUN_CLASS_ERROR, 0xFFF, &transaction_id);
  TEST_ASSERT_EQUAL_HEX8(0x3F, buffer[0]);
  TEST_ASSERT_EQUAL_HEX8(0xFF, buffer[1]);

  stun_message_write(dst, STUN_CLASS_INDICATION, 0x081, &transaction_id);
  TEST_ASSERT_EQUAL_HEX8(0x02, buffer[0]);
  TEST_ASSERT_EQUAL_HEX8(0x11, buffer[1]);
}

static void test_message_parse() {
  uint8_t const data[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_V4};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);
  auto const message = &parsed.message;
  TEST_ASSERT_EQUAL(STUN_CLASS_SUCCESS, message->header.message_class);
  TEST_ASSERT_EQUAL_HEX16(STUN_METHOD_BINDING, message->header.method);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(transaction_id.bytes,
                                message->header.transaction_id.bytes, 12);
  TEST_ASSERT_EQUAL_size_t(sizeof(data), message->datagram.size);
  TEST_ASSERT_EQUAL_PTR(data, message->datagram.data);
}

static void test_message_parse_class_and_method() {
  // an error response with the highest method
  uint8_t const error[] = {
      0x3F, 0xFF, 0, 8, COOKIE, TRANSACTION_ID, 0x00, 0x09, 0, 4, 0, 0, 4, 0,
  };
  auto parsed = parse(sizeof(error), error);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);
  TEST_ASSERT_EQUAL(STUN_CLASS_ERROR, parsed.message.header.message_class);
  TEST_ASSERT_EQUAL_HEX16(0xFFF, parsed.message.header.method);

  uint8_t const indication[] = {0x02, 0x11, 0, 0, COOKIE, TRANSACTION_ID};
  parsed = parse(sizeof(indication), indication);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);
  TEST_ASSERT_EQUAL(STUN_CLASS_INDICATION, parsed.message.header.message_class);
  TEST_ASSERT_EQUAL_HEX16(0x081, parsed.message.header.method);
}

static void test_message_rejects_other_protocols() {
  uint8_t const wrong_cookie[] = {
      0x01, 0x01, 0, 12, NOT_COOKIE, TRANSACTION_ID, XOR_MAPPED_ADDRESS_V4,
  };
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(wrong_cookie), wrong_cookie).status);

  // the top bits set, as in RTP
  uint8_t const top_bits[] = {
      0x81, 0x01, 0, 12, COOKIE, TRANSACTION_ID, XOR_MAPPED_ADDRESS_V4,
  };
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(top_bits), top_bits).status);
}

static void test_message_rejects_bad_lengths() {
  // the length counts past the datagram
  uint8_t const long_length[] = {SUCCESS(16), XOR_MAPPED_ADDRESS_V4};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(long_length), long_length).status);

  uint8_t const trailing[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_V4, 0, 0, 0, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(trailing), trailing).status);

  uint8_t const truncated[] = {0x01, 0x01, 0, 0, COOKIE};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(truncated), truncated).status);

  // an attribute running past the message
  uint8_t const attribute[] = {SUCCESS(8), 0x80, 0x22, 0, 8, 1, 2, 3, 4};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(attribute), attribute).status);
}

static void test_message_attributes() {
  uint8_t const data[] = {SUCCESS(20), SOFTWARE, XOR_MAPPED_ADDRESS_V4};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);

  auto it = stun_message_attributes(&parsed.message);

  // an optional type we don't know
  auto next = stun_attribute_next(&it);
  TEST_ASSERT_TRUE(next.has_value);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_UNKNOWN, next.value.type);
  TEST_ASSERT_EQUAL_HEX16(0x8022, next.value.unknown.wire_type);

  next = stun_attribute_next(&it);
  TEST_ASSERT_TRUE(next.has_value);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, next.value.type);

  TEST_ASSERT_FALSE(stun_attribute_next(&it).has_value);
  TEST_ASSERT_FALSE(stun_attribute_next(&it).has_value);
}

static void test_message_find_attribute() {
  uint8_t const data[] = {SUCCESS(44), SOFTWARE, XOR_MAPPED_ADDRESS_V6,
                          XOR_MAPPED_ADDRESS_V4};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);

  // the first one of the type, here the IPv6 address
  auto const address = stun_message_find_attribute(
      &parsed.message, STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
  TEST_ASSERT_TRUE(address.has_value);
  TEST_ASSERT_EQUAL_HEX8(0x20, address.value.xor_mapped_address.ip.addr[0]);

  TEST_ASSERT_FALSE(
      stun_message_find_attribute(&parsed.message, STUN_ATTRIBUTE_ERROR_CODE)
          .has_value);
}

static void test_message_no_attributes() {
  uint8_t const data[] = {REQUEST(0)};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);

  auto it = stun_message_attributes(&parsed.message);
  TEST_ASSERT_FALSE(stun_attribute_next(&it).has_value);
}

static void test_message_rejects_invalid_attributes() {
  // a comprehension-required type we don't know after a valid address, which
  // keeps the header
  uint8_t const required[] = {
      SUCCESS(20), XOR_MAPPED_ADDRESS_V4, 0x7F, 0xFF, 0, 4, 1, 2, 3, 4,
  };
  auto const parsed = parse(sizeof(required), required);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID, parsed.status);
  TEST_ASSERT_EQUAL(STUN_CLASS_SUCCESS, parsed.header.message_class);
  TEST_ASSERT_EQUAL_HEX16(STUN_METHOD_BINDING, parsed.header.method);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(transaction_id.bytes,
                                parsed.header.transaction_id.bytes, 12);

  // or without one its class and method call for
  uint8_t const success[] = {SUCCESS(8), SOFTWARE};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(success), success).status);
}

// the FINGERPRINT of SUCCESS(20) followed by XOR_MAPPED_ADDRESS_V4
#define FINGERPRINT 0x80, 0x28, 0, 4, 0x7D, 0x28, 0x1F, 0x59

static void test_message_fingerprint() {
  uint8_t data[] = {SUCCESS(20), XOR_MAPPED_ADDRESS_V4, FINGERPRINT};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);
  TEST_ASSERT_TRUE(
      stun_message_find_attribute(&parsed.message, STUN_ATTRIBUTE_FINGERPRINT)
          .has_value);

  // and one that doesn't match isn't STUN
  data[sizeof(data) - 1] ^= 1;
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_NOT_STUN,
                    parse(sizeof(data), data).status);
}

void message_tests() {
  RUN_TEST(test_message_write);
  RUN_TEST(test_message_write_interleaves_class_and_method);
  RUN_TEST(test_message_parse);
  RUN_TEST(test_message_parse_class_and_method);
  RUN_TEST(test_message_rejects_other_protocols);
  RUN_TEST(test_message_rejects_bad_lengths);
  RUN_TEST(test_message_attributes);
  RUN_TEST(test_message_find_attribute);
  RUN_TEST(test_message_no_attributes);
  RUN_TEST(test_message_rejects_invalid_attributes);
  RUN_TEST(test_message_fingerprint);
}
