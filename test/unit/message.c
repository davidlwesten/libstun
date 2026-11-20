#include <unity.h>

#include "message.h"
#include "runner.h"

static stun_message_parse_result_t parse(size_t size, uint8_t const data[]) {
  return stun_message_parse((const_view_t){.size = size, .data = data});
}

// The transaction ID and addresses of RFC 5769's sample responses
#define TRANSACTION_ID                                                         \
  0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE

// 192.0.2.1:32853
#define XOR_MAPPED_ADDRESS_V4                                                  \
  0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43

// [2001:db8:1234:5678:11:2233:4455:6677]:32853
#define XOR_MAPPED_ADDRESS_V6                                                  \
  0x00, 0x20, 0, 20, 0x00, 0x02, 0xA1, 0x47, 0x01, 0x13, 0xA9, 0xFA, 0xA5,     \
      0xD3, 0xF1, 0x79, 0xBC, 0x25, 0xF4, 0xB5, 0xBE, 0xD2, 0xB9, 0xD9

#define COOKIE 0x21, 0x12, 0xA4, 0x42
#define NOT_COOKIE 0x21, 0x12, 0xA4, 0x43

// The header of a Binding success response with `length` bytes of attributes
#define SUCCESS(length) 0x01, 0x01, 0, length, COOKIE, TRANSACTION_ID

// "abc", padded
#define SOFTWARE 0x80, 0x22, 0, 3, 'a', 'b', 'c', 0

#define XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY                                      \
  0x00, 0x20, 0, 8, 0x00, 0x03, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43

// The header of a Binding request with `length` bytes of attributes
#define REQUEST(length) 0x00, 0x01, 0, length, COOKIE, TRANSACTION_ID

// The header of a Binding error response with `length` bytes of attributes
#define ERROR(length) 0x01, 0x11, 0, length, COOKIE, TRANSACTION_ID

// 400 Bad Request, padded
#define ERROR_CODE_400                                                         \
  0x00, 0x09, 0, 15, 0, 0, 4, 0, 'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e',  \
      's', 't', 0

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
  stun_attribute_t attribute;

  // an optional type we don't know
  TEST_ASSERT_TRUE(stun_attribute_next(&it, &attribute));
  TEST_ASSERT_EQUAL_HEX16(0x8022, attribute.type);

  TEST_ASSERT_TRUE(stun_attribute_next(&it, &attribute));
  TEST_ASSERT_EQUAL_HEX16(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, attribute.type);

  TEST_ASSERT_FALSE(stun_attribute_next(&it, &attribute));
  TEST_ASSERT_FALSE(stun_attribute_next(&it, &attribute));
}

static void test_message_no_attributes() {
  uint8_t const data[] = {REQUEST(0)};
  auto const parsed = parse(sizeof(data), data);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed.status);

  auto it = stun_message_attributes(&parsed.message);
  stun_attribute_t attribute;
  TEST_ASSERT_FALSE(stun_attribute_next(&it, &attribute));
}

static void test_message_rejects_unknown_required_attributes() {
  // after a valid address, keeping the header
  uint8_t const required[] = {
      SUCCESS(20), XOR_MAPPED_ADDRESS_V4, 0x7F, 0xFF, 0, 4, 1, 2, 3, 4,
  };
  auto const parsed = parse(sizeof(required), required);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID, parsed.status);
  TEST_ASSERT_EQUAL(STUN_CLASS_SUCCESS, parsed.header.message_class);
  TEST_ASSERT_EQUAL_HEX16(STUN_METHOD_BINDING, parsed.header.method);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(transaction_id.bytes,
                                parsed.header.transaction_id.bytes, 12);

  uint8_t const lowest[] = {REQUEST(4), 0x00, 0x00, 0, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(lowest), lowest).status);

  // the lowest optional type
  uint8_t const optional[] = {REQUEST(4), 0x80, 0x00, 0, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID,
                    parse(sizeof(optional), optional).status);
}

static void test_message_requires_what_its_class_and_method_call_for() {
  // an error response without ERROR-CODE, whatever its method
  uint8_t const error[] = {ERROR(8), SOFTWARE};
  auto parsed = parse(sizeof(error), error);
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID, parsed.status);
  TEST_ASSERT_EQUAL(STUN_CLASS_ERROR, parsed.header.message_class);

  uint8_t const other_error[] = {0x01, 0x12, 0, 0, COOKIE, TRANSACTION_ID};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(other_error), other_error).status);

  // a Binding success response without XOR-MAPPED-ADDRESS
  uint8_t const success[] = {SUCCESS(8), SOFTWARE};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(success), success).status);

  // but not a success response to another method
  uint8_t const other_success[] = {0x01, 0x02, 0, 0, COOKIE, TRANSACTION_ID};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID,
                    parse(sizeof(other_success), other_success).status);

  // nor a request or an indication
  uint8_t const request[] = {REQUEST(0)};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID,
                    parse(sizeof(request), request).status);
  uint8_t const indication[] = {0x00, 0x11, 0, 0, COOKIE, TRANSACTION_ID};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID,
                    parse(sizeof(indication), indication).status);
}

// the message's first attribute
static stun_attribute_t
first_attribute(stun_message_parse_result_t const *parsed) {
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_VALID, parsed->status);
  auto it = stun_message_attributes(&parsed->message);
  stun_attribute_t attribute;
  TEST_ASSERT_TRUE(stun_attribute_next(&it, &attribute));
  return attribute;
}

static void test_attribute_xor_mapped_address_v4() {
  uint8_t const data[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_V4};
  auto const parsed = parse(sizeof(data), data);
  auto const attribute = first_attribute(&parsed);

  uint8_t const ip[16] = {[10] = 0xFF, 0xFF, 192, 0, 2, 1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, attribute.xor_mapped_address.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, attribute.xor_mapped_address.port);
}

static void test_attribute_xor_mapped_address_v6() {
  uint8_t const data[] = {SUCCESS(24), XOR_MAPPED_ADDRESS_V6};
  auto const parsed = parse(sizeof(data), data);
  auto const attribute = first_attribute(&parsed);

  uint8_t const ip[16] = {0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, attribute.xor_mapped_address.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, attribute.xor_mapped_address.port);
}

static void test_attribute_xor_mapped_address_invalid() {
  uint8_t const family[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(family), family).status);

  // an IPv4 address that's too short
  uint8_t const short_value[] = {
      SUCCESS(8), 0x00, 0x20, 0, 4, 0x00, 0x01, 0xA1, 0x47,
  };
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(short_value), short_value).status);
}

static void test_attribute_error_code() {
  uint8_t const bad_request[] = {ERROR(20), ERROR_CODE_400};
  auto parsed = parse(sizeof(bad_request), bad_request);
  TEST_ASSERT_EQUAL_UINT16(400, first_attribute(&parsed).error_code);

  // the reserved bits are ignored, and the reason phrase can be empty
  uint8_t const reserved[] = {ERROR(8), 0x00, 0x09,     0, 4,
                              0xFF,     0xFF, 0xF8 | 6, 99};
  parsed = parse(sizeof(reserved), reserved);
  TEST_ASSERT_EQUAL_UINT16(699, first_attribute(&parsed).error_code);

  uint8_t const lowest[] = {ERROR(8), 0x00, 0x09, 0, 4, 0, 0, 3, 0};
  parsed = parse(sizeof(lowest), lowest);
  TEST_ASSERT_EQUAL_UINT16(300, first_attribute(&parsed).error_code);
}

static void test_attribute_error_code_invalid() {
  uint8_t const class_too_low[] = {ERROR(8), 0x00, 0x09, 0, 4, 0, 0, 2, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(class_too_low), class_too_low).status);

  uint8_t const class_too_high[] = {ERROR(8), 0x00, 0x09, 0, 4, 0, 0, 7, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(class_too_high), class_too_high).status);

  uint8_t const number_too_high[] = {ERROR(8), 0x00, 0x09, 0, 4, 0, 0, 4, 100};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(number_too_high), number_too_high).status);

  uint8_t const too_short[] = {ERROR(8), 0x00, 0x09, 0, 3, 0, 0, 4, 0};
  TEST_ASSERT_EQUAL(STUN_MESSAGE_PARSE_INVALID,
                    parse(sizeof(too_short), too_short).status);
}

void message_tests() {
  RUN_TEST(test_message_write);
  RUN_TEST(test_message_write_interleaves_class_and_method);
  RUN_TEST(test_message_parse);
  RUN_TEST(test_message_parse_class_and_method);
  RUN_TEST(test_message_rejects_other_protocols);
  RUN_TEST(test_message_rejects_bad_lengths);
  RUN_TEST(test_message_attributes);
  RUN_TEST(test_message_no_attributes);
  RUN_TEST(test_message_rejects_unknown_required_attributes);
  RUN_TEST(test_message_requires_what_its_class_and_method_call_for);
  RUN_TEST(test_attribute_xor_mapped_address_v4);
  RUN_TEST(test_attribute_xor_mapped_address_v6);
  RUN_TEST(test_attribute_xor_mapped_address_invalid);
  RUN_TEST(test_attribute_error_code);
  RUN_TEST(test_attribute_error_code_invalid);
}
