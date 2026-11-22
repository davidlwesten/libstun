#include <unity.h>

#include "attribute.h"
#include "runner.h"
#include "samples.h"

#include <string.h>

// what the last reader made reads: a header, left zeroed since the reader
// takes it from stun_header_t instead, then the attributes
static uint8_t message[256];

// a reader for the attributes in `data`, valid until the next call
static stun_attribute_reader_t reader(stun_class_t message_class,
                                      stun_method_t method,
                                      size_t size,
                                      uint8_t const data[]) {
  TEST_ASSERT_LESS_OR_EQUAL(sizeof(message) - STUN_HEADER_SIZE, size);
  memset(message, 0, STUN_HEADER_SIZE);
  memcpy(message + STUN_HEADER_SIZE, data, size);

  stun_header_t const header = {
      .message_class = message_class,
      .method = method,
      .transaction_id = {{TRANSACTION_ID}},
  };
  return stun_attribute_reader_init(
      &header,
      (const_view_t){.size = STUN_HEADER_SIZE + size, .data = message});
}

// the next attribute, which has to be there
static stun_attribute_t read_attribute(stun_attribute_reader_t *reader) {
  auto const read = stun_attribute_reader_next(reader);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_ATTRIBUTE, read.status);
  return read.attribute;
}

static void expect_unknown(stun_attribute_t attribute, uint16_t wire_type) {
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_UNKNOWN, attribute.type);
  TEST_ASSERT_EQUAL_HEX16(wire_type, attribute.unknown.wire_type);
}

// how reading all of `data` ends
static stun_attribute_read_status_t read_all(stun_class_t message_class,
                                             stun_method_t method,
                                             size_t size,
                                             uint8_t const data[]) {
  auto it = reader(message_class, method, size, data);
  stun_attribute_read_result_t read;
  do {
    read = stun_attribute_reader_next(&it);
  } while (read.status == STUN_ATTRIBUTE_READ_ATTRIBUTE);
  return read.status;
}

// a request, which needs no attribute
static stun_attribute_read_status_t read_request(size_t size,
                                                 uint8_t const data[]) {
  return read_all(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, size, data);
}

static void test_reader_reads_in_order() {
  uint8_t const data[] = {SOFTWARE, XOR_MAPPED_ADDRESS_V4};
  auto it = reader(STUN_CLASS_SUCCESS, STUN_METHOD_BINDING, sizeof(data), data);

  expect_unknown(read_attribute(&it), 0x8022);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
                    read_attribute(&it).type);

  // and keeps ending
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_END,
                    stun_attribute_reader_next(&it).status);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_END,
                    stun_attribute_reader_next(&it).status);
}

static void test_reader_no_attributes() {
  uint8_t const data[1] = {};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_END, read_request(0, data));
}

static void test_reader_rejects_bad_framing() {
  // half a header
  uint8_t const half[] = {0x80, 0x22};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(half), half));

  // a value longer than what's left
  uint8_t const long_value[] = {0x80, 0x22, 0, 8, 'a', 'b', 'c', 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(long_value), long_value));

  // without its padding
  uint8_t const unpadded[] = {0x80, 0x22, 0, 3, 'a', 'b', 'c'};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(unpadded), unpadded));

  // after a valid attribute, which comes first
  uint8_t const trailing[] = {SOFTWARE, 0x80};
  auto it = reader(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, sizeof(trailing),
                   trailing);
  expect_unknown(read_attribute(&it), 0x8022);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    stun_attribute_reader_next(&it).status);
}

static void test_reader_unknown_types() {
  // the lowest and highest comprehension-required ones reject the message
  uint8_t const lowest[] = {0x00, 0x00, 0, 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(lowest), lowest));
  uint8_t const highest[] = {0x7F, 0xFF, 0, 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(highest), highest));

  // the lowest and highest optional ones come with only their wire type
  uint8_t const optional[] = {0x80, 0x00, 0, 0, 0xFF, 0xFF, 0, 0};
  auto it = reader(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, sizeof(optional),
                   optional);
  expect_unknown(read_attribute(&it), 0x8000);
  expect_unknown(read_attribute(&it), 0xFFFF);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_END,
                    stun_attribute_reader_next(&it).status);
}

static void test_reader_requires_what_class_and_method_call_for() {
  // an error response ERROR-CODE, whatever its method
  uint8_t const software[] = {SOFTWARE};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_all(STUN_CLASS_ERROR, STUN_METHOD_BINDING,
                             sizeof(software), software));
  TEST_ASSERT_EQUAL(
      STUN_ATTRIBUTE_READ_INVALID,
      read_all(STUN_CLASS_ERROR, (stun_method_t)0x002, 0, software));
  uint8_t const error_code[] = {ERROR_CODE_400};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_END,
                    read_all(STUN_CLASS_ERROR, (stun_method_t)0x002,
                             sizeof(error_code), error_code));

  // a Binding success response XOR-MAPPED-ADDRESS, checked after the last
  // attribute
  auto it = reader(STUN_CLASS_SUCCESS, STUN_METHOD_BINDING, sizeof(software),
                   software);
  expect_unknown(read_attribute(&it), 0x8022);
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    stun_attribute_reader_next(&it).status);

  // which another known attribute doesn't stand in for
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_all(STUN_CLASS_SUCCESS, STUN_METHOD_BINDING,
                             sizeof(error_code), error_code));

  // but nothing for a success response to another method
  TEST_ASSERT_EQUAL(
      STUN_ATTRIBUTE_READ_END,
      read_all(STUN_CLASS_SUCCESS, (stun_method_t)0x002, 0, software));

  // nor a request or an indication
  TEST_ASSERT_EQUAL(
      STUN_ATTRIBUTE_READ_END,
      read_all(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, 0, software));
  TEST_ASSERT_EQUAL(
      STUN_ATTRIBUTE_READ_END,
      read_all(STUN_CLASS_INDICATION, STUN_METHOD_BINDING, 0, software));
}

// the attribute in `data`, which has to parse as `type`
static stun_attribute_t
parse_one(stun_attribute_type_t type, size_t size, uint8_t const data[]) {
  auto it = reader(STUN_CLASS_REQUEST, STUN_METHOD_BINDING, size, data);
  auto const attribute = read_attribute(&it);
  TEST_ASSERT_EQUAL(type, attribute.type);
  return attribute;
}

static void test_attribute_xor_mapped_address_v4() {
  uint8_t const data[] = {XOR_MAPPED_ADDRESS_V4};
  auto const attribute =
      parse_one(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, sizeof(data), data);

  uint8_t const ip[16] = {[10] = 0xFF, 0xFF, 192, 0, 2, 1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, attribute.xor_mapped_address.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, attribute.xor_mapped_address.port);
}

static void test_attribute_xor_mapped_address_v6() {
  uint8_t const data[] = {XOR_MAPPED_ADDRESS_V6};
  auto const attribute =
      parse_one(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS, sizeof(data), data);

  uint8_t const ip[16] = {0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, attribute.xor_mapped_address.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, attribute.xor_mapped_address.port);
}

static void test_attribute_xor_mapped_address_invalid() {
  uint8_t const family[] = {XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(family), family));

  // an IPv4 address that's too short
  uint8_t const short_value[] = {0x00, 0x20, 0, 4, 0x00, 0x01, 0xA1, 0x47};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(short_value), short_value));
}

// the code of the ERROR-CODE in `data`, which has to parse
static uint16_t error_code_of(size_t size, uint8_t const data[]) {
  return parse_one(STUN_ATTRIBUTE_ERROR_CODE, size, data).error_code;
}

static void test_attribute_error_code() {
  uint8_t const bad_request[] = {ERROR_CODE_400};
  TEST_ASSERT_EQUAL_UINT16(400,
                           error_code_of(sizeof(bad_request), bad_request));

  // the reserved bits are ignored, and the reason phrase can be empty
  uint8_t const reserved[] = {0x00, 0x09, 0, 4, 0xFF, 0xFF, 0xF8 | 6, 99};
  TEST_ASSERT_EQUAL_UINT16(699, error_code_of(sizeof(reserved), reserved));

  uint8_t const lowest[] = {0x00, 0x09, 0, 4, 0, 0, 3, 0};
  TEST_ASSERT_EQUAL_UINT16(300, error_code_of(sizeof(lowest), lowest));
}

static void test_attribute_error_code_invalid() {
  uint8_t const class_too_low[] = {0x00, 0x09, 0, 4, 0, 0, 2, 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(class_too_low), class_too_low));

  uint8_t const class_too_high[] = {0x00, 0x09, 0, 4, 0, 0, 7, 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(class_too_high), class_too_high));

  uint8_t const number_too_high[] = {0x00, 0x09, 0, 4, 0, 0, 4, 100};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(number_too_high), number_too_high));

  uint8_t const too_short[] = {0x00, 0x09, 0, 3, 0, 0, 4, 0};
  TEST_ASSERT_EQUAL(STUN_ATTRIBUTE_READ_INVALID,
                    read_request(sizeof(too_short), too_short));
}

void attribute_tests() {
  RUN_TEST(test_reader_reads_in_order);
  RUN_TEST(test_reader_no_attributes);
  RUN_TEST(test_reader_rejects_bad_framing);
  RUN_TEST(test_reader_unknown_types);
  RUN_TEST(test_reader_requires_what_class_and_method_call_for);
  RUN_TEST(test_attribute_xor_mapped_address_v4);
  RUN_TEST(test_attribute_xor_mapped_address_v6);
  RUN_TEST(test_attribute_xor_mapped_address_invalid);
  RUN_TEST(test_attribute_error_code);
  RUN_TEST(test_attribute_error_code_invalid);
}
