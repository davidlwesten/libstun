#include <unity.h>

#include "packet.h"
#include "runner.h"

static stun_optional_binding_response_t read(size_t size,
                                             uint8_t const data[]) {
  return stun_packet_read_response((const_view_t){.size = size, .data = data});
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

#define UNKNOWN_REQUIRED 0x7F, 0xFF, 0, 4, 1, 2, 3, 4

#define XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY                                      \
  0x00, 0x20, 0, 8, 0x00, 0x03, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43

static void test_packet_binding_request() {
  stun_transaction_id_t const id = {{TRANSACTION_ID}};
  uint8_t buffer[24] = {[20] = 0xAA};
  auto const size = stun_packet_write_binding_request(
      (view_t){.size = sizeof(buffer), .data = buffer}, &id);

  // no attributes, and nothing past the header
  uint8_t const expected[] = {0x00, 0x01, 0, 0, COOKIE, TRANSACTION_ID, 0xAA};
  TEST_ASSERT_EQUAL_size_t(20, size);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, buffer, sizeof(expected));
}

static void test_packet_response_v4() {
  uint8_t const data[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_V4};
  auto const response = read(sizeof(data), data);
  TEST_ASSERT_TRUE(response.has_value);

  stun_transaction_id_t const id = {{TRANSACTION_ID}};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(id.bytes, response.value.transaction_id.bytes,
                                sizeof(id.bytes));
  uint8_t const ip[16] = {[10] = 0xFF, 0xFF, 192, 0, 2, 1};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, response.value.mapped.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, response.value.mapped.port);
}

static void test_packet_response_v6() {
  uint8_t const data[] = {SUCCESS(24), XOR_MAPPED_ADDRESS_V6};
  auto const response = read(sizeof(data), data);
  TEST_ASSERT_TRUE(response.has_value);

  uint8_t const ip[16] = {0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                          0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  TEST_ASSERT_EQUAL_UINT8_ARRAY(ip, response.value.mapped.ip.addr, 16);
  TEST_ASSERT_EQUAL_UINT16(32853, response.value.mapped.port);
}

static void test_packet_response_skips_optional_attributes() {
  uint8_t const data[] = {SUCCESS(20), SOFTWARE, XOR_MAPPED_ADDRESS_V4};
  auto const response = read(sizeof(data), data);
  TEST_ASSERT_TRUE(response.has_value);
  TEST_ASSERT_EQUAL_UINT16(32853, response.value.mapped.port);
}

static void test_packet_response_first_address_counts() {
  uint8_t const data[] = {
      SUCCESS(36),
      XOR_MAPPED_ADDRESS_V4,
      XOR_MAPPED_ADDRESS_V6,
  };
  auto const response = read(sizeof(data), data);
  TEST_ASSERT_TRUE(response.has_value);
  TEST_ASSERT_EQUAL_UINT8(192, response.value.mapped.ip.addr[12]);
}

static void test_packet_response_unknown_required_attribute() {
  uint8_t const data[] = {SUCCESS(20), UNKNOWN_REQUIRED, XOR_MAPPED_ADDRESS_V4};
  TEST_ASSERT_FALSE(read(sizeof(data), data).has_value);
}

static void test_packet_response_without_address() {
  uint8_t const data[] = {SUCCESS(0)};
  TEST_ASSERT_FALSE(read(sizeof(data), data).has_value);
}

static void test_packet_response_bad_address() {
  uint8_t const data[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY};
  TEST_ASSERT_FALSE(read(sizeof(data), data).has_value);
}

static void test_packet_ignores_other_messages() {
  uint8_t const request[] = {
      0x00, 0x01, 0, 12, COOKIE, TRANSACTION_ID, XOR_MAPPED_ADDRESS_V4,
  };
  TEST_ASSERT_FALSE(read(sizeof(request), request).has_value);

  uint8_t const wrong_cookie[] = {
      0x01, 0x01, 0, 12, NOT_COOKIE, TRANSACTION_ID, XOR_MAPPED_ADDRESS_V4,
  };
  TEST_ASSERT_FALSE(read(sizeof(wrong_cookie), wrong_cookie).has_value);

  // the top bits set, as in RTP
  uint8_t const top_bits[] = {
      0x81, 0x01, 0, 12, COOKIE, TRANSACTION_ID, XOR_MAPPED_ADDRESS_V4,
  };
  TEST_ASSERT_FALSE(read(sizeof(top_bits), top_bits).has_value);
}

static void test_packet_rejects_bad_lengths() {
  // the length counts past the datagram
  uint8_t const long_length[] = {SUCCESS(16), XOR_MAPPED_ADDRESS_V4};
  TEST_ASSERT_FALSE(read(sizeof(long_length), long_length).has_value);

  uint8_t const trailing[] = {SUCCESS(12), XOR_MAPPED_ADDRESS_V4, 0, 0, 0, 0};
  TEST_ASSERT_FALSE(read(sizeof(trailing), trailing).has_value);

  uint8_t const truncated[] = {0x01, 0x01, 0, 0, COOKIE};
  TEST_ASSERT_FALSE(read(sizeof(truncated), truncated).has_value);
}

void packet_tests() {
  RUN_TEST(test_packet_binding_request);
  RUN_TEST(test_packet_response_v4);
  RUN_TEST(test_packet_response_v6);
  RUN_TEST(test_packet_response_skips_optional_attributes);
  RUN_TEST(test_packet_response_first_address_counts);
  RUN_TEST(test_packet_response_unknown_required_attribute);
  RUN_TEST(test_packet_response_without_address);
  RUN_TEST(test_packet_response_bad_address);
  RUN_TEST(test_packet_ignores_other_messages);
  RUN_TEST(test_packet_rejects_bad_lengths);
}
