#include <unity.h>

#include "crc32.h"
#include "runner.h"

static uint32_t crc32_of(size_t size, uint8_t const data[]) {
  return stun_crc32((const_view_t){.size = size, .data = data});
}

static void test_crc32_check_value() {
  uint8_t const data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
  TEST_ASSERT_EQUAL_HEX32(0xCBF43926, crc32_of(sizeof(data), data));
}

static void test_crc32_residue() {
  // any message followed by its CRC, least significant byte first, gives
  // the same CRC
  uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', 0, 0, 0, 0};
  constexpr size_t MESSAGE_SIZE = sizeof(data) - sizeof(uint32_t);
  auto const crc = crc32_of(MESSAGE_SIZE, data);
  for (size_t i = 0; i < sizeof(uint32_t); ++i) {
    data[MESSAGE_SIZE + i] = (uint8_t)(crc >> (8 * i));
  }

  TEST_ASSERT_EQUAL_HEX32(0x2144DF1C, crc32_of(sizeof(data), data));
}

static void test_crc32_empty() {
  uint8_t const data[1] = {};
  TEST_ASSERT_EQUAL_HEX32(0, crc32_of(0, data));
}

static void test_crc32_rfc_5769_fingerprint() {
  // RFC 5769's sample IPv4 response, up to its FINGERPRINT, whose value is
  // the CRC of these bytes XORed with 0x5354554E
  uint8_t const data[] = {
      0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01,
      0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x0b,
      0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
      0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
      0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
      0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
  };
  TEST_ASSERT_EQUAL_HEX32(0xC07D4C96 ^ 0x5354554E,
                          crc32_of(sizeof(data), data));
}

void crc32_tests() {
  RUN_TEST(test_crc32_check_value);
  RUN_TEST(test_crc32_residue);
  RUN_TEST(test_crc32_empty);
  RUN_TEST(test_crc32_rfc_5769_fingerprint);
}
