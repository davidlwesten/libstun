#include "attributes.h"

#include "stun_wire_gen.h"

#include <string.h>

static constexpr size_t MAGIC_COOKIE_SIZE = sizeof(uint32_t);
static constexpr size_t IPV4_SIZE = 4;
static constexpr size_t IPV6_SIZE = 16;

// what XOR-MAPPED-ADDRESS's address is XORed with: the magic cookie, then the
// transaction ID, which only an IPv6 address is long enough to reach
static constexpr size_t XOR_KEY_SIZE =
    MAGIC_COOKIE_SIZE + STUN_TRANSACTION_ID_SIZE;
static_assert(XOR_KEY_SIZE == IPV6_SIZE);

// ::ffff:0:0/96, followed by the IPv4 address
static constexpr uint8_t IPV4_MAPPED_PREFIX[12] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF,
};
static_assert(sizeof(IPV4_MAPPED_PREFIX) + IPV4_SIZE == IPV6_SIZE);
static_assert(sizeof((stun_ip_address_t){}.addr) == IPV6_SIZE);

static void store_be32(uint8_t out[static 4], uint32_t value) {
  out[0] = (uint8_t)(value >> 24);
  out[1] = (uint8_t)(value >> 16);
  out[2] = (uint8_t)(value >> 8);
  out[3] = (uint8_t)value;
}

static void fill_xor_key(stun_transaction_id_t const *transaction_id,
                         uint8_t key[static XOR_KEY_SIZE]) {
  store_be32(key, STUN_WIRE_MAGIC_COOKIE);
  memcpy(key + MAGIC_COOKIE_SIZE, transaction_id->bytes,
         STUN_TRANSACTION_ID_SIZE);
}

static void xor_bytes(size_t size,
                      uint8_t out[size],
                      uint8_t const in[size],
                      uint8_t const key[size]) {
  for (size_t i = 0; i < size; ++i) {
    out[i] = in[i] ^ key[i];
  }
}

stun_attribute_read_result_t
stun_attribute_parse_xor_mapped_address(stun_wire_attribute_t const *attribute,
                                        stun_attribute_reader_t const *reader) {
  struct stun_wire_xor_mapped_address wire;
  if (stun_wire_xor_mapped_address_decode(
          &wire, attribute->value.ptr, attribute->value.len) != STUN_WIRE_OK) {
    return STUN_INVALID_READ_RESULT;
  }

  uint8_t key[XOR_KEY_SIZE];
  fill_xor_key(&reader->header.transaction_id, key);

  // the port is XORed with the cookie's first half
  stun_socket_address_t address = {
      .port = wire.port ^ (uint16_t)(STUN_WIRE_MAGIC_COOKIE >> 16),
  };

  switch (wire.family) {
  case STUN_WIRE_FAMILY_IPV4:
    memcpy(address.ip.addr, IPV4_MAPPED_PREFIX, sizeof(IPV4_MAPPED_PREFIX));
    xor_bytes(IPV4_SIZE, address.ip.addr + sizeof(IPV4_MAPPED_PREFIX),
              wire.address.ipv4.addr, key);
    break;
  case STUN_WIRE_FAMILY_IPV6:
    xor_bytes(IPV6_SIZE, address.ip.addr, wire.address.ipv6.addr, key);
    break;
  default:
    return STUN_INVALID_READ_RESULT;
  }

  return (stun_attribute_read_result_t){
      .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .attribute =
          {
              .type = STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
              .xor_mapped_address = address,
          },
  };
}
