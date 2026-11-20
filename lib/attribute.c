#include "attribute.h"

#include "stun_wire_gen.h"
#include "view.h"

#include <assert.h>
#include <string.h>

static constexpr size_t STUN_MAGIC_COOKIE_SIZE = sizeof(uint32_t);

// ::ffff:0:0/96, followed by the IPv4 address
static constexpr uint8_t STUN_IPV4_MAPPED_PREFIX[12] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF,
};

// error codes are class * 100 + number
static constexpr uint8_t STUN_ERROR_CODE_CLASS_MIN = 3;
static constexpr uint8_t STUN_ERROR_CODE_CLASS_MAX = 6;
static constexpr uint8_t STUN_ERROR_CODE_NUMBERS_PER_CLASS = 100;

static void stun_store_be32(uint8_t out[static 4], uint32_t value) {
  out[0] = (uint8_t)(value >> 24);
  out[1] = (uint8_t)(value >> 16);
  out[2] = (uint8_t)(value >> 8);
  out[3] = (uint8_t)value;
}

static stun_attribute_parse_status_t
stun_attribute_parse_xor_mapped_address(const_view_t value,
                                        stun_transaction_id_t const *id,
                                        stun_socket_address_t *out) {
  struct stun_wire_xor_mapped_address address;
  if (stun_wire_xor_mapped_address_decode(&address, value.data, value.size) !=
      STUN_WIRE_OK) {
    return STUN_ATTRIBUTE_PARSE_INVALID;
  }

  // the cookie, then the transaction ID for the rest of an IPv6 address
  uint8_t key[STUN_MAGIC_COOKIE_SIZE + sizeof(id->bytes)];
  stun_store_be32(key, STUN_WIRE_MAGIC_COOKIE);
  memcpy(key + STUN_MAGIC_COOKIE_SIZE, id->bytes, sizeof(id->bytes));
  static_assert(sizeof(key) == sizeof(out->ip.addr));

  out->port = address.port ^ (uint16_t)(STUN_WIRE_MAGIC_COOKIE >> 16);
  switch (address.family) {
  case STUN_WIRE_FAMILY_IPV4:
    static_assert(sizeof(STUN_IPV4_MAPPED_PREFIX) +
                      sizeof(address.address.ipv4.addr) ==
                  sizeof(out->ip.addr));
    memcpy(out->ip.addr, STUN_IPV4_MAPPED_PREFIX,
           sizeof(STUN_IPV4_MAPPED_PREFIX));
    for (size_t i = 0; i < sizeof(address.address.ipv4.addr); ++i) {
      out->ip.addr[sizeof(STUN_IPV4_MAPPED_PREFIX) + i] =
          address.address.ipv4.addr[i] ^ key[i];
    }
    return STUN_ATTRIBUTE_PARSE_KNOWN;
  case STUN_WIRE_FAMILY_IPV6:
    for (size_t i = 0; i < sizeof(address.address.ipv6.addr); ++i) {
      out->ip.addr[i] = address.address.ipv6.addr[i] ^ key[i];
    }
    return STUN_ATTRIBUTE_PARSE_KNOWN;
  default:
    return STUN_ATTRIBUTE_PARSE_INVALID;
  }
}

static stun_attribute_parse_status_t
stun_attribute_parse_error_code(const_view_t value, uint16_t *out) {
  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, value.data, value.size) !=
      STUN_WIRE_OK) {
    return STUN_ATTRIBUTE_PARSE_INVALID;
  }

  if (error.class < STUN_ERROR_CODE_CLASS_MIN ||
      error.class > STUN_ERROR_CODE_CLASS_MAX ||
      error.number >= STUN_ERROR_CODE_NUMBERS_PER_CLASS) {
    return STUN_ATTRIBUTE_PARSE_INVALID;
  }

  *out = (uint16_t)(error.class * STUN_ERROR_CODE_NUMBERS_PER_CLASS +
                    error.number);
  return STUN_ATTRIBUTE_PARSE_KNOWN;
}

stun_attribute_parse_result_t
stun_attribute_parse(stun_header_t const *header,
                     struct stun_wire_attribute const *wire) {
  assert(header);
  assert(wire);

  stun_attribute_parse_result_t result = {.attribute = {.type = wire->type}};
  auto const attribute = &result.attribute;
  const_view_t const value = {.size = wire->value.len, .data = wire->value.ptr};
  switch (attribute->type) {
  case STUN_ATTRIBUTE_ERROR_CODE:
    result.status =
        stun_attribute_parse_error_code(value, &attribute->error_code);
    break;
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    result.status = stun_attribute_parse_xor_mapped_address(
        value, &header->transaction_id, &attribute->xor_mapped_address);
    break;
  default:
    result.status = STUN_ATTRIBUTE_PARSE_UNKNOWN;
    break;
  }
  return result;
}
