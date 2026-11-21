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

static bool
stun_attribute_parse_xor_mapped_address(const_view_t value,
                                        stun_header_t const *header,
                                        stun_attribute_t *attribute) {
  struct stun_wire_xor_mapped_address address;
  if (stun_wire_xor_mapped_address_decode(&address, value.data, value.size) !=
      STUN_WIRE_OK) {
    return false;
  }

  // the cookie, then the transaction ID for the rest of an IPv6 address
  auto const id = &header->transaction_id;
  uint8_t key[STUN_MAGIC_COOKIE_SIZE + sizeof(id->bytes)];
  stun_store_be32(key, STUN_WIRE_MAGIC_COOKIE);
  memcpy(key + STUN_MAGIC_COOKIE_SIZE, id->bytes, sizeof(id->bytes));

  auto const out = &attribute->xor_mapped_address;
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
    return true;
  case STUN_WIRE_FAMILY_IPV6:
    for (size_t i = 0; i < sizeof(address.address.ipv6.addr); ++i) {
      out->ip.addr[i] = address.address.ipv6.addr[i] ^ key[i];
    }
    return true;
  default:
    return false;
  }
}

static bool stun_attribute_parse_error_code(const_view_t value,
                                            stun_header_t const *,
                                            stun_attribute_t *attribute) {
  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, value.data, value.size) !=
      STUN_WIRE_OK) {
    return false;
  }

  if (error.class < STUN_ERROR_CODE_CLASS_MIN ||
      error.class > STUN_ERROR_CODE_CLASS_MAX ||
      error.number >= STUN_ERROR_CODE_NUMBERS_PER_CLASS) {
    return false;
  }

  attribute->error_code =
      (uint16_t)(error.class * STUN_ERROR_CODE_NUMBERS_PER_CLASS +
                 error.number);
  return true;
}

typedef struct stun_attribute_descriptor {
  /// The type's code on the wire
  uint16_t code;
  /// Fills in the type's member of the union, or returns false if the value
  /// doesn't parse
  bool (*parse)(const_view_t value,
                stun_header_t const *header,
                stun_attribute_t *attribute);
} stun_attribute_descriptor_t;

// every type we know, at its value in stun_attribute_type_t
static stun_attribute_descriptor_t const
    STUN_ATTRIBUTES[STUN_ATTRIBUTE_TYPE_COUNT] = {
        [STUN_ATTRIBUTE_ERROR_CODE] = {0x0009, stun_attribute_parse_error_code},
        [STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS] =
            {0x0020, stun_attribute_parse_xor_mapped_address},
};

// the type with that code on the wire
static stun_attribute_type_t stun_attribute_type_of(uint16_t code) {
  for (size_t i = STUN_ATTRIBUTE_UNKNOWN + 1; i < STUN_ATTRIBUTE_TYPE_COUNT;
       ++i) {
    if (STUN_ATTRIBUTES[i].code == code) {
      // a type without a row would have code 0 and nothing to parse it
      assert(STUN_ATTRIBUTES[i].parse);
      return (stun_attribute_type_t)i;
    }
  }
  return STUN_ATTRIBUTE_UNKNOWN;
}

// one bit each in stun_attribute_reader_t::seen
static_assert(STUN_ATTRIBUTE_TYPE_COUNT <= 32);

static uint32_t stun_attribute_seen_bit(stun_attribute_type_t type) {
  return 1u << type;
}

// the types a message of its class and method has to carry, as their bits in
// stun_attribute_reader_t::seen
static uint32_t stun_attribute_required_by(stun_header_t const *header) {
  switch (header->message_class) {
  case STUN_CLASS_ERROR:
    return stun_attribute_seen_bit(STUN_ATTRIBUTE_ERROR_CODE);
  case STUN_CLASS_SUCCESS:
    switch (header->method) {
    case STUN_METHOD_BINDING:
      return stun_attribute_seen_bit(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
    default:
      return 0;
    }
  case STUN_CLASS_REQUEST:
  case STUN_CLASS_INDICATION:
    return 0;
  }
  return 0;
}

// types from here up are comprehension-optional
static constexpr uint16_t STUN_ATTRIBUTE_COMPREHENSION_OPTIONAL = 0x8000;

static bool stun_attribute_is_comprehension_required(uint16_t type) {
  return type < STUN_ATTRIBUTE_COMPREHENSION_OPTIONAL;
}

stun_attribute_reader_t stun_attribute_reader_init(stun_header_t const *header,
                                                   const_view_t attributes) {
  assert(header);
  assert(attributes.data);
  return (stun_attribute_reader_t){.header = *header, .remaining = attributes};
}

stun_attribute_read_result_t
stun_attribute_reader_next(stun_attribute_reader_t *reader) {
  assert(reader);

  auto const invalid =
      (stun_attribute_read_result_t){.status = STUN_ATTRIBUTE_READ_INVALID};

  auto const remaining = reader->remaining;
  if (remaining.size == 0) {
    auto const required = stun_attribute_required_by(&reader->header);
    if ((reader->seen & required) != required) {
      return invalid;
    }

    return (stun_attribute_read_result_t){.status = STUN_ATTRIBUTE_READ_END};
  }

  struct stun_wire_attribute_iter it = {
      .pos = remaining.data,
      .end = remaining.data + remaining.size,
  };
  struct stun_wire_attribute wire;
  if (!stun_wire_attribute_iter_next(&it, &wire)) {
    return invalid;
  }

  auto const consumed = (size_t)(it.pos - remaining.data);
  reader->remaining =
      (const_view_t){.size = remaining.size - consumed, .data = it.pos};

  auto const type = stun_attribute_type_of(wire.type);
  stun_attribute_t parsed = {.type = type};
  if (type == STUN_ATTRIBUTE_UNKNOWN) {
    if (stun_attribute_is_comprehension_required(wire.type)) {
      return invalid;
    }

    parsed.unknown.code = wire.type;
  } else {
    const_view_t const value = {.size = wire.value.len, .data = wire.value.ptr};
    if (!STUN_ATTRIBUTES[type].parse(value, &reader->header, &parsed)) {
      return invalid;
    }

    reader->seen |= stun_attribute_seen_bit(type);
  }

  return (stun_attribute_read_result_t){
      .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .attribute = parsed,
  };
}
