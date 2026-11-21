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
  stun_attribute_type_t type;
  /// Fills in the type's member of the union, or returns false if the value
  /// doesn't parse
  bool (*parse)(const_view_t value,
                stun_header_t const *header,
                stun_attribute_t *attribute);
} stun_attribute_descriptor_t;

// every type in stun_attribute_type_t
static stun_attribute_descriptor_t const STUN_ATTRIBUTES[] = {
    {STUN_ATTRIBUTE_ERROR_CODE, stun_attribute_parse_error_code},
    {STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
     stun_attribute_parse_xor_mapped_address},
};

static constexpr size_t STUN_ATTRIBUTE_COUNT =
    sizeof(STUN_ATTRIBUTES) / sizeof(STUN_ATTRIBUTES[0]);

// one bit each in stun_attribute_reader_t::seen
static_assert(STUN_ATTRIBUTE_COUNT <= 32);

// the type's row, or nullptr if we don't know it
static stun_attribute_descriptor_t const *
stun_attribute_describe(uint16_t type) {
  for (size_t i = 0; i < STUN_ATTRIBUTE_COUNT; ++i) {
    if (STUN_ATTRIBUTES[i].type == type) {
      return &STUN_ATTRIBUTES[i];
    }
  }
  return nullptr;
}

static uint32_t
stun_attribute_seen_bit(stun_attribute_descriptor_t const *descriptor) {
  return 1u << (descriptor - STUN_ATTRIBUTES);
}

static uint32_t stun_attribute_seen_bit_of(stun_attribute_type_t type) {
  auto const descriptor = stun_attribute_describe(type);
  assert(descriptor);
  return stun_attribute_seen_bit(descriptor);
}

// what a message of its class and method has to carry
static uint32_t stun_attribute_required(stun_header_t const *header) {
  switch (header->message_class) {
  case STUN_CLASS_ERROR:
    return stun_attribute_seen_bit_of(STUN_ATTRIBUTE_ERROR_CODE);
  case STUN_CLASS_SUCCESS:
    return header->method == STUN_METHOD_BINDING
               ? stun_attribute_seen_bit_of(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS)
               : 0;
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

stun_attribute_read_status_t
stun_attribute_reader_next(stun_attribute_reader_t *reader,
                           stun_attribute_t *attribute) {
  assert(reader);
  assert(attribute);

  auto const remaining = reader->remaining;
  if (remaining.size == 0) {
    auto const required = stun_attribute_required(&reader->header);
    return (reader->seen & required) == required ? STUN_ATTRIBUTE_READ_END
                                                 : STUN_ATTRIBUTE_READ_INVALID;
  }

  struct stun_wire_attribute_iter it = {
      .pos = remaining.data,
      .end = remaining.data + remaining.size,
  };
  struct stun_wire_attribute wire;
  if (!stun_wire_attribute_iter_next(&it, &wire)) {
    return STUN_ATTRIBUTE_READ_INVALID;
  }

  auto const consumed = (size_t)(it.pos - remaining.data);
  reader->remaining =
      (const_view_t){.size = remaining.size - consumed, .data = it.pos};

  stun_attribute_t parsed = {.type = wire.type};
  auto const descriptor = stun_attribute_describe(parsed.type);
  if (descriptor) {
    const_view_t const value = {.size = wire.value.len, .data = wire.value.ptr};
    if (!descriptor->parse(value, &reader->header, &parsed)) {
      return STUN_ATTRIBUTE_READ_INVALID;
    }

    reader->seen |= stun_attribute_seen_bit(descriptor);
  } else if (stun_attribute_is_comprehension_required(parsed.type)) {
    return STUN_ATTRIBUTE_READ_INVALID;
  }

  *attribute = parsed;
  return STUN_ATTRIBUTE_READ_ATTRIBUTE;
}
