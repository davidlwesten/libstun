#include "message.h"

#include "stun_wire_gen.h"
#include "validator.h"

#include <assert.h>
#include <string.h>

// The 14-bit type interleaves the method's bits M11-M0 with the class's C1-C0
// as M11-M7 C1 M6-M4 C0 M3-M0
static uint16_t stun_message_type(stun_class_t message_class,
                                  stun_method_t method) {
  auto const c = (unsigned)message_class;
  return (uint16_t)((method & 0x000Fu) | (method & 0x0070u) << 1 |
                    (method & 0x0F80u) << 2 | (c & 1u) << 4 | (c & 2u) << 7);
}

[[maybe_unused]] static constexpr stun_method_t STUN_METHOD_MAX = 0x0FFF;

// the header, which ends with the transaction ID
static constexpr size_t STUN_HEADER_SIZE = 20;
static constexpr size_t STUN_TRANSACTION_ID_OFFSET =
    STUN_HEADER_SIZE - STUN_TRANSACTION_ID_SIZE;

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

typedef enum stun_decode_status {
  /// Of a type we know, with its value in the union
  STUN_DECODE_KNOWN,
  STUN_DECODE_UNKNOWN,
  /// Of a type we know, but the value doesn't decode
  STUN_DECODE_INVALID,
} stun_decode_status_t;

static stun_decode_status_t stun_attribute_decode_xor_mapped_address(
    const_view_t value,
    uint8_t const transaction_id[STUN_TRANSACTION_ID_SIZE],
    stun_socket_address_t *out) {
  struct stun_wire_xor_mapped_address address;
  if (stun_wire_xor_mapped_address_decode(&address, value.data, value.size) !=
      STUN_WIRE_OK) {
    return STUN_DECODE_INVALID;
  }

  // the cookie, then the transaction ID for the rest of an IPv6 address
  uint8_t key[STUN_MAGIC_COOKIE_SIZE + STUN_TRANSACTION_ID_SIZE];
  stun_store_be32(key, STUN_WIRE_MAGIC_COOKIE);
  memcpy(key + STUN_MAGIC_COOKIE_SIZE, transaction_id,
         STUN_TRANSACTION_ID_SIZE);
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
    return STUN_DECODE_KNOWN;
  case STUN_WIRE_FAMILY_IPV6:
    for (size_t i = 0; i < sizeof(address.address.ipv6.addr); ++i) {
      out->ip.addr[i] = address.address.ipv6.addr[i] ^ key[i];
    }
    return STUN_DECODE_KNOWN;
  default:
    return STUN_DECODE_INVALID;
  }
}

static stun_decode_status_t stun_attribute_decode_error_code(const_view_t value,
                                                             uint16_t *out) {
  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, value.data, value.size) !=
      STUN_WIRE_OK) {
    return STUN_DECODE_INVALID;
  }
  if (error.class < STUN_ERROR_CODE_CLASS_MIN ||
      error.class > STUN_ERROR_CODE_CLASS_MAX ||
      error.number >= STUN_ERROR_CODE_NUMBERS_PER_CLASS) {
    return STUN_DECODE_INVALID;
  }

  *out = (uint16_t)(error.class * STUN_ERROR_CODE_NUMBERS_PER_CLASS +
                    error.number);
  return STUN_DECODE_KNOWN;
}

// the attribute at `offset`, moving past it, or false after the last one
static bool stun_attribute_read(const_view_t datagram,
                                size_t *offset,
                                stun_attribute_t *attribute) {
  if (*offset == datagram.size) {
    return false;
  }

  // the generated decoder already checked the attributes' framing
  struct stun_wire_attribute_iter it = {
      .pos = datagram.data + *offset,
      .end = datagram.data + datagram.size,
  };
  struct stun_wire_attribute next;
  [[maybe_unused]] bool const read = stun_wire_attribute_iter_next(&it, &next);
  assert(read);
  *offset = (size_t)(it.pos - datagram.data);

  *attribute = (stun_attribute_t){
      .type = next.type,
      .value = {.size = next.value.len, .data = next.value.ptr},
  };
  return true;
}

static stun_decode_status_t stun_attribute_decode(const_view_t datagram,
                                                  stun_attribute_t *attribute) {
  switch (attribute->type) {
  case STUN_ATTRIBUTE_ERROR_CODE:
    return stun_attribute_decode_error_code(attribute->value,
                                            &attribute->error_code);
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    return stun_attribute_decode_xor_mapped_address(
        attribute->value, datagram.data + STUN_TRANSACTION_ID_OFFSET,
        &attribute->xor_mapped_address);
  default:
    return STUN_DECODE_UNKNOWN;
  }
}

stun_parse_result_t stun_message_parse(const_view_t datagram) {
  assert(datagram.data);

  // the generated decoder checks the zero bits, the cookie and the lengths
  struct stun_wire_message wire;
  if (stun_wire_message_decode(&wire, datagram.data, datagram.size) !=
      STUN_WIRE_OK) {
    return (stun_parse_result_t){.status = STUN_PARSE_NOT_STUN};
  }

  auto const type = wire.type;
  stun_header_t header = {
      .message_class = (stun_class_t)((type >> 4 & 1) | (type >> 7 & 2)),
      .method = (stun_method_t)((type & 0x000F) | (type & 0x00E0) >> 1 |
                                (type & 0x3E00) >> 2),
  };
  memcpy(header.transaction_id.bytes, wire.transaction_id,
         sizeof(header.transaction_id.bytes));

  auto const invalid =
      (stun_parse_result_t){.status = STUN_PARSE_INVALID, .header = header};

  auto validator = stun_validator_begin(&header);
  size_t offset = STUN_HEADER_SIZE;
  stun_attribute_t attribute;
  while (stun_attribute_read(datagram, &offset, &attribute)) {
    auto const status = stun_attribute_decode(datagram, &attribute);
    if (status == STUN_DECODE_INVALID ||
        !stun_validator_add(&validator, &attribute,
                            status == STUN_DECODE_KNOWN)) {
      return invalid;
    }
  }
  if (!stun_validator_end(&validator)) {
    return invalid;
  }

  return (stun_parse_result_t){
      .status = STUN_PARSE_VALID,
      .message = {.header = header, .datagram = datagram},
  };
}

size_t stun_message_write(view_t dst,
                          stun_class_t message_class,
                          stun_method_t method,
                          stun_transaction_id_t const *transaction_id) {
  assert(dst.data);
  assert(method <= STUN_METHOD_MAX);
  assert(transaction_id);

  struct stun_wire_message message = {
      .type = stun_message_type(message_class, method),
  };
  memcpy(message.transaction_id, transaction_id->bytes,
         sizeof(message.transaction_id));

  size_t written = 0;
  [[maybe_unused]] auto const status =
      stun_wire_message_encode(&message, dst.data, dst.size, &written);
  assert(status == STUN_WIRE_OK);

  return written;
}

stun_attribute_iterator_t
stun_message_attributes(stun_message_t const *message) {
  assert(message);
  return (stun_attribute_iterator_t){
      .datagram = message->datagram,
      .offset = STUN_HEADER_SIZE,
  };
}

bool stun_attribute_next(stun_attribute_iterator_t *iterator,
                         stun_attribute_t *attribute) {
  assert(iterator);
  assert(attribute);

  if (!stun_attribute_read(iterator->datagram, &iterator->offset, attribute)) {
    return false;
  }
  [[maybe_unused]] auto const status =
      stun_attribute_decode(iterator->datagram, attribute);
  // parsing the message already decoded every attribute
  assert(status != STUN_DECODE_INVALID);
  return true;
}
