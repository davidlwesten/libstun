#include "attribute.h"

#include "attributes/attributes.h"
#include "stun_wire_gen.h"
#include "view.h"

#include <assert.h>

typedef struct stun_attribute_descriptor {
  /// The attribute of this type that `value` holds, or
  /// STUN_ATTRIBUTE_READ_INVALID if it doesn't parse
  stun_attribute_read_result_t (*parse)(const_view_t value,
                                        stun_header_t const *header);
} stun_attribute_descriptor_t;

// every type we know, at its value in stun_attribute_type_t
static stun_attribute_descriptor_t const
    STUN_ATTRIBUTES[STUN_ATTRIBUTE_TYPE_COUNT] = {
        [STUN_ATTRIBUTE_ERROR_CODE] =
            {
                stun_attribute_parse_error_code,
            },
        [STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS] =
            {
                stun_attribute_parse_xor_mapped_address,
            },
};

// which of our types a type on the wire is
static stun_attribute_type_t stun_attribute_type_of(uint16_t wire_type) {
  switch (wire_type) {
  case STUN_WIRE_ATTRIBUTE_TYPE_ERROR_CODE:
    return STUN_ATTRIBUTE_ERROR_CODE;
  case STUN_WIRE_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
    return STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS;
  default:
    return STUN_ATTRIBUTE_UNKNOWN;
  }
}

static uint32_t stun_attribute_seen_bit(stun_attribute_type_t type) {
  // one bit each in stun_attribute_reader_t::seen
  static_assert(STUN_ATTRIBUTE_TYPE_COUNT <= 32);
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

static bool stun_attribute_is_comprehension_required(uint16_t wire_type) {
  // types from here up are comprehension-optional
  constexpr uint16_t STUN_ATTRIBUTE_COMPREHENSION_OPTIONAL = 0x8000;
  return wire_type < STUN_ATTRIBUTE_COMPREHENSION_OPTIONAL;
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

  auto const remaining = reader->remaining;
  if (remaining.size == 0) {
    auto const required = stun_attribute_required_by(&reader->header);
    if ((reader->seen & required) != required) {
      return STUN_INVALID_READ_RESULT;
    }

    return (stun_attribute_read_result_t){.status = STUN_ATTRIBUTE_READ_END};
  }

  struct stun_wire_attribute_iter it = {.pos = remaining.data,
                                        .end = remaining.data + remaining.size};
  struct stun_wire_attribute wire;
  if (!stun_wire_attribute_iter_next(&it, &wire)) {
    return STUN_INVALID_READ_RESULT;
  }

  reader->remaining =
      (const_view_t){.size = (size_t)(it.end - it.pos), .data = it.pos};

  auto const type = stun_attribute_type_of(wire.type);
  if (type == STUN_ATTRIBUTE_UNKNOWN) {
    return stun_attribute_is_comprehension_required(wire.type)
               ? STUN_INVALID_READ_RESULT
               : (stun_attribute_read_result_t){
                     .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
                     .attribute =
                         {
                             .type = type,
                             .unknown = {.wire_type = wire.type},
                         },
                 };
  }

  const_view_t const value = {.size = wire.value.len, .data = wire.value.ptr};
  // a type without a row would have nothing to parse it
  assert(STUN_ATTRIBUTES[type].parse);
  auto const result = STUN_ATTRIBUTES[type].parse(value, &reader->header);
  if (result.status == STUN_ATTRIBUTE_READ_ATTRIBUTE) {
    assert(result.attribute.type == type);
    reader->seen |= stun_attribute_seen_bit(type);
  }

  return result;
}
