#include "attribute.h"

#include "attributes/attributes.h"
#include "stun_wire_gen.h"
#include "view.h"

#include <assert.h>

// what `attribute` means, or STUN_ATTRIBUTE_READ_INVALID if it doesn't parse
typedef stun_attribute_read_result_t
parser_t(stun_wire_attribute_t const *attribute,
         stun_attribute_reader_t const *reader);

typedef struct descriptor {
  parser_t *parse;
} descriptor_t;

// every type we know, at its value in stun_attribute_type_t
static descriptor_t const DESCRIPTORS[STUN_ATTRIBUTE_TYPE_COUNT] = {
    [STUN_ATTRIBUTE_ERROR_CODE] =
        {
            stun_attribute_parse_error_code,
        },
    [STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS] =
        {
            stun_attribute_parse_xor_mapped_address,
        },
    [STUN_ATTRIBUTE_FINGERPRINT] =
        {
            stun_attribute_parse_fingerprint,
        },
};

// which of our types a type on the wire is
static stun_attribute_type_t type_from_wire(uint16_t wire_type) {
  switch (wire_type) {
  case STUN_WIRE_ATTRIBUTE_TYPE_ERROR_CODE:
    return STUN_ATTRIBUTE_ERROR_CODE;
  case STUN_WIRE_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
    return STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS;
  case STUN_WIRE_ATTRIBUTE_TYPE_FINGERPRINT:
    return STUN_ATTRIBUTE_FINGERPRINT;
  default:
    return STUN_ATTRIBUTE_UNKNOWN;
  }
}

static uint32_t seen_bit(stun_attribute_type_t type) {
  // one bit each in stun_attribute_reader_t::seen
  static_assert(STUN_ATTRIBUTE_TYPE_COUNT <= 32);
  return 1u << type;
}

// the types a message of its class and method has to carry, as their bits in
// stun_attribute_reader_t::seen
static uint32_t required_by(stun_header_t const *header) {
  switch (header->message_class) {
  case STUN_CLASS_ERROR:
    return seen_bit(STUN_ATTRIBUTE_ERROR_CODE);
  case STUN_CLASS_SUCCESS:
    switch (header->method) {
    case STUN_METHOD_BINDING:
      return seen_bit(STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
    default:
      return 0;
    }
  case STUN_CLASS_REQUEST:
  case STUN_CLASS_INDICATION:
    return 0;
  }
  return 0;
}

static bool is_comprehension_required(uint16_t wire_type) {
  // types from here up are comprehension-optional
  constexpr uint16_t COMPREHENSION_OPTIONAL = 0x8000;
  return wire_type < COMPREHENSION_OPTIONAL;
}

stun_attribute_reader_t stun_attribute_reader_init(stun_header_t const *header,
                                                   const_view_t message) {
  assert(header);
  assert(message.data);
  assert(message.size >= STUN_HEADER_SIZE);
  return (stun_attribute_reader_t){
      .header = *header,
      .message = message,
      .offset = STUN_HEADER_SIZE,
  };
}

stun_attribute_read_result_t
stun_attribute_reader_next(stun_attribute_reader_t *reader) {
  assert(reader);

  auto const message = reader->message;
  assert(reader->offset <= message.size);

  // check if we've read all attributes and have seen all the required ones
  if (reader->offset == message.size) {
    auto const required = required_by(&reader->header);
    if ((reader->seen & required) != required) {
      return STUN_INVALID_READ_RESULT;
    }

    return (stun_attribute_read_result_t){.status = STUN_ATTRIBUTE_READ_END};
  }

  // nothing may follow a FINGERPRINT
  if (reader->seen & seen_bit(STUN_ATTRIBUTE_FINGERPRINT)) {
    return STUN_INVALID_READ_RESULT;
  }

  // frame the attribute at `offset`: its type and length come first, and the
  // length says where its value ends and, with the padding, where the next
  // attribute starts. This only fails if it runs past the end.
  struct stun_wire_attribute_iter it = {.pos = message.data + reader->offset,
                                        .end = message.data + message.size};
  stun_wire_attribute_t wire;
  if (!stun_wire_attribute_iter_next(&it, &wire)) {
    return STUN_INVALID_READ_RESULT;
  }

  // where the next attribute starts. `offset` moves there only once this one
  // has been read, so a parser sees `offset` at its own attribute.
  auto const next = (size_t)(it.pos - message.data);

  // there's nothing to parse a type we don't know with. Only optional ones
  // can be skipped, and they're passed on with just their wire type.
  auto const type = type_from_wire(wire.type);
  if (type == STUN_ATTRIBUTE_UNKNOWN) {
    if (is_comprehension_required(wire.type)) {
      return STUN_INVALID_READ_RESULT;
    }

    reader->offset = next;
    return (stun_attribute_read_result_t){
        .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
        .attribute =
            {
                .type = type,
                .unknown = {.wire_type = wire.type},
            },
    };
  }

  auto const result = DESCRIPTORS[type].parse(&wire, reader);
  if (result.status != STUN_ATTRIBUTE_READ_ATTRIBUTE) {
    return result;
  }

  reader->offset = next;
  // recorded for the checks after the last attribute
  reader->seen |= seen_bit(type);
  return result;
}
