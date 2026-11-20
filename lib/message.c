#include "message.h"

#include "stun_wire_gen.h"
#include "validator.h"

#include <assert.h>
#include <string.h>

[[maybe_unused]] static constexpr stun_method_t STUN_METHOD_MAX = 0x0FFF;

// where the method's middle and high parts start, see Message in stun.pkt
static constexpr unsigned STUN_METHOD_MID_SHIFT = 4;
static constexpr unsigned STUN_METHOD_HIGH_SHIFT = 7;
static constexpr unsigned STUN_METHOD_LOW_MASK =
    (1u << STUN_METHOD_MID_SHIFT) - 1;
static constexpr unsigned STUN_METHOD_MID_MASK =
    (1u << (STUN_METHOD_HIGH_SHIFT - STUN_METHOD_MID_SHIFT)) - 1;

static constexpr size_t STUN_HEADER_SIZE = 20;

// decode the attribute at `offset`, moving past it, or false after the last
// one
static bool stun_attribute_read(const_view_t datagram,
                                size_t *offset,
                                struct stun_wire_attribute *wire) {
  assert(offset);
  assert(wire);

  if (*offset == datagram.size) {
    return false;
  }

  // the generated decoder already checked the attributes' framing
  struct stun_wire_attribute_iter it = {
      .pos = datagram.data + *offset,
      .end = datagram.data + datagram.size,
  };
  [[maybe_unused]] bool const read = stun_wire_attribute_iter_next(&it, wire);
  assert(read);
  *offset = (size_t)(it.pos - datagram.data);
  return true;
}

stun_message_parse_result_t stun_message_parse(const_view_t datagram) {
  assert(datagram.data);

  // the generated decoder checks the zero bits, the cookie and the lengths
  struct stun_wire_message wire;
  if (stun_wire_message_decode(&wire, datagram.data, datagram.size) !=
      STUN_WIRE_OK) {
    return (stun_message_parse_result_t){.status = STUN_MESSAGE_PARSE_NOT_STUN};
  }

  stun_header_t header = {
      .message_class = (stun_class_t)(wire.class_high << 1 | wire.class_low),
      .method = (stun_method_t)(wire.method_high << STUN_METHOD_HIGH_SHIFT |
                                wire.method_mid << STUN_METHOD_MID_SHIFT |
                                wire.method_low),
  };
  memcpy(header.transaction_id.bytes, wire.transaction_id,
         sizeof(header.transaction_id.bytes));

  auto const invalid =
      (stun_message_parse_result_t){.status = STUN_MESSAGE_PARSE_INVALID,
                                    .header = header};

  auto validator = stun_validator_begin(&header);
  size_t offset = STUN_HEADER_SIZE;
  struct stun_wire_attribute wire_attribute;
  while (stun_attribute_read(datagram, &offset, &wire_attribute)) {
    auto const parsed = stun_attribute_parse(&header, &wire_attribute);
    if (parsed.status == STUN_ATTRIBUTE_PARSE_INVALID ||
        !stun_validator_add(&validator, &parsed.attribute,
                            parsed.status == STUN_ATTRIBUTE_PARSE_KNOWN)) {
      return invalid;
    }
  }
  if (!stun_validator_end(&validator)) {
    return invalid;
  }

  return (stun_message_parse_result_t){
      .status = STUN_MESSAGE_PARSE_VALID,
      .header = header,
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

  auto const c = (unsigned)message_class;
  struct stun_wire_message message = {
      .method_high = (uint8_t)(method >> STUN_METHOD_HIGH_SHIFT),
      .class_high = (uint8_t)(c >> 1),
      .method_mid =
          (uint8_t)(method >> STUN_METHOD_MID_SHIFT & STUN_METHOD_MID_MASK),
      .class_low = (uint8_t)(c & 1),
      .method_low = (uint8_t)(method & STUN_METHOD_LOW_MASK),
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
      .header = message->header,
      .datagram = message->datagram,
      .offset = STUN_HEADER_SIZE,
  };
}

bool stun_attribute_next(stun_attribute_iterator_t *iterator,
                         stun_attribute_t *attribute) {
  assert(iterator);
  assert(attribute);

  struct stun_wire_attribute wire;
  if (!stun_attribute_read(iterator->datagram, &iterator->offset, &wire)) {
    return false;
  }
  auto const parsed = stun_attribute_parse(&iterator->header, &wire);
  // stun_message_parse already parsed every attribute
  assert(parsed.status != STUN_ATTRIBUTE_PARSE_INVALID);
  *attribute = parsed.attribute;
  return true;
}

bool stun_message_find_attribute(stun_message_t const *message,
                                 stun_attribute_type_t type,
                                 stun_attribute_t *attribute) {
  assert(message);
  assert(attribute);

  auto it = stun_message_attributes(message);
  while (stun_attribute_next(&it, attribute)) {
    if (attribute->type == type) {
      return true;
    }
  }
  return false;
}
