#include "message.h"

#include "stun_wire_gen.h"

#include <assert.h>
#include <string.h>

[[maybe_unused]] static constexpr stun_method_t METHOD_MAX = 0x0FFF;

// where the method's middle and high parts start, see Message in stun.pkt
static constexpr unsigned METHOD_MID_SHIFT = 4;
static constexpr unsigned METHOD_HIGH_SHIFT = 7;
static constexpr unsigned METHOD_LOW_MASK = (1u << METHOD_MID_SHIFT) - 1;
static constexpr unsigned METHOD_MID_MASK =
    (1u << (METHOD_HIGH_SHIFT - METHOD_MID_SHIFT)) - 1;

// what lets a result's `header` read a valid one's `message.header`
static_assert(offsetof(stun_message_t, header) == 0);

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
      .method = (stun_method_t)(wire.method_high << METHOD_HIGH_SHIFT |
                                wire.method_mid << METHOD_MID_SHIFT |
                                wire.method_low),
  };
  memcpy(header.transaction_id.bytes, wire.transaction_id,
         sizeof(header.transaction_id.bytes));

  // read every attribute only for the reader to check them against its rules,
  // ending in STUN_ATTRIBUTE_READ_END if the message follows all of them. The
  // attributes themselves are read again when iterating over the message.
  auto reader = stun_attribute_reader_init(&header, datagram);
  stun_attribute_read_result_t read;
  do {
    read = stun_attribute_reader_next(&reader);
  } while (read.status == STUN_ATTRIBUTE_READ_ATTRIBUTE);

  if (read.status == STUN_ATTRIBUTE_READ_NOT_STUN) {
    return (stun_message_parse_result_t){.status = STUN_MESSAGE_PARSE_NOT_STUN};
  }

  if (read.status == STUN_ATTRIBUTE_READ_INVALID) {
    return (stun_message_parse_result_t){
        .status = STUN_MESSAGE_PARSE_INVALID,
        .header = header,
    };
  }

  return (stun_message_parse_result_t){
      .status = STUN_MESSAGE_PARSE_VALID,
      .message = {.header = header, .datagram = datagram},
  };
}

size_t stun_message_write(view_t dst,
                          stun_class_t message_class,
                          stun_method_t method,
                          stun_transaction_id_t const *transaction_id) {
  assert(dst.data);
  assert(method <= METHOD_MAX);
  assert(transaction_id);

  auto const c = (unsigned)message_class;
  struct stun_wire_message message = {
      .method_high = (uint8_t)(method >> METHOD_HIGH_SHIFT),
      .class_high = (uint8_t)(c >> 1),
      .method_mid = (uint8_t)(method >> METHOD_MID_SHIFT & METHOD_MID_MASK),
      .class_low = (uint8_t)(c & 1),
      .method_low = (uint8_t)(method & METHOD_LOW_MASK),
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
      .reader = stun_attribute_reader_init(&message->header, message->datagram),
  };
}

stun_optional_attribute_t
stun_attribute_next(stun_attribute_iterator_t *iterator) {
  assert(iterator);

  auto const read = stun_attribute_reader_next(&iterator->reader);
  // stun_message_parse already read the whole message
  assert(read.status == STUN_ATTRIBUTE_READ_ATTRIBUTE ||
         read.status == STUN_ATTRIBUTE_READ_END);
  return (stun_optional_attribute_t){
      .has_value = read.status == STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .value = read.attribute,
  };
}

stun_optional_attribute_t
stun_message_find_attribute(stun_message_t const *message,
                            stun_attribute_type_t type) {
  assert(message);

  auto it = stun_message_attributes(message);
  for (auto next = stun_attribute_next(&it); next.has_value;
       next = stun_attribute_next(&it)) {
    if (next.value.type == type) {
      return next;
    }
  }

  return (stun_optional_attribute_t){};
}
