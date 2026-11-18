#include "message.h"

#include "stun_wire_gen.h"

#include <assert.h>
#include <string.h>

// The 14-bit type interleaves the method's bits M11-M0 with the class's C1-C0
// as M11-M7 C1 M6-M4 C0 M3-M0
static uint16_t stun_message_type(stun_class_t message_class, uint16_t method) {
  auto const c = (unsigned)message_class;
  return (uint16_t)((method & 0x000Fu) | (method & 0x0070u) << 1 |
                    (method & 0x0F80u) << 2 | (c & 1u) << 4 | (c & 2u) << 7);
}

stun_optional_message_t stun_message_parse(const_view_t src) {
  assert(src.data);

  stun_optional_message_t result = {.has_value = false};

  // the generated decoder checks the zero bits, the cookie and the lengths
  struct stun_wire_message message;
  if (stun_wire_message_decode(&message, src.data, src.size) != STUN_WIRE_OK) {
    return result;
  }

  auto const type = message.type;
  result.value = (stun_message_t){
      .message_class = (stun_class_t)((type >> 4 & 1) | (type >> 7 & 2)),
      .method = (uint16_t)((type & 0x000F) | (type & 0x00E0) >> 1 |
                           (type & 0x3E00) >> 2),
      .attributes = {.size = message.attributes.raw_len,
                     .data = message.attributes.raw},
  };
  memcpy(result.value.transaction_id.bytes, message.transaction_id,
         sizeof(result.value.transaction_id.bytes));
  result.has_value = true;
  return result;
}

size_t stun_message_write(view_t dst,
                          stun_class_t message_class,
                          uint16_t method,
                          stun_transaction_id_t const *transaction_id) {
  assert(dst.data);
  assert(method <= 0x0FFF);
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
  return (stun_attribute_iterator_t){.rest = message->attributes};
}

bool stun_attribute_next(stun_attribute_iterator_t *iterator,
                         stun_attribute_t *attribute) {
  assert(iterator);
  assert(attribute);

  // parsing the message already checked the attributes' framing
  struct stun_wire_attribute_iter it = {
      .pos = iterator->rest.data,
      .end = iterator->rest.data + iterator->rest.size,
  };
  struct stun_wire_attribute next;
  if (iterator->rest.size == 0 || !stun_wire_attribute_iter_next(&it, &next)) {
    return false;
  }

  *attribute = (stun_attribute_t){
      .type = next.type,
      .value = {.size = next.value.len, .data = next.value.ptr},
  };
  iterator->rest =
      (const_view_t){.size = (size_t)(it.end - it.pos), .data = it.pos};
  return true;
}

bool stun_attribute_is_comprehension_required(uint16_t type) {
  return type < 0x8000;
}

stun_optional_socket_address_t stun_attribute_read_xor_mapped_address(
    stun_attribute_t const *attribute,
    stun_transaction_id_t const *transaction_id) {
  assert(attribute);
  assert(attribute->type == STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS);
  assert(transaction_id);

  stun_optional_socket_address_t result = {.has_value = false};

  struct stun_wire_xor_mapped_address address;
  if (stun_wire_xor_mapped_address_decode(&address, attribute->value.data,
                                          attribute->value.size) !=
      STUN_WIRE_OK) {
    return result;
  }

  // the cookie, then the transaction ID for the rest of an IPv6 address
  uint8_t key[16] = {
      STUN_WIRE_MAGIC_COOKIE >> 24,
      (STUN_WIRE_MAGIC_COOKIE >> 16) & 0xFF,
      (STUN_WIRE_MAGIC_COOKIE >> 8) & 0xFF,
      STUN_WIRE_MAGIC_COOKIE & 0xFF,
  };
  memcpy(key + 4, transaction_id->bytes, sizeof(transaction_id->bytes));

  auto const out = &result.value;
  out->port = address.port ^ (uint16_t)(STUN_WIRE_MAGIC_COOKIE >> 16);
  switch (address.family) {
  case STUN_WIRE_FAMILY_IPV4:
    memset(out->ip.addr, 0, 10);
    out->ip.addr[10] = 0xFF;
    out->ip.addr[11] = 0xFF;
    for (size_t i = 0; i < 4; ++i) {
      out->ip.addr[12 + i] = address.address.ipv4.addr[i] ^ key[i];
    }
    break;
  case STUN_WIRE_FAMILY_IPV6:
    for (size_t i = 0; i < 16; ++i) {
      out->ip.addr[i] = address.address.ipv6.addr[i] ^ key[i];
    }
    break;
  default:
    return result;
  }
  result.has_value = true;
  return result;
}

stun_optional_error_code_t
stun_attribute_read_error_code(stun_attribute_t const *attribute) {
  assert(attribute);
  assert(attribute->type == STUN_ATTRIBUTE_ERROR_CODE);

  stun_optional_error_code_t result = {.has_value = false};

  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, attribute->value.data,
                                  attribute->value.size) != STUN_WIRE_OK) {
    return result;
  }
  if (error.class < 3 || error.class > 6 || error.number > 99) {
    return result;
  }

  result.value = (uint16_t)(error.class * 100 + error.number);
  result.has_value = true;
  return result;
}
