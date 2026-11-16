#include "packet.h"

#include "stun_gen.h"

#include <assert.h>
#include <string.h>

size_t stun_packet_write_binding_request(view_t dst,
                                         stun_transaction_id_t const *id) {
  assert(dst.data);
  assert(id);

  struct stun_message request = {.type = STUN_TYPE_BINDING_REQUEST};
  memcpy(request.transaction_id, id->bytes, sizeof(request.transaction_id));

  size_t written = 0;
  [[maybe_unused]] auto const status =
      stun_message_encode(&request, dst.data, dst.size, &written);
  assert(status == STUN_OK);

  return written;
}

// Section 14: types below 0x8000 have to be understood
static bool is_comprehension_required(enum stun_attribute_type type) {
  return type < 0x8000;
}

static bool read_xor_mapped_address(stun_socket_address_t *out,
                                    struct stun_bytes value,
                                    uint8_t const transaction_id[12]) {
  struct stun_xor_mapped_address address;
  if (stun_xor_mapped_address_decode(&address, value.ptr, value.len) !=
      STUN_OK) {
    return false;
  }

  // the cookie, then the transaction ID for the rest of an IPv6 address
  uint8_t key[16] = {
      STUN_MAGIC_COOKIE >> 24,
      (STUN_MAGIC_COOKIE >> 16) & 0xFF,
      (STUN_MAGIC_COOKIE >> 8) & 0xFF,
      STUN_MAGIC_COOKIE & 0xFF,
  };
  memcpy(key + 4, transaction_id, 12);

  out->port = address.port ^ (uint16_t)(STUN_MAGIC_COOKIE >> 16);
  switch (address.family) {
  case STUN_FAMILY_IPV4:
    memset(out->ip.addr, 0, 10);
    out->ip.addr[10] = 0xFF;
    out->ip.addr[11] = 0xFF;
    for (size_t i = 0; i < 4; ++i) {
      out->ip.addr[12 + i] = address.address.ipv4.addr[i] ^ key[i];
    }
    return true;
  case STUN_FAMILY_IPV6:
    for (size_t i = 0; i < 16; ++i) {
      out->ip.addr[i] = address.address.ipv6.addr[i] ^ key[i];
    }
    return true;
  }
  return false;
}

stun_optional_binding_response_t stun_packet_read_response(const_view_t src) {
  assert(src.data);

  stun_optional_binding_response_t result = {.has_value = false};

  // the generated decoder checks the cookie, the zero bits and the lengths
  struct stun_message message;
  if (stun_message_decode(&message, src.data, src.size) != STUN_OK ||
      message.type != STUN_TYPE_BINDING_SUCCESS) {
    return result;
  }

  auto const out = &result.value;
  memcpy(out->transaction_id.bytes, message.transaction_id,
         sizeof(out->transaction_id.bytes));

  // only the first XOR-MAPPED-ADDRESS counts (section 14)
  bool mapped = false;
  struct stun_attribute_iter it;
  stun_attribute_iter_init(&it, &message.attributes);
  struct stun_attribute attribute;
  while (stun_attribute_iter_next(&it, &attribute)) {
    if (attribute.type == STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS) {
      if (!mapped && !read_xor_mapped_address(&out->mapped, attribute.value,
                                              message.transaction_id)) {
        return result;
      }
      mapped = true;
    } else if (is_comprehension_required(attribute.type)) {
      return result;
    }
  }

  result.has_value = mapped;
  return result;
}
