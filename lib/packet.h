#pragma once

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include <byo/stun/stun.h>

// Reading and writing STUN messages on top of the generated codec, with the
// rules the schema can't express

typedef struct stun_transaction_id {
  uint8_t bytes[12];
} stun_transaction_id_t;

/**
 * @brief Write a Binding request without attributes
 *
 * @returns The size of the request
 */
size_t stun_packet_write_binding_request(view_t dst,
                                         stun_transaction_id_t const *id);

/**
 * @brief A Binding success response as far as a client cares about it
 */
typedef struct stun_binding_response {
  stun_transaction_id_t transaction_id;
  /// From XOR-MAPPED-ADDRESS, already un-XORed
  stun_socket_address_t mapped;
} stun_binding_response_t;

typedef struct stun_optional_binding_response {
  bool has_value;
  stun_binding_response_t value;
} stun_optional_binding_response_t;

/**
 * @brief Parse a datagram received from a STUN server
 *
 * @returns The response, or nothing if `src` isn't a valid Binding success
 *          response with an XOR-MAPPED-ADDRESS and should be ignored. That
 *          includes responses with comprehension-required attributes we don't
 *          know.
 */
stun_optional_binding_response_t stun_packet_read_response(const_view_t src);
