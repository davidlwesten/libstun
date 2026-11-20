#pragma once

#include <stdint.h>

#include "header.h"
#include "view.h"
#include <byo/stun/stun.h>

// Giving one decoded attribute (RFC 8489) its meaning

/**
 * @brief Attribute types
 *
 * Messages can carry types that aren't listed here, and they're passed on as
 * they are.
 */
typedef enum stun_attribute_type : uint16_t {
  STUN_ATTRIBUTE_ERROR_CODE = 0x0009,
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS = 0x0020,
} stun_attribute_type_t;

/**
 * @brief An attribute, parsed if its type is listed in stun_attribute_type_t
 */
typedef struct stun_attribute {
  stun_attribute_type_t type;
  /// Without the padding
  const_view_t value;
  union {
    stun_socket_address_t xor_mapped_address;
    /// 300 to 699, without the reason phrase
    uint16_t error_code;
  };
} stun_attribute_t;

typedef enum stun_attribute_parse_status {
  /// Of a type we know, with its value in the union
  STUN_ATTRIBUTE_PARSE_KNOWN,
  STUN_ATTRIBUTE_PARSE_UNKNOWN,
  /// Of a type we know, but the value doesn't parse
  STUN_ATTRIBUTE_PARSE_INVALID,
} stun_attribute_parse_status_t;

typedef struct stun_attribute_parse_result {
  stun_attribute_parse_status_t status;
  /// Its type and value whatever the status, and the union if it's KNOWN
  stun_attribute_t attribute;
} stun_attribute_parse_result_t;

struct stun_wire_attribute;

/**
 * @brief Parse a decoded attribute
 *
 * @param[in] header The header of the message it came in
 * @param[in] wire   The attribute as decoded
 */
stun_attribute_parse_result_t
stun_attribute_parse(stun_header_t const *header,
                     struct stun_wire_attribute const *wire);
