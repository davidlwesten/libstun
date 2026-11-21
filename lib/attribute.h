#pragma once

#include <stdint.h>

#include "header.h"
#include "view.h"
#include <byo/stun/stun.h>

// Reading a message's attributes (RFC 8489) and giving them their meaning

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
  union {
    stun_socket_address_t xor_mapped_address;
    /// 300 to 699, without the reason phrase
    uint16_t error_code;
  };
} stun_attribute_t;

/**
 * @brief Reads a message's attributes in the order they came in
 *
 * Parses each one, and checks the message against the rules for its
 * attributes as it goes: no attribute may fail to decode or parse, none of the
 * comprehension-required ones may be of a type we don't know, and the message
 * has to carry what its class and method call for (an error response an
 * ERROR-CODE, a Binding success response an XOR-MAPPED-ADDRESS).
 */
typedef struct stun_attribute_reader {
  /// The message's, which parsing its attributes needs
  stun_header_t header;
  /// The attributes not read yet
  const_view_t remaining;
  /// The known types read so far, one bit each
  uint32_t seen;
} stun_attribute_reader_t;

typedef enum stun_attribute_read_status {
  /// The message breaks one of the rules
  STUN_ATTRIBUTE_READ_INVALID = 0,
  /// The next attribute was read
  STUN_ATTRIBUTE_READ_ATTRIBUTE,
  /// After the last attribute, and the message follows the rules
  STUN_ATTRIBUTE_READ_END,
} stun_attribute_read_status_t;

/**
 * @brief Start reading a message's attributes
 *
 * @param[in] header     The message's header
 * @param[in] attributes All of the message after its header
 */
stun_attribute_reader_t stun_attribute_reader_init(stun_header_t const *header,
                                                   const_view_t attributes);

/**
 * @brief Read the next attribute
 *
 * @param[in]  reader    The reader to advance
 * @param[out] attribute For STUN_ATTRIBUTE_READ_ATTRIBUTE, the attribute, with
 *                       its value in the union if its type is listed in
 *                       stun_attribute_type_t
 */
stun_attribute_read_status_t
stun_attribute_reader_next(stun_attribute_reader_t *reader,
                           stun_attribute_t *attribute);
