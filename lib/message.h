#pragma once

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include <byo/stun/stun.h>

// STUN messages (RFC 8489) and their attributes, without any state: parsing
// and checking what's received, and writing what's sent

static constexpr size_t STUN_TRANSACTION_ID_SIZE = 12;

typedef struct stun_transaction_id {
  uint8_t bytes[STUN_TRANSACTION_ID_SIZE];
} stun_transaction_id_t;

typedef enum stun_class {
  STUN_CLASS_REQUEST = 0,
  STUN_CLASS_INDICATION = 1,
  STUN_CLASS_SUCCESS = 2,
  STUN_CLASS_ERROR = 3,
} stun_class_t;

/**
 * @brief Methods, 12 bits
 *
 * Messages can carry methods that aren't listed here, and they're passed on as
 * they are.
 */
typedef enum stun_method : uint16_t {
  STUN_METHOD_BINDING = 0x001,
} stun_method_t;

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

typedef struct stun_header {
  stun_class_t message_class;
  stun_method_t method;
  stun_transaction_id_t transaction_id;
} stun_header_t;

/**
 * @brief A valid message, pointing into the buffer it was parsed from
 *
 * Only stun_message_parse makes them, after checking all of it.
 */
typedef struct stun_message {
  stun_header_t header;
  /// All of it, header included. Read the attributes with
  /// stun_message_attributes.
  const_view_t datagram;
} stun_message_t;

typedef enum stun_parse_status {
  /// Not a STUN message, e.g. another protocol on the same socket
  STUN_PARSE_NOT_STUN,
  /// A STUN message we can't accept, e.g. with a comprehension-required
  /// attribute we don't know, a known one that doesn't parse, or without
  /// one its class and method call for
  STUN_PARSE_INVALID,
  STUN_PARSE_VALID,
} stun_parse_status_t;

typedef struct stun_parse_result {
  stun_parse_status_t status;
  union {
    /// For STUN_PARSE_INVALID, to tell which transaction it belongs to
    stun_header_t header;
    /// For STUN_PARSE_VALID
    stun_message_t message;
  };
} stun_parse_result_t;

/**
 * @brief Parse a datagram as a STUN message
 *
 * Checks the framing (the zero bits, the magic cookie, and lengths that add up
 * to exactly `datagram`) and every attribute: those listed in
 * stun_attribute_type_t have to parse, and others mustn't be
 * comprehension-required. Then checks the message carries what its class and
 * method call for: an error response an ERROR-CODE, and a Binding success
 * response an XOR-MAPPED-ADDRESS.
 */
stun_parse_result_t stun_message_parse(const_view_t datagram);

/**
 * @brief Write a message without attributes
 *
 * @param[in] dst            At least 20 bytes
 * @param[in] message_class  The message's class
 * @param[in] method         12 bits
 * @param[in] transaction_id The message's transaction ID
 *
 * @returns The size of the message
 */
size_t stun_message_write(view_t dst,
                          stun_class_t message_class,
                          stun_method_t method,
                          stun_transaction_id_t const *transaction_id);

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

typedef struct stun_attribute_iterator {
  /// All of the message, header included
  const_view_t datagram;
  /// Where the next attribute starts
  size_t offset;
} stun_attribute_iterator_t;

/**
 * @brief Iterate over a message's attributes in the order they came in
 */
stun_attribute_iterator_t
stun_message_attributes(stun_message_t const *message);

/**
 * @brief Get the next attribute
 *
 * @returns false after the last one
 */
bool stun_attribute_next(stun_attribute_iterator_t *iterator,
                         stun_attribute_t *attribute);
