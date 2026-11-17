#pragma once

#include <stddef.h>
#include <stdint.h>

#include "view.h"
#include <byo/stun/stun.h>

// STUN messages (RFC 8489) and their attributes, without any state: parsing
// what's received, reading the attributes, and writing what's sent

typedef struct stun_transaction_id {
  uint8_t bytes[12];
} stun_transaction_id_t;

/**
 * @brief A message's class (section 5)
 */
typedef enum stun_class {
  STUN_CLASS_REQUEST = 0,
  STUN_CLASS_INDICATION = 1,
  STUN_CLASS_SUCCESS = 2,
  STUN_CLASS_ERROR = 3,
} stun_class_t;

/**
 * @brief Methods, 12 bits (section 18.2)
 *
 * Messages can carry methods that aren't listed here, and they're passed on as
 * they are.
 */
enum {
  STUN_METHOD_BINDING = 0x001,
};

/**
 * @brief Attribute types (section 18.3)
 *
 * Messages can carry types that aren't listed here, and they're passed on as
 * they are.
 */
enum {
  STUN_ATTRIBUTE_ERROR_CODE = 0x0009,
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS = 0x0020,
};

/**
 * @brief A parsed message, pointing into the buffer it was parsed from
 */
typedef struct stun_message {
  stun_class_t message_class;
  uint16_t method;
  stun_transaction_id_t transaction_id;
  /// Read them with stun_message_attributes
  const_view_t attributes;
} stun_message_t;

typedef struct stun_optional_message {
  bool has_value;
  stun_message_t value;
} stun_optional_message_t;

/**
 * @brief Parse a datagram as a STUN message
 *
 * Checks what every message has to get right: the zero bits, the magic cookie,
 * and lengths that add up to exactly `src`, attributes included.
 *
 * @returns The message, or nothing if `src` isn't one
 */
stun_optional_message_t stun_message_parse(const_view_t src);

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
                          uint16_t method,
                          stun_transaction_id_t const *transaction_id);

typedef struct stun_attribute {
  uint16_t type;
  /// Without the padding
  const_view_t value;
} stun_attribute_t;

typedef struct stun_attribute_iterator {
  const_view_t rest;
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

/**
 * @brief Whether a receiver that doesn't know `type` has to reject the
 *        message (section 14)
 */
bool stun_attribute_is_comprehension_required(uint16_t type);

typedef struct stun_optional_socket_address {
  bool has_value;
  stun_socket_address_t value;
} stun_optional_socket_address_t;

/**
 * @brief Read an XOR-MAPPED-ADDRESS (section 14.2)
 *
 * @param[in] attribute      Of type STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS
 * @param[in] transaction_id The transaction ID of the message it came in,
 *                           part of the key for IPv6 addresses
 *
 * @returns The address, un-XORed, or nothing if the value isn't valid
 */
stun_optional_socket_address_t stun_attribute_read_xor_mapped_address(
    stun_attribute_t const *attribute,
    stun_transaction_id_t const *transaction_id);

typedef struct stun_optional_error_code {
  bool has_value;
  /// 300 to 699
  uint16_t value;
} stun_optional_error_code_t;

/**
 * @brief Read an ERROR-CODE, leaving out the reason phrase
 *
 * @param[in] attribute Of type STUN_ATTRIBUTE_ERROR_CODE
 *
 * @returns The error code, or nothing if the value isn't valid
 */
stun_optional_error_code_t
stun_attribute_read_error_code(stun_attribute_t const *attribute);
