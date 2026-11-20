#pragma once

#include <stddef.h>
#include <stdint.h>

#include "attribute.h"
#include "header.h"
#include "view.h"
#include <byo/stun/stun.h>

// STUN messages (RFC 8489) and their attributes, without any state: parsing
// and checking what's received, and writing what's sent

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

typedef enum stun_message_parse_status {
  /// Not a STUN message, e.g. another protocol on the same socket
  STUN_MESSAGE_PARSE_NOT_STUN = 0,
  /// A STUN message we can't accept, e.g. with a comprehension-required
  /// attribute we don't know, a known one that doesn't parse, or without
  /// one its class and method call for
  STUN_MESSAGE_PARSE_INVALID,
  STUN_MESSAGE_PARSE_VALID,
} stun_message_parse_status_t;

typedef struct stun_message_parse_result {
  stun_message_parse_status_t status;
  /// Unless it's STUN_MESSAGE_PARSE_NOT_STUN, e.g. to tell which transaction
  /// it belongs to
  stun_header_t header;
  /// For STUN_MESSAGE_PARSE_VALID
  stun_message_t message;
} stun_message_parse_result_t;

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
stun_message_parse_result_t stun_message_parse(const_view_t datagram);

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

typedef struct stun_attribute_iterator {
  /// The message's, which parsing its attributes needs
  stun_header_t header;
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

/**
 * @brief Find the first attribute of a type
 *
 * @returns false if the message has none
 */
bool stun_message_find_attribute(stun_message_t const *message,
                                 stun_attribute_type_t type,
                                 stun_attribute_t *attribute);
