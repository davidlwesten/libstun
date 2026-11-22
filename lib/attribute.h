#pragma once

#include <stdint.h>

#include "header.h"
#include "view.h"
#include <byo/stun/stun.h>

// Reading a message's attributes (RFC 8489) and giving them their meaning

/**
 * @brief The types of attribute we know
 *
 * These aren't the types on the wire. Attributes of other types come as
 * STUN_ATTRIBUTE_UNKNOWN, with their wire type.
 */
typedef enum stun_attribute_type {
  STUN_ATTRIBUTE_UNKNOWN = 0,
  STUN_ATTRIBUTE_ERROR_CODE,
  STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS,
  /// Carries no value: reading it already checked it
  STUN_ATTRIBUTE_FINGERPRINT,
  /// Not a type, but how many there are
  STUN_ATTRIBUTE_TYPE_COUNT,
} stun_attribute_type_t;

/**
 * @brief An attribute, with its value parsed into the union
 */
typedef struct stun_attribute {
  stun_attribute_type_t type;
  union {
    struct {
      uint16_t wire_type;
    } unknown;
    stun_socket_address_t xor_mapped_address;
    /// 300 to 699, without the reason phrase
    uint16_t error_code;
  };
} stun_attribute_t;

typedef struct stun_optional_attribute {
  bool has_value;
  stun_attribute_t value;
} stun_optional_attribute_t;

/**
 * @brief Reads attributes that haven't been checked yet, in the order they
 *        came in
 *
 * Parses each one, and checks the message against the rules for its
 * attributes as it goes: no attribute may fail to decode or parse, none of the
 * comprehension-required ones may be of a type we don't know, nothing may
 * follow a FINGERPRINT, and the message has to carry what its class and method
 * call for (e.g. an error response an ERROR-CODE, a Binding success response
 * an XOR-MAPPED-ADDRESS).
 *
 * This is how stun_message_parse checks a message. To read the attributes of
 * one it parsed, use stun_message_attributes, which can't fail.
 */
typedef struct stun_attribute_reader {
  /// The message's, which parsing its attributes needs
  stun_header_t header;
  /// All of it, header included
  const_view_t message;
  /// Where the next attribute starts in `message`
  size_t offset;
  /// The known types read so far, one bit each
  uint32_t seen;
} stun_attribute_reader_t;

typedef enum stun_attribute_read_status {
  /// The message breaks one of the rules
  STUN_ATTRIBUTE_READ_INVALID = 0,
  /// It isn't a STUN message after all: its FINGERPRINT doesn't match
  STUN_ATTRIBUTE_READ_NOT_STUN,
  /// The next attribute was read
  STUN_ATTRIBUTE_READ_ATTRIBUTE,
  /// After the last attribute, and the message follows the rules
  STUN_ATTRIBUTE_READ_END,
} stun_attribute_read_status_t;

typedef struct stun_attribute_read_result {
  stun_attribute_read_status_t status;
  /// For STUN_ATTRIBUTE_READ_ATTRIBUTE, with its value in the union if its
  /// type is listed in stun_attribute_type_t
  stun_attribute_t attribute;
} stun_attribute_read_result_t;

/**
 * @brief Start reading a message's attributes
 *
 * @param[in] header  The message's header
 * @param[in] message All of it, header included
 */
stun_attribute_reader_t stun_attribute_reader_init(stun_header_t const *header,
                                                   const_view_t message);

/**
 * @brief Read the next attribute
 *
 * @param[in] reader The reader to advance
 */
stun_attribute_read_result_t
stun_attribute_reader_next(stun_attribute_reader_t *reader);
