#pragma once

#include "attribute.h"

typedef struct stun_wire_attribute stun_wire_attribute_t;

// The attributes we know, one file each. Their parsers fill in the rows of
// the table in attribute.c, and get the reader still at their attribute.

// what reading an attribute gives when the message breaks a rule
static constexpr stun_attribute_read_result_t STUN_INVALID_READ_RESULT = {
    .status = STUN_ATTRIBUTE_READ_INVALID,
};

/**
 * @brief Parse an ERROR-CODE
 */
stun_attribute_read_result_t
stun_attribute_parse_error_code(stun_wire_attribute_t const *attribute,
                                stun_attribute_reader_t const *reader);

/**
 * @brief Parse an XOR-MAPPED-ADDRESS, which the transaction ID in the
 *        header partly hides
 */
stun_attribute_read_result_t
stun_attribute_parse_xor_mapped_address(stun_wire_attribute_t const *attribute,
                                        stun_attribute_reader_t const *reader);

/**
 * @brief Parse a FINGERPRINT, which has to match the message up to it
 *
 * @returns STUN_ATTRIBUTE_READ_NOT_STUN if it doesn't
 */
stun_attribute_read_result_t
stun_attribute_parse_fingerprint(stun_wire_attribute_t const *attribute,
                                 stun_attribute_reader_t const *reader);
