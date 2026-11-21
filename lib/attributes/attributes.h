#pragma once

#include "attribute.h"
#include "header.h"
#include "view.h"

// The attributes we know, one file each. Their parsers fill in the rows of
// the table in attribute.c.

// what reading an attribute gives when the message breaks a rule
static constexpr stun_attribute_read_result_t STUN_INVALID_READ_RESULT = {
    .status = STUN_ATTRIBUTE_READ_INVALID,
};

/**
 * @brief Parse an ERROR-CODE value
 */
stun_attribute_read_result_t
stun_attribute_parse_error_code(const_view_t value,
                                stun_header_t const *header);

/**
 * @brief Parse an XOR-MAPPED-ADDRESS value, which the transaction ID in
 *        `header` partly hides
 */
stun_attribute_read_result_t
stun_attribute_parse_xor_mapped_address(const_view_t value,
                                        stun_header_t const *header);
