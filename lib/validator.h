#pragma once

#include "message.h"

/**
 * @brief The rules a message has to follow as a whole, checked attribute by
 *        attribute as stun_message_parse walks it
 */
typedef struct stun_validator {
  stun_header_t header;
  /// The known types seen so far, one bit each
  uint32_t seen;
} stun_validator_t;

stun_validator_t stun_validator_begin(stun_header_t const *header);

/**
 * @brief Check the next attribute, in the order they came in
 *
 * @param[in] validator The validator to update
 * @param[in] attribute An attribute that decoded
 * @param[in] known     Whether its type is listed in stun_attribute_type_t
 *
 * @returns false if the message can't be accepted
 */
bool stun_validator_add(stun_validator_t *validator,
                        stun_attribute_t const *attribute,
                        bool known);

/**
 * @brief Check the rules that need the whole message, after the last attribute
 *
 * @returns false if the message can't be accepted
 */
bool stun_validator_end(stun_validator_t const *validator);
