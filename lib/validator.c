#include "validator.h"

#include <assert.h>

enum {
  STUN_SEEN_ERROR_CODE = 1u << 0,
  STUN_SEEN_XOR_MAPPED_ADDRESS = 1u << 1,
};

static uint32_t stun_validator_bit(stun_attribute_type_t type) {
  switch (type) {
  case STUN_ATTRIBUTE_ERROR_CODE:
    return STUN_SEEN_ERROR_CODE;
  case STUN_ATTRIBUTE_XOR_MAPPED_ADDRESS:
    return STUN_SEEN_XOR_MAPPED_ADDRESS;
  }
  return 0;
}

// what a message of its class and method has to carry
static uint32_t stun_validator_required(stun_header_t const *header) {
  switch (header->message_class) {
  case STUN_CLASS_ERROR:
    return STUN_SEEN_ERROR_CODE;
  case STUN_CLASS_SUCCESS:
    return header->method == STUN_METHOD_BINDING ? STUN_SEEN_XOR_MAPPED_ADDRESS
                                                 : 0;
  case STUN_CLASS_REQUEST:
  case STUN_CLASS_INDICATION:
    return 0;
  }
  return 0;
}

static bool stun_attribute_is_comprehension_required(uint16_t type) {
  return type < 0x8000;
}

stun_validator_t stun_validator_begin(stun_header_t const *header) {
  assert(header);
  return (stun_validator_t){.header = *header};
}

bool stun_validator_add(stun_validator_t *validator,
                        stun_attribute_t const *attribute,
                        bool known) {
  assert(validator);
  assert(attribute);

  if (!known) {
    return !stun_attribute_is_comprehension_required(attribute->type);
  }
  validator->seen |= stun_validator_bit(attribute->type);
  return true;
}

bool stun_validator_end(stun_validator_t const *validator) {
  assert(validator);

  auto const required = stun_validator_required(&validator->header);
  return (validator->seen & required) == required;
}
