#include "attributes.h"

#include "stun_wire_gen.h"

// error codes are class * 100 + number
static constexpr uint8_t CLASS_MIN = 3;
static constexpr uint8_t CLASS_MAX = 6;
static constexpr uint8_t NUMBERS_PER_CLASS = 100;

stun_attribute_read_result_t
stun_attribute_parse_error_code(stun_wire_attribute_t const *attribute,
                                stun_attribute_reader_t const *) {
  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, attribute->value.ptr,
                                  attribute->value.len) != STUN_WIRE_OK) {
    return STUN_INVALID_READ_RESULT;
  }

  if (error.class < CLASS_MIN || error.class > CLASS_MAX ||
      error.number >= NUMBERS_PER_CLASS) {
    return STUN_INVALID_READ_RESULT;
  }

  return (stun_attribute_read_result_t){
      .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .attribute =
          {
              .type = STUN_ATTRIBUTE_ERROR_CODE,
              .error_code =
                  (uint16_t)(error.class * NUMBERS_PER_CLASS + error.number),
          },
  };
}
