#include "attributes.h"

#include "stun_wire_gen.h"

// error codes are class * 100 + number
static constexpr uint8_t STUN_ERROR_CODE_CLASS_MIN = 3;
static constexpr uint8_t STUN_ERROR_CODE_CLASS_MAX = 6;
static constexpr uint8_t STUN_ERROR_CODE_NUMBERS_PER_CLASS = 100;

stun_attribute_read_result_t
stun_attribute_parse_error_code(const_view_t value, stun_header_t const *) {
  struct stun_wire_error_code error;
  if (stun_wire_error_code_decode(&error, value.data, value.size) !=
      STUN_WIRE_OK) {
    return STUN_INVALID_READ_RESULT;
  }

  if (error.class < STUN_ERROR_CODE_CLASS_MIN ||
      error.class > STUN_ERROR_CODE_CLASS_MAX ||
      error.number >= STUN_ERROR_CODE_NUMBERS_PER_CLASS) {
    return STUN_INVALID_READ_RESULT;
  }

  return (stun_attribute_read_result_t){
      .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .attribute =
          {
              .type = STUN_ATTRIBUTE_ERROR_CODE,
              .error_code =
                  (uint16_t)(error.class * STUN_ERROR_CODE_NUMBERS_PER_CLASS +
                             error.number),
          },
  };
}
