#include "attributes.h"

#include "crc32.h"
#include "stun_wire_gen.h"

// what the CRC is XORed with, so that it doesn't match a CRC-32 that another
// protocol's packets carry in the same place
static constexpr uint32_t XOR = 0x5354554E;

stun_attribute_read_result_t
stun_attribute_parse_fingerprint(stun_wire_attribute_t const *attribute,
                                 stun_attribute_reader_t const *reader) {
  struct stun_wire_fingerprint fingerprint;
  if (stun_wire_fingerprint_decode(&fingerprint, attribute->value.ptr,
                                   attribute->value.len) != STUN_WIRE_OK) {
    return STUN_INVALID_READ_RESULT;
  }

  // everything before this attribute, header included
  const_view_t const preceding = {.size = reader->offset,
                                  .data = reader->message.data};
  if ((stun_crc32(preceding) ^ XOR) != fingerprint.crc) {
    return (stun_attribute_read_result_t){
        .status = STUN_ATTRIBUTE_READ_NOT_STUN,
    };
  }

  return (stun_attribute_read_result_t){
      .status = STUN_ATTRIBUTE_READ_ATTRIBUTE,
      .attribute = {.type = STUN_ATTRIBUTE_FINGERPRINT},
  };
}
