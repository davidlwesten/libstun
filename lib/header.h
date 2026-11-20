#pragma once

#include <stddef.h>
#include <stdint.h>

// What every STUN message (RFC 8489) starts with, as plain data

static constexpr size_t STUN_TRANSACTION_ID_SIZE = 12;

typedef struct stun_transaction_id {
  uint8_t bytes[STUN_TRANSACTION_ID_SIZE];
} stun_transaction_id_t;

typedef enum stun_class {
  STUN_CLASS_REQUEST = 0,
  STUN_CLASS_INDICATION = 1,
  STUN_CLASS_SUCCESS = 2,
  STUN_CLASS_ERROR = 3,
} stun_class_t;

/**
 * @brief Methods, 12 bits
 *
 * Messages can carry methods that aren't listed here, and they're passed on as
 * they are.
 */
typedef enum stun_method : uint16_t {
  STUN_METHOD_BINDING = 0x001,
} stun_method_t;

typedef struct stun_header {
  stun_class_t message_class;
  stun_method_t method;
  stun_transaction_id_t transaction_id;
} stun_header_t;
