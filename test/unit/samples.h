#pragma once

// Attributes and transaction IDs for building test messages

// The transaction ID and addresses of RFC 5769's sample responses
#define TRANSACTION_ID                                                         \
  0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE

// 192.0.2.1:32853
#define XOR_MAPPED_ADDRESS_V4                                                  \
  0x00, 0x20, 0, 8, 0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43

// [2001:db8:1234:5678:11:2233:4455:6677]:32853
#define XOR_MAPPED_ADDRESS_V6                                                  \
  0x00, 0x20, 0, 20, 0x00, 0x02, 0xA1, 0x47, 0x01, 0x13, 0xA9, 0xFA, 0xA5,     \
      0xD3, 0xF1, 0x79, 0xBC, 0x25, 0xF4, 0xB5, 0xBE, 0xD2, 0xB9, 0xD9

// "abc", padded
#define SOFTWARE 0x80, 0x22, 0, 3, 'a', 'b', 'c', 0

#define XOR_MAPPED_ADDRESS_UNKNOWN_FAMILY                                      \
  0x00, 0x20, 0, 8, 0x00, 0x03, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43

// 400 Bad Request, padded
#define ERROR_CODE_400                                                         \
  0x00, 0x09, 0, 15, 0, 0, 4, 0, 'B', 'a', 'd', ' ', 'R', 'e', 'q', 'u', 'e',  \
      's', 't', 0
