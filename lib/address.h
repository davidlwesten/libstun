#pragma once

#include <stdint.h>

typedef struct stun_ip_address {
  /// IPv4 addresses are IPv4-mapped, ::ffff:a.b.c.d
  uint8_t addr[16];
} stun_ip_address_t;

typedef struct stun_socket_address {
  stun_ip_address_t ip;
  uint16_t port;
} stun_socket_address_t;
