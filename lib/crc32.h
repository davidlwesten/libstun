#pragma once

#include <stdint.h>

#include "view.h"

/**
 * @brief The CRC-32 of `data`, as ITU V.42 defines it
 */
uint32_t stun_crc32(const_view_t data);
