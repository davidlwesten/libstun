#pragma once

#include <byo/stun/stun.h>

/**
 * @brief When to send a request again (RFC 8489, section 6.2.1)
 *
 * Starts zeroed, with the first transmission due right away. After that the
 * client waits 500 ms, doubling every time, and gives up 8 s after the
 * seventh, 39.5 s after the first.
 */
typedef struct stun_retransmit {
  /// Transmissions so far
  uint32_t count;
  /// The next transmission, or when to give up after the last one
  stun_time_ms_t next;
} stun_retransmit_t;

typedef enum stun_retransmit_status {
  STUN_RETRANSMIT_WAIT,
  STUN_RETRANSMIT_DUE,
  /// No response to the last transmission either
  STUN_RETRANSMIT_GAVE_UP,
} stun_retransmit_status_t;

stun_retransmit_status_t
stun_retransmit_poll(stun_retransmit_t const *retransmit, stun_time_ms_t now);

void stun_retransmit_advance(stun_retransmit_t *retransmit, stun_time_ms_t now);
