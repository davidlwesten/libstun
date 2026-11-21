#include "retransmit.h"

#include <assert.h>

// RTO, the first wait, doubling after every transmission
static constexpr stun_time_ms_t FIRST_WAIT = 500;

// Rc
static constexpr uint32_t ATTEMPTS = 7;

// Rm, the wait after the last transmission in RTOs
static constexpr stun_time_ms_t LAST_WAIT = 16;

stun_retransmit_status_t
stun_retransmit_poll(stun_retransmit_t const *retransmit, stun_time_ms_t now) {
  assert(retransmit);

  if (now < retransmit->next) {
    return STUN_RETRANSMIT_WAIT;
  }
  return retransmit->count < ATTEMPTS ? STUN_RETRANSMIT_DUE
                                      : STUN_RETRANSMIT_GAVE_UP;
}

void stun_retransmit_advance(stun_retransmit_t *retransmit,
                             stun_time_ms_t now) {
  assert(retransmit);
  assert(retransmit->count < ATTEMPTS);

  retransmit->count += 1;
  retransmit->next = now + (retransmit->count < ATTEMPTS
                                ? FIRST_WAIT << (retransmit->count - 1)
                                : FIRST_WAIT * LAST_WAIT);
}
