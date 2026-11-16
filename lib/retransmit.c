#include "retransmit.h"

#include <assert.h>

// RTO, the first wait, doubling after every transmission
static constexpr stun_time_ms_t STUN_RETRANSMIT_FIRST_WAIT = 500;

// Rc
static constexpr uint32_t STUN_RETRANSMIT_ATTEMPTS = 7;

// Rm, the wait after the last transmission in RTOs
static constexpr stun_time_ms_t STUN_RETRANSMIT_LAST_WAIT = 16;

stun_retransmit_status_t
stun_retransmit_poll(stun_retransmit_t const *retransmit, stun_time_ms_t now) {
  assert(retransmit);

  if (now < retransmit->next) {
    return STUN_RETRANSMIT_WAIT;
  }
  return retransmit->count < STUN_RETRANSMIT_ATTEMPTS ? STUN_RETRANSMIT_DUE
                                                      : STUN_RETRANSMIT_GAVE_UP;
}

void stun_retransmit_advance(stun_retransmit_t *retransmit,
                             stun_time_ms_t now) {
  assert(retransmit);
  assert(retransmit->count < STUN_RETRANSMIT_ATTEMPTS);

  retransmit->count += 1;
  retransmit->next =
      now + (retransmit->count < STUN_RETRANSMIT_ATTEMPTS
                 ? STUN_RETRANSMIT_FIRST_WAIT << (retransmit->count - 1)
                 : STUN_RETRANSMIT_FIRST_WAIT * STUN_RETRANSMIT_LAST_WAIT);
}
